#!/usr/bin/env python3
# export AWS_PROFILE=iam_test
"""
IAM Policy Sprawl Scanner - MVP prototype

Usage:
    python iam_sprawl_scanner.py --days 90 --include-aws-managed --target users

Notes:
- CloudTrail LookupEvents is used to infer "observed" actions (max 90 days).
- This is an MVP: it suggests replacements based on observed events; it does NOT
  automatically modify policies. Use suggestions as a starting point for a PR.
"""

import boto3
import json
import argparse
from datetime import datetime, timedelta, UTC
import time

# ---------- Helpers ----------
def normalize_to_list(x):
    if x is None:
        return []
    if isinstance(x, str):
        return [x]
    if isinstance(x, dict):
        return [x]
    return list(x)

def extract_service_from_action(action):
    if action == '*' or action == '*:*':
        return '*'
    if ':' in action:
        return action.split(':', 1)[0].lower()
    return action.lower()

def extract_service_from_eventsource(event_source):
    if not event_source:
        return None
    return event_source.split('.')[0].lower()

# ---------- IAM scanning ----------
def get_all_entities(iam, target="all"):
    """
    Returns a list of dicts: {'type': 'role'|'user'|'group', 'name': name, ...}
    Filter based on --target option.
    """
    entities = []

    if target in ("all", "roles"):
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for r in page.get('Roles', []):
                entities.append({'type': 'role', 'name': r['RoleName']})

    if target in ("all", "users"):
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for u in page.get('Users', []):
                entities.append({'type': 'user', 'name': u['UserName']})

    if target in ("all", "groups"):
        paginator = iam.get_paginator('list_groups')
        for page in paginator.paginate():
            for g in page.get('Groups', []):
                entities.append({'type': 'group', 'name': g['GroupName']})

    return entities

# ---------- IAM policy helpers ----------
def get_attached_managed_policies_for_entity(iam, entity):
    t = entity['type']
    name = entity['name']
    attached = []
    try:
        if t == 'role':
            paginator = iam.get_paginator('list_attached_role_policies')
            for p in paginator.paginate(RoleName=name):
                attached.extend(p.get('AttachedPolicies', []))
        elif t == 'user':
            paginator = iam.get_paginator('list_attached_user_policies')
            for p in paginator.paginate(UserName=name):
                attached.extend(p.get('AttachedPolicies', []))
        elif t == 'group':
            paginator = iam.get_paginator('list_attached_group_policies')
            for p in paginator.paginate(GroupName=name):
                attached.extend(p.get('AttachedPolicies', []))
    except Exception as e:
        print(f"Warning: failed to list attached managed policies for {t}/{name}: {e}")
    return attached

def get_inline_policies_for_entity(iam, entity):
    t = entity['type']
    name = entity['name']
    inline_names = []
    try:
        if t == 'role':
            paginator = iam.get_paginator('list_role_policies')
            for p in paginator.paginate(RoleName=name):
                inline_names.extend(p.get('PolicyNames', []))
        elif t == 'user':
            paginator = iam.get_paginator('list_user_policies')
            for p in paginator.paginate(UserName=name):
                inline_names.extend(p.get('PolicyNames', []))
        elif t == 'group':
            paginator = iam.get_paginator('list_group_policies')
            for p in paginator.paginate(GroupName=name):
                inline_names.extend(p.get('PolicyNames', []))
    except Exception as e:
        print(f"Warning: failed to list inline policies for {t}/{name}: {e}")
    return inline_names

def get_inline_policy_document(iam, entity, policy_name):
    t = entity['type']
    name = entity['name']
    try:
        if t == 'role':
            resp = iam.get_role_policy(RoleName=name, PolicyName=policy_name)
            return resp.get('PolicyDocument')
        if t == 'user':
            resp = iam.get_user_policy(UserName=name, PolicyName=policy_name)
            return resp.get('PolicyDocument')
        if t == 'group':
            resp = iam.get_group_policy(GroupName=name, PolicyName=policy_name)
            return resp.get('PolicyDocument')
    except Exception as e:
        print(f"Warning: failed to get inline policy {policy_name} for {t}/{name}: {e}")
    return None

def get_managed_policy_document(iam, policy_arn):
    try:
        p = iam.get_policy(PolicyArn=policy_arn)['Policy']
        ver = p.get('DefaultVersionId')
        pv = iam.get_policy_version(PolicyArn=policy_arn, VersionId=ver)
        return pv.get('PolicyVersion', {}).get('Document')
    except Exception as e:
        print(f"Warning: failed to read managed policy {policy_arn}: {e}")
    return None

# ---------- Policy analysis ----------
def analyze_policy_document(policy_doc):
    issues = []
    if not policy_doc:
        return issues
    stmts = policy_doc.get('Statement', [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for stmt in stmts:
        acts = normalize_to_list(stmt.get('Action'))
        res = normalize_to_list(stmt.get('Resource'))
        princ = stmt.get('Principal')
        for a in acts:
            if a == '*' or '*' in str(a):
                issues.append({'issue_type': 'wildcard_action', 'action': a, 'statement': stmt})
        for r in res:
            if r == '*' or (isinstance(r, str) and '*' in r):
                issues.append({'issue_type': 'wildcard_resource', 'resource': r, 'statement': stmt})
        if princ == '*' or princ == {"AWS": "*"} or (isinstance(princ, dict) and any('*' in normalize_to_list(v) for v in princ.values())):
            issues.append({'issue_type': 'wildcard_principal', 'principal': princ, 'statement': stmt})
    return issues

# ---------- CloudTrail ----------
def collect_cloudtrail_actions(cloudtrail, days=90, max_events=5000):
    observed = set()
    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(days=days)
    next_token = None
    fetched = 0
    while True:
        try:
            if next_token:
                resp = cloudtrail.lookup_events(NextToken=next_token, StartTime=start_time, EndTime=end_time, MaxResults=50)
            else:
                resp = cloudtrail.lookup_events(StartTime=start_time, EndTime=end_time, MaxResults=50)
        except Exception as e:
            print(f"Warning: CloudTrail lookup failed: {e}")
            break
        events = resp.get('Events', [])
        for ev in events:
            fetched += 1
            try:
                ev_detail = json.loads(ev.get('CloudTrailEvent', '{}'))
                event_source = ev_detail.get('eventSource') or ev.get('EventSource')
                event_name = ev_detail.get('eventName') or ev.get('EventName')
            except Exception:
                event_source = ev.get('EventSource')
                event_name = ev.get('EventName')
            svc = extract_service_from_eventsource(event_source) or extract_service_from_action(event_name)
            if svc and event_name:
                observed.add(f"{svc}:{event_name}")
            if fetched >= max_events:
                break
        next_token = resp.get('NextToken')
        if not next_token or fetched >= max_events:
            break
        time.sleep(0.1)
    return observed

# ---------- Suggestions ----------
COMMON_FALLBACKS = {
    's3': ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
    'ec2': ['ec2:DescribeInstances', 'ec2:StartInstances', 'ec2:StopInstances'],
    'lambda': ['lambda:InvokeFunction', 'lambda:GetFunction'],
    'dynamodb': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query'],
    'sts': ['sts:AssumeRole'],
}

def suggest_actions_for_wildcard(action_pattern, observed_actions):
    svc = extract_service_from_action(action_pattern)
    if svc == '*' or svc == '':
        return []
    matches = sorted([a for a in observed_actions if a.split(':',1)[0].lower() == svc])
    if matches:
        return matches
    return COMMON_FALLBACKS.get(svc, [])

# ---------- Main ----------
def scan_account(include_aws_managed=False, days=90, target="all"):
    iam = boto3.client('iam')
    cloudtrail = boto3.client('cloudtrail')
    entities = get_all_entities(iam, target)
    print(f"Found {len(entities)} {target} entities. Scanning policies...")
    findings = []
    for e in entities:
        attached = get_attached_managed_policies_for_entity(iam, e)
        inline_names = get_inline_policies_for_entity(iam, e)
        for pol_name in inline_names:
            doc = get_inline_policy_document(iam, e, pol_name)
            issues = analyze_policy_document(doc)
            if issues:
                findings.append({
                    'entity': e,
                    'policy_type': 'inline',
                    'policy_name': pol_name,
                    'policy_document': doc,
                    'issues': issues
                })
        for pol in attached:
            arn = pol.get('PolicyArn')
            if (not include_aws_managed) and arn and ':aws:policy/' in arn:
                continue
            doc = get_managed_policy_document(iam, arn)
            issues = analyze_policy_document(doc)
            if issues:
                findings.append({
                    'entity': e,
                    'policy_type': 'managed',
                    'policy_name': pol.get('PolicyName'),
                    'policy_arn': arn,
                    'policy_document': doc,
                    'issues': issues
                })
    print(f"Policy analysis complete. {len(findings)} policies with issues found.")

    observed = set()
    if days and days > 0:
        print(f"Collecting CloudTrail events for the last {days} days (best-effort)...")
        observed = collect_cloudtrail_actions(cloudtrail, days=days)
        print(f"Observed {len(observed)} distinct service:event actions from CloudTrail.")

    suggestions = []
    for f in findings:
        for iss in f['issues']:
            if iss['issue_type'] == 'wildcard_action':
                pattern = iss['action']
                suggested = suggest_actions_for_wildcard(pattern, observed)
                suggestions.append({
                    'entity': f['entity'],
                    'policy_type': f['policy_type'],
                    'policy_name': f.get('policy_name'),
                    'policy_arn': f.get('policy_arn'),
                    'issue': iss,
                    'suggested_actions': suggested
                })
            else:
                suggestions.append({
                    'entity': f['entity'],
                    'policy_type': f['policy_type'],
                    'policy_name': f.get('policy_name'),
                    'policy_arn': f.get('policy_arn'),
                    'issue': iss,
                    'suggested_actions': []
                })
    return {'findings': findings, 'suggestions': suggestions, 'observed_actions_sample': sorted(list(observed))[:200]}

# ---------- CLI ----------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IAM Policy Sprawl Scanner (MVP)')
    parser.add_argument('--days', type=int, default=90, help='Days back to query CloudTrail (0 to skip)')
    parser.add_argument('--include-aws-managed', action='store_true', default=False, help='Include AWS-managed policies in scan')
    parser.add_argument('--target', choices=['all', 'users', 'roles', 'groups'], default='all', help='Limit scan to certain IAM entities')
    parser.add_argument('--out', default='report.json', help='Write JSON report')
    args = parser.parse_args()

    report = scan_account(include_aws_managed=args.include_aws_managed, days=args.days, target=args.target)

    with open(args.out, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Report written to {args.out}. Summary:")
    for s in report['suggestions'][:20]:
        ent = s['entity']
        print(f"- {ent['type']}/{ent['name']} | {s['policy_type']} {s.get('policy_name') or s.get('policy_arn')} -> issue {s['issue']['issue_type']}")
        if s['suggested_actions']:
            print(f"  Suggested actions (sample): {s['suggested_actions'][:10]}")
    print("Done.")
