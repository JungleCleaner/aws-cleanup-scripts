#!/usr/bin/env python3
"""
delete-waf-classic-acl.py

Safely deletes an orphaned WAF Classic Web ACL and all its associated rules.

WAF Classic requires a strict deletion sequence:
  1. Remove every rule from the ACL  (update_web_acl)
  2. Delete the now-empty ACL        (delete_web_acl)
  3. Remove all predicates from each rule (update_rule)
  4. Delete the now-empty rules      (delete_rule)

Usage:
  python3 delete-waf-classic-acl.py --acl-id <id> [--scope global|regional] [--region <region>] [--dry-run] [--profile <profile>]

Requirements:
  pip install boto3
"""

import argparse
import sys
import boto3
from botocore.exceptions import ClientError


def parse_args():
    parser = argparse.ArgumentParser(
        description="Safely delete a WAF Classic Web ACL and all its associated rules."
    )
    parser.add_argument("--acl-id", required=True, help="WAF Classic WebACL ID (not ARN)")
    parser.add_argument(
        "--scope",
        choices=["global", "regional"],
        default="global",
        help="'global' (CloudFront, us-east-1) or 'regional' (default: global)",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (required for regional scope, default: us-east-1)",
    )
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would happen without making any changes",
    )
    return parser.parse_args()


def get_client(scope, region, profile):
    session = boto3.Session(profile_name=profile)
    if scope == "global":
        return session.client("waf", region_name="us-east-1")
    else:
        return session.client("waf-regional", region_name=region)


def get_change_token(client, dry_run):
    if dry_run:
        return "DRY-RUN-TOKEN"
    return client.get_change_token()["ChangeToken"]


def step(msg, dry_run=False):
    prefix = "[dry-run] " if dry_run else ""
    print(f"{prefix}{msg}")


def main():
    args = parse_args()
    region = "us-east-1" if args.scope == "global" else args.region

    print(f"Fetching ACL {args.acl_id} ({args.scope}, {region})...")

    try:
        client = get_client(args.scope, region, args.profile)
        acl = client.get_web_acl(WebACLId=args.acl_id)["WebACL"]
    except ClientError as e:
        print(f"Error: could not fetch ACL {args.acl_id}: {e}", file=sys.stderr)
        sys.exit(1)

    acl_name = acl["Name"]
    default_action = acl["DefaultAction"]["Type"]
    rules = acl.get("Rules", [])

    print(f"  Name          : {acl_name}")
    print(f"  Default action: {default_action}")
    print(f"  Rules         : {len(rules)}")
    print()

    if args.dry_run:
        print("[dry-run mode — no changes will be made]\n")

    # ── Step 1: Detach all rules from the ACL ────────────────────────────────

    if rules:
        print(f"Step 1: Removing {len(rules)} rule(s) from ACL...")
        updates = [{"Action": "DELETE", "ActivatedRule": r} for r in rules]
        if not args.dry_run:
            client.update_web_acl(
                WebACLId=args.acl_id,
                ChangeToken=get_change_token(client, args.dry_run),
                Updates=updates,
                DefaultAction={"Type": default_action},
            )
        else:
            print(f"  would call update_web_acl with {len(updates)} DELETE update(s)")
        print("  ✓ Rules detached.")
    else:
        print("Step 1: No rules attached — skipping.")

    print()

    # ── Step 2: Delete the now-empty ACL ─────────────────────────────────────

    print(f"Step 2: Deleting ACL '{acl_name}' ({args.acl_id})...")
    if not args.dry_run:
        client.delete_web_acl(
            WebACLId=args.acl_id,
            ChangeToken=get_change_token(client, args.dry_run),
        )
    else:
        print("  would call delete_web_acl")
    print("  ✓ ACL deleted.")
    print()

    # ── Steps 3 & 4: Clear each rule's predicates then delete it ─────────────

    for activated_rule in rules:
        rule_id = activated_rule["RuleId"]
        print(f"Processing rule {rule_id}...")

        try:
            rule = client.get_rule(RuleId=rule_id)["Rule"]
        except ClientError as e:
            print(f"  ⚠  Could not fetch rule {rule_id} — may already be deleted: {e}")
            continue

        rule_name = rule["Name"]
        predicates = rule.get("Predicates", [])

        print(f"  Name       : {rule_name}")
        print(f"  Predicates : {len(predicates)}")

        if predicates:
            print(f"  Step 3: Removing {len(predicates)} predicate(s)...")
            pred_updates = [{"Action": "DELETE", "Predicate": p} for p in predicates]
            if not args.dry_run:
                client.update_rule(
                    RuleId=rule_id,
                    ChangeToken=get_change_token(client, args.dry_run),
                    Updates=pred_updates,
                )
            else:
                print(f"  would call update_rule with {len(pred_updates)} DELETE update(s)")
            print("  ✓ Predicates removed.")

        print(f"  Step 4: Deleting rule '{rule_name}' ({rule_id})...")
        if not args.dry_run:
            client.delete_rule(
                RuleId=rule_id,
                ChangeToken=get_change_token(client, args.dry_run),
            )
        else:
            print("  would call delete_rule")
        print("  ✓ Rule deleted.")
        print()

    print(f"Done. ACL '{acl_name}' and all its rules have been deleted.")


if __name__ == "__main__":
    main()
