#!/usr/bin/env python3
"""
delete-route53-hosted-zone.py

Safely deletes a Route53 hosted zone and all its non-default records.

Route53 requires a strict deletion sequence:
  1. Delete all non-default records (everything except the root NS and SOA)
  2. Delete the now-empty hosted zone

Usage:
  python3 delete-route53-hosted-zone.py --zone-id <id> [--dry-run] [--profile <profile>]
  python3 delete-route53-hosted-zone.py --domain <example.com> [--dry-run] [--profile <profile>]

Requirements:
  pip install boto3
"""

import argparse
import sys
import boto3
from botocore.exceptions import ClientError


def parse_args():
    parser = argparse.ArgumentParser(
        description="Safely delete a Route53 hosted zone and all its records."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--zone-id", help="Hosted zone ID (e.g. Z1234567890ABC)")
    group.add_argument("--domain", help="Domain name (e.g. example.com)")
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would happen without making any changes",
    )
    return parser.parse_args()


def get_zone_id_for_domain(client, domain):
    """Look up the hosted zone ID for a given domain name."""
    dns_name = domain if domain.endswith(".") else domain + "."
    resp = client.list_hosted_zones_by_name(DNSName=dns_name, MaxItems="1")
    zones = resp.get("HostedZones", [])
    if not zones:
        return None
    zone = zones[0]
    # Exact match only — list_hosted_zones_by_name returns alphabetically >= dns_name
    if zone["Name"] != dns_name:
        return None
    return zone["Id"].split("/")[-1]


def main():
    args = parse_args()
    session = boto3.Session(profile_name=args.profile)
    client = session.client("route53")

    # Resolve zone ID
    if args.zone_id:
        zone_id = args.zone_id.split("/")[-1]  # strip /hostedzone/ prefix if present
    else:
        print(f"Looking up zone for {args.domain}...")
        zone_id = get_zone_id_for_domain(client, args.domain)
        if not zone_id:
            print(f"Error: no hosted zone found for {args.domain}", file=sys.stderr)
            sys.exit(1)

    # Fetch zone details
    try:
        zone = client.get_hosted_zone(Id=zone_id)["HostedZone"]
    except ClientError as e:
        print(f"Error: could not fetch zone {zone_id}: {e}", file=sys.stderr)
        sys.exit(1)

    zone_name = zone["Name"]
    record_count = zone["ResourceRecordSetCount"]

    print(f"Hosted zone: {zone_name} ({zone_id})")
    print(f"  Record count: {record_count}")
    print()

    if args.dry_run:
        print("[dry-run mode — no changes will be made]\n")

    # ── Step 1: Collect and delete non-default records ────────────────────────

    all_records = []
    paginator = client.get_paginator("list_resource_record_sets")
    for page in paginator.paginate(HostedZoneId=zone_id):
        all_records.extend(page["ResourceRecordSets"])

    # NS and SOA at the zone apex are required and must stay until the zone is deleted
    to_delete = [
        r for r in all_records
        if not (r["Type"] in ("NS", "SOA") and r["Name"] == zone_name)
    ]

    if to_delete:
        print(f"Step 1: Deleting {len(to_delete)} non-default record(s)...")
        for r in to_delete:
            alias = " (alias)" if "AliasTarget" in r else ""
            print(f"  - {r['Name']} ({r['Type']}){alias}")

        if not args.dry_run:
            changes = [{"Action": "DELETE", "ResourceRecordSet": r} for r in to_delete]
            # Route53 allows up to 1000 changes per batch
            for i in range(0, len(changes), 1000):
                batch = changes[i:i + 1000]
                client.change_resource_record_sets(
                    HostedZoneId=zone_id,
                    ChangeBatch={"Changes": batch},
                )
        print("  ✓ Records deleted.")
    else:
        print("Step 1: No non-default records — skipping.")

    print()

    # ── Step 2: Delete the now-empty hosted zone ──────────────────────────────

    print(f"Step 2: Deleting hosted zone '{zone_name}' ({zone_id})...")
    if not args.dry_run:
        client.delete_hosted_zone(Id=zone_id)
    else:
        print("  would call delete_hosted_zone")
    print("  ✓ Hosted zone deleted.")
    print()

    print(f"Done. Hosted zone '{zone_name}' has been deleted.")


if __name__ == "__main__":
    main()
