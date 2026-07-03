#!/usr/bin/env python3
"""
migrate-opensearch-classic-to-nextgen.py

Migrates data from an Amazon OpenSearch Serverless Classic collection to an
already-existing NextGen collection. NextGen scales to zero OCUs when idle,
eliminating the Classic minimum floor charge (~$700/month for a VPC
collection).

IMPORTANT — why this doesn't use the `_reindex` API:
  OpenSearch/Elasticsearch Serverless does not support `_reindex` with a
  `remote` source ("reindex.remote is not supported in serverless mode").
  AWS's own recommendation for cross-collection copies is an OpenSearch
  Ingestion pipeline, which is a lot of setup (IAM role, data access policy,
  pipeline YAML, OCU capacity) for a one-off migration. Instead, this script
  copies documents directly: it opens a Point-in-Time on the source index,
  paginates through every document with `search_after` (the modern,
  supported replacement for the deprecated `_scroll` API), and writes each
  batch to the target with `_bulk`. This is the same fundamental approach
  OSI itself uses under the hood.

Collection generation is immutable in OpenSearch Serverless, so this script
does NOT create or delete any collections. The full migration is:

  1. Create the new NextGen collection ahead of time (and its
     access/network/encryption policies), however you normally provision
     resources.
  2. Run this script to copy all data from the classic collection to it.
  3. Update your application configuration (env vars, secrets, etc.) to
     point at the new collection's endpoint.
  4. Once you've confirmed traffic is flowing to the new collection, delete
     the classic one when you no longer need it:
       aws opensearchserverless delete-collection --id <classic-collection-id>

RELIABILITY NOTES (please read before running against a large index):
  - Every HTTP call (search, bulk write, PIT open/close) retries with
    exponential backoff on throttling (429) and transient 5xx/network
    errors — expected at scale under sustained load.
  - Documents are written to the target with their original `_id`, so
    writes are idempotent: re-running this script (or retrying a failed
    batch) never creates duplicates, it just overwrites with the same
    content.
  - Progress is checkpointed to a local JSON file at INDEX granularity
    (which indices are fully done), not at the individual-document level.
    This is a deliberate trade-off: search_after cursors are only valid
    within the Point-in-Time they were issued against, and a PIT cannot
    be safely resumed after the process restarts (it may have expired, or
    a fresh one may enumerate shards differently). Because writes are
    idempotent, restarting an in-progress index from scratch after a crash
    is always *correct* — just slower — which is a better trade-off than a
    resume mechanism that could silently skip documents. Fully-completed
    indices are always skipped on a re-run.
  - Any document that still fails after a retry is written to a
    `--failed-docs-file` (JSON Lines) instead of aborting the whole run, so
    one bad document can't block migrating the other 4,999,999.
  - Index mappings (field types) and custom analyzers are copied from
    source to target before data is copied, so the target doesn't rely on
    dynamic mapping guessing field types differently than the source.

Usage:
  python3 migrate-opensearch-classic-to-nextgen.py \\
    --source-collection-id <classic-collection-id> \\
    --target-collection-id <existing-nextgen-collection-id> \\
    [--region <region>] [--profile <profile>] \\
    [--batch-size 1000] [--dry-run] [--fresh]

Requirements:
  pip install boto3
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

# OpenSearch Serverless's data-plane gateway requires this header on every
# request that has a body — botocore's SigV4Auth factors the payload hash
# into the signature but never actually sets this header on the outgoing
# request, so without this AOSS rejects otherwise-correctly-signed requests
# with a 403 and `x-aoss-response-hint: X01:gw-helper-deny`.
def _content_sha256(data):
    return hashlib.sha256(data).hexdigest() if data else hashlib.sha256(b"").hexdigest()

DEFAULT_BATCH_SIZE = 1000
PIT_KEEP_ALIVE = "10m"
MAX_RETRIES = 6
INITIAL_BACKOFF_SECONDS = 1
RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Migrate data from an OpenSearch Serverless Classic collection to an existing NextGen collection."
    )
    parser.add_argument("--source-collection-id", required=True, help="Classic collection ID to migrate from")
    parser.add_argument("--target-collection-id", required=True, help="Existing NextGen collection ID to migrate to")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Documents per search/bulk batch (default: {DEFAULT_BATCH_SIZE}). "
        "Lower this if your documents are large — keep bulk payloads under ~5MB.",
    )
    parser.add_argument(
        "--checkpoint-file",
        default=None,
        help="Where to track fully-migrated indices (default: .opensearch-migration-<source>-<target>.json)",
    )
    parser.add_argument(
        "--failed-docs-file",
        default=None,
        help="Where to record documents that failed to migrate after retries (default: "
        "opensearch-migration-failures-<source>-<target>.jsonl)",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Ignore any existing checkpoint and re-migrate every index from scratch",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List indices and document counts without copying any data",
    )
    return parser.parse_args()


# ── AWS control-plane helpers ─────────────────────────────────────────────────


def get_collection(client, collection_id):
    try:
        res = client.batch_get_collection(ids=[collection_id])
    except ClientError as e:
        sys.exit(f"Error: could not fetch collection {collection_id}: {e}")
    for err in res.get("collectionErrorDetails", []):
        sys.exit(f"Error: could not fetch collection {collection_id}: {err.get('errorMessage', err)}")
    details = res.get("collectionDetails", [])
    if not details:
        sys.exit(f"Error: collection {collection_id} not found.")
    return details[0]


# ── Signed data-plane HTTP with retries ───────────────────────────────────────


def signed_request(session, region, method, url, body=None):
    """Signs and sends a request to a collection's OpenSearch data-plane endpoint,
    retrying with exponential backoff on throttling/transient errors. Uses
    botocore's SigV4 signer directly (rather than requests-aws4auth) so the only
    dependency this script needs is boto3."""
    creds = session.get_credentials()
    if creds is None:
        sys.exit("Error: no AWS credentials found.")

    data = json.dumps(body).encode() if body is not None else None
    last_error = None

    for attempt in range(MAX_RETRIES):
        frozen = creds.get_frozen_credentials()
        headers = {"X-Amz-Content-SHA256": _content_sha256(data)}
        if data:
            headers["Content-Type"] = "application/json"
        aws_request = AWSRequest(method=method, url=url, data=data, headers=headers)
        SigV4Auth(frozen, "aoss", region).add_auth(aws_request)
        req = urllib.request.Request(url, data=data, headers=dict(aws_request.headers), method=method)

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body_text = e.read().decode(errors="replace")
            if e.code in RETRYABLE_HTTP_CODES and attempt < MAX_RETRIES - 1:
                last_error = f"{e.code} {body_text}"
            else:
                sys.exit(f"Error calling {method} {url}: {e.code} {body_text}")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt < MAX_RETRIES - 1:
                last_error = str(e)
            else:
                sys.exit(f"Error calling {method} {url} after {MAX_RETRIES} attempts: {e}")

        backoff = INITIAL_BACKOFF_SECONDS * (2**attempt)
        print(f"  ⚠ {method} {url} failed ({last_error}) — retrying in {backoff}s (attempt {attempt + 2}/{MAX_RETRIES})...")
        time.sleep(backoff)


def step(msg):
    print(f"▶ {msg}")


def ok(msg):
    print(f"✓ {msg}")


def warn(msg):
    print(f"⚠ {msg}")


# ── Checkpointing (index-level only — see docstring for why) ─────────────────


def load_checkpoint(path):
    if not os.path.exists(path):
        return {"completed_indices": []}
    with open(path) as f:
        return json.load(f)


def save_checkpoint(path, checkpoint):
    with open(path, "w") as f:
        json.dump(checkpoint, f, indent=2)


# ── Index mapping/settings copy ───────────────────────────────────────────────


def copy_index_mapping(session, region, source_endpoint, target_endpoint, index):
    source_def = signed_request(session, region, "GET", f"{source_endpoint}/{index}")
    idx = source_def.get(index, {})
    mappings = idx.get("mappings", {})
    analysis = idx.get("settings", {}).get("index", {}).get("analysis")

    create_body = {"mappings": mappings}
    if analysis:
        # Custom analyzers/tokenizers/filters matter for search behavior and can't
        # be inferred from dynamic mapping — everything else (shards, replicas,
        # etc.) is managed automatically by Serverless, so we don't copy it.
        create_body["settings"] = {"index": {"analysis": analysis}}

    # PUT is idempotent here: if the index already exists (e.g. a retried run),
    # OpenSearch returns resource_already_exists_exception, which we treat as OK.
    try:
        signed_request(session, region, "PUT", f"{target_endpoint}/{index}", create_body)
    except SystemExit as e:
        if "resource_already_exists_exception" not in str(e):
            raise


# ── Point-in-time helpers ─────────────────────────────────────────────────────


def open_pit(session, region, endpoint, index):
    res = signed_request(session, region, "POST", f"{endpoint}/{index}/_search/point_in_time?keep_alive={PIT_KEEP_ALIVE}")
    return res["pit_id"]


def close_pit(session, region, endpoint, pit_id):
    try:
        signed_request(session, region, "DELETE", f"{endpoint}/_search/point_in_time", {"pit_id": [pit_id]})
    except SystemExit:
        pass  # best-effort cleanup — PIT will simply expire on its own otherwise


def count_at_pit(session, region, endpoint, pit_id):
    body = {"size": 0, "track_total_hits": True, "pit": {"id": pit_id, "keep_alive": PIT_KEEP_ALIVE}}
    res = signed_request(session, region, "POST", f"{endpoint}/_search", body)
    return res["hits"]["total"]["value"]


# ── Bulk write with per-document error handling ───────────────────────────────


def bulk_write(session, region, target_endpoint, index, docs, failed_docs_file):
    """Writes `docs` (list of (doc_id, source) tuples) via _bulk, retrying failed
    items once as a smaller batch before giving up on them individually. Returns
    the number of documents successfully written."""

    def send(batch):
        lines = []
        for doc_id, source in batch:
            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
            lines.append(json.dumps(source))
        body = "\n".join(lines) + "\n"
        return _bulk_raw(session, region, f"{target_endpoint}/_bulk", body)

    result = send(docs)
    items = result.get("items", [])
    failed = [
        docs[i]
        for i, item in enumerate(items)
        if item.get("index", {}).get("error")
    ]

    succeeded = len(docs) - len(failed)

    if failed:
        warn(f"{len(failed)} document(s) failed in this batch — retrying once...")
        retry_result = send(failed)
        retry_items = retry_result.get("items", [])
        still_failed = [
            (failed[i], retry_items[i].get("index", {}).get("error"))
            for i in range(len(failed))
            if retry_items[i].get("index", {}).get("error")
        ]
        succeeded += len(failed) - len(still_failed)
        if still_failed:
            with open(failed_docs_file, "a") as f:
                for (doc_id, _source), error in still_failed:
                    f.write(json.dumps({"index": index, "id": doc_id, "error": error}) + "\n")
            warn(f"{len(still_failed)} document(s) still failing — recorded to {failed_docs_file}")

    return succeeded


def _bulk_raw(session, region, url, ndjson_body):
    """_bulk needs a raw newline-delimited body, not a single JSON object, so it
    bypasses signed_request's json.dumps — everything else (signing, retries) is
    identical."""
    creds = session.get_credentials()
    if creds is None:
        sys.exit("Error: no AWS credentials found.")

    data = ndjson_body.encode()
    last_error = None

    for attempt in range(MAX_RETRIES):
        frozen = creds.get_frozen_credentials()
        headers = {"Content-Type": "application/x-ndjson", "X-Amz-Content-SHA256": _content_sha256(data)}
        aws_request = AWSRequest(method="POST", url=url, data=data, headers=headers)
        SigV4Auth(frozen, "aoss", region).add_auth(aws_request)
        req = urllib.request.Request(url, data=data, headers=dict(aws_request.headers), method="POST")

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body_text = e.read().decode(errors="replace")
            if e.code in RETRYABLE_HTTP_CODES and attempt < MAX_RETRIES - 1:
                last_error = f"{e.code} {body_text}"
            else:
                sys.exit(f"Error calling POST {url}: {e.code} {body_text}")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt < MAX_RETRIES - 1:
                last_error = str(e)
            else:
                sys.exit(f"Error calling POST {url} after {MAX_RETRIES} attempts: {e}")

        backoff = INITIAL_BACKOFF_SECONDS * (2**attempt)
        print(f"  ⚠ bulk write failed ({last_error}) — retrying in {backoff}s (attempt {attempt + 2}/{MAX_RETRIES})...")
        time.sleep(backoff)


# ── Per-index migration ────────────────────────────────────────────────────────


def migrate_index(session, region, source_endpoint, target_endpoint, index, batch_size, failed_docs_file):
    step(f"Migrating index '{index}'...")
    copy_index_mapping(session, region, source_endpoint, target_endpoint, index)

    pit_id = open_pit(session, region, source_endpoint, index)
    try:
        total = count_at_pit(session, region, source_endpoint, pit_id)
        print(f"  {total:,} document(s) to migrate")
        if total == 0:
            return 0, 0

        migrated = 0
        search_after = None
        start_time = time.time()

        while True:
            body = {
                "size": batch_size,
                # _shard_doc is an Elasticsearch-only PIT tiebreaker — OpenSearch
                # doesn't implement it (400 query_shard_exception). OpenSearch's
                # own recommended pattern is _doc (cheap, no fielddata, but can
                # collide across shards) plus _id as a tiebreaker to guarantee
                # search_after never skips or duplicates a document.
                "sort": [{"_doc": "asc"}, {"_id": "asc"}],
                "pit": {"id": pit_id, "keep_alive": PIT_KEEP_ALIVE},
                "track_total_hits": False,
            }
            if search_after is not None:
                body["search_after"] = search_after

            res = signed_request(session, region, "POST", f"{source_endpoint}/_search", body)
            hits = res["hits"]["hits"]
            if not hits:
                break

            docs = [(h["_id"], h["_source"]) for h in hits]
            migrated += bulk_write(session, region, target_endpoint, index, docs, failed_docs_file)
            search_after = hits[-1]["sort"]

            elapsed = max(time.time() - start_time, 0.001)
            rate = migrated / elapsed
            pct = migrated * 100 // total if total else 100
            print(f"  ...{migrated:,}/{total:,} ({pct}%) — {rate:.0f} docs/sec", end="\r", flush=True)

        print()
        ok(f"'{index}': {migrated:,}/{total:,} document(s) migrated")
        return migrated, total
    finally:
        close_pit(session, region, source_endpoint, pit_id)


def main():
    args = parse_args()
    session = boto3.Session(profile_name=args.profile)
    client = session.client("opensearchserverless", region_name=args.region)

    checkpoint_path = args.checkpoint_file or f".opensearch-migration-{args.source_collection_id}-{args.target_collection_id}.json"
    failed_docs_file = args.failed_docs_file or f"opensearch-migration-failures-{args.source_collection_id}-{args.target_collection_id}.jsonl"

    if args.fresh and os.path.exists(checkpoint_path):
        os.remove(checkpoint_path)
    checkpoint = load_checkpoint(checkpoint_path)

    step(f"Fetching source (Classic) collection {args.source_collection_id}...")
    source = get_collection(client, args.source_collection_id)
    if source.get("status") != "ACTIVE":
        sys.exit(f"Error: source collection is not ACTIVE (status: {source.get('status')}).")
    source_endpoint = source["collectionEndpoint"]
    ok(f"Source: {source['name']} ({source_endpoint})")

    step(f"Fetching target (NextGen) collection {args.target_collection_id}...")
    target = get_collection(client, args.target_collection_id)
    if target.get("status") != "ACTIVE":
        sys.exit(
            f"Error: target collection is not ACTIVE (status: {target.get('status')}). "
            "Create it and wait for it to become ACTIVE before migrating."
        )
    target_endpoint = target["collectionEndpoint"]
    ok(f"Target: {target['name']} ({target_endpoint})")
    print()

    step("Listing indices on source collection...")
    indices_res = signed_request(session, args.region, "GET", f"{source_endpoint}/_cat/indices?format=json")
    # Leading-dot indices are internal/system-managed — skip them.
    indices = [i["index"] for i in indices_res if not i["index"].startswith(".")]

    if not indices:
        print("No indices found on the source collection — nothing to migrate.")
        return

    print(f"Found {len(indices)} index(es): {', '.join(indices)}")
    print()

    if args.dry_run:
        print("[dry-run mode — no data will be copied]\n")
        for index in indices:
            pit_id = open_pit(session, args.region, source_endpoint, index)
            try:
                count = count_at_pit(session, args.region, source_endpoint, pit_id)
            finally:
                close_pit(session, args.region, source_endpoint, pit_id)
            print(f"[dry-run] would migrate '{index}' ({count:,} documents) → target")
        return

    remaining = [i for i in indices if i not in checkpoint["completed_indices"]]
    already_done = [i for i in indices if i in checkpoint["completed_indices"]]
    if already_done:
        print(f"Skipping {len(already_done)} already-completed index(es) from checkpoint: {', '.join(already_done)}")
        print(f"(delete {checkpoint_path} or pass --fresh to re-migrate everything)\n")

    results = {}
    for index in remaining:
        migrated, total = migrate_index(session, args.region, source_endpoint, target_endpoint, index, args.batch_size, failed_docs_file)
        results[index] = (migrated, total)
        checkpoint["completed_indices"].append(index)
        save_checkpoint(checkpoint_path, checkpoint)

    print()
    if results:
        step("Summary:")
        for index, (migrated, total) in results.items():
            print(f"  {index}: {migrated:,}/{total:,} document(s) migrated")
        print()

    if os.path.exists(failed_docs_file):
        warn(f"Some documents failed to migrate — see {failed_docs_file} for details. Investigate before cutting over.")

    print("Migration complete!")
    print()
    print("Next steps:")
    print(f"  1. Update your application to use the NextGen endpoint: {target_endpoint}")
    print("  2. Once traffic is confirmed on the new collection, delete the classic one when no longer needed:")
    print(f"       aws opensearchserverless delete-collection --id {args.source_collection_id} --region {args.region}")


if __name__ == "__main__":
    main()
