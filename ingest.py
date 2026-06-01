#!/usr/bin/env python3
"""
BLOODHOUND — ingest.py
Loads logs.ndjson into local Elasticsearch.

  pip install "elasticsearch>=8,<9"
  python3 ingest.py            # uses logs.ndjson in this folder

It (1) creates the index with mapping.json so source.ip/destination.ip are real
`ip` fields (cidrMatch needs that), (2) adds hour_of_day to every doc (EQL can't
extract hour from a timestamp), (3) bulk-loads everything.
"""
import argparse, json
from elasticsearch import Elasticsearch, helpers

INDEX = "bloodhound-logs"

def docs(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            d["hour_of_day"] = int(d["@timestamp"][11:13])
            yield {"_index": INDEX, "_source": d}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="logs.ndjson")
    ap.add_argument("--host", default="http://localhost:9200")
    args = ap.parse_args()

    es = Elasticsearch(args.host, request_timeout=60)
    if not es.ping():
        raise SystemExit("Cannot reach Elasticsearch. Is `docker compose up -d` running?")

    if es.indices.exists(index=INDEX):
        es.indices.delete(index=INDEX)
    with open("mapping.json") as f:
        es.indices.create(index=INDEX, body=json.load(f))

    ok = errors = 0
    for success, _ in helpers.streaming_bulk(es, docs(args.file),
                                             chunk_size=2000, raise_on_error=False):
        ok += success; errors += (not success)
    es.indices.refresh(index=INDEX)
    print(f"indexed ok={ok} errors={errors} | "
          f"index holds {es.count(index=INDEX)['count']:,} docs")

if __name__ == "__main__":
    main()
