"""CLI: python -m ieso_sim [--endpoints 200] [--seed 7] [--control-plane URL] [--out fleet.json]"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections import Counter

from .fleet import generate


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate and import the simulated fleet")
    ap.add_argument("--endpoints", type=int, default=200)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--control-plane", default=os.environ.get("CONTROL_PLANE", "http://control-plane:8000"))
    ap.add_argument("--out", help="write the fleet JSON to this file instead of importing it")
    args = ap.parse_args()
    fleet = generate(args.endpoints, args.seed)
    kinds = Counter(i["type"].rsplit(".", 1)[-1] for ep in fleet for i in ep["incidents"])
    print(f"simulated fleet: {len(fleet)} endpoints, incidents: {dict(kinds)}")
    if args.out:
        with open(args.out, "w") as f:
            json.dump({"endpoints": fleet}, f, indent=1)
        print(f"written to {args.out}")
        return 0
    req = urllib.request.Request(f"{args.control_plane}/v1/admin/import", data=json.dumps({"endpoints": fleet}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(f"imported into {args.control_plane}: {json.loads(resp.read())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
