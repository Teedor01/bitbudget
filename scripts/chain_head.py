import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from integrations.near_rpc import NearRpc, NearRpcError, NearRpcUnavailable   # noqa: E402

DEFAULT_RPC = "https://test.rpc.fastnear.com"
EXPLORER = "https://testnet.nearblocks.io"
ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def read_head(rpc: NearRpc, contract: str) -> dict:
    h = rpc.view_function(contract, "get_head")
    if not isinstance(h, dict) or not isinstance(h.get("version"), int) or not isinstance(h.get("digest"), str):
        raise NearRpcError("the account did not return a Bit Budget head (is it the anchor contract?)")
    return {k: h.get(k) for k in ("version", "digest", "scope_id", "policy_digest", "writer")}


def main(argv=None, rpc=None, out=print):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--contract", required=True)
    ap.add_argument("--rpc", default=DEFAULT_RPC)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)
    if not ACCOUNT_RE.match(a.contract):
        out("invalid account id")
        return 2
    try:
        head = read_head(rpc or NearRpc(a.rpc), a.contract)
    except NearRpcUnavailable as e:
        out("NEAR RPC unavailable (nothing was read): %s" % e)
        return 1
    except NearRpcError as e:
        out("the chain returned an error: %s" % e)
        return 1
    links = {"contract": "%s/address/%s" % (EXPLORER, a.contract)}
    if a.json:
        out(json.dumps({"contract": a.contract, "head": head, "explorer": links}, indent=2))
        return 0
    out("contract : %s (NEAR testnet)" % a.contract)
    for k in ("version", "digest", "scope_id", "policy_digest", "writer"):
        out("%-13s %s" % (k, head[k]))
    out("explorer : %s   (read-only)" % links["contract"])
    out("source   : get_head view call at finality=final via %s" % a.rpc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
