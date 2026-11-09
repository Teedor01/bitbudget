import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from integrations.near_anchor import NearCliSender   # noqa: E402

J = '{"k":1}'
COMMANDS = {
    "create faucet account": "account create-account sponsor-by-faucet-service x.testnet autogenerate-new-keypair save-to-keychain network-config testnet create",
    "create faucet account (legacy keychain)": "account create-account sponsor-by-faucet-service x.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create",
    "view balance": "tokens x.testnet view-near-balance network-config testnet now",
    "view account": "account view-account-summary x.testnet network-config testnet now",
    "deploy + init": "contract deploy x.testnet use-file f.wasm with-init-call new json-args '%s' prepaid-gas '100 TeraGas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send" % J,
    "read-only view": "contract call-function as-read-only x.testnet get_head json-args '{}' network-config testnet now",
    "tx status": "transaction view-status 11111111111111111111111111111111 network-config testnet",
}


def run(near, argv):
    r = subprocess.run([near] + argv + ["--help"], capture_output=True, text=True, timeout=30)
    return r.returncode == 0, (r.stderr or r.stdout).strip().splitlines()[-1:] 


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--near", default="near")
    a = ap.parse_args()
    import shlex
    ver = subprocess.run([a.near, "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1:]
    print("near binary:", a.near, ver)
    ok = True
    items = [(k, shlex.split(v)) for k, v in COMMANDS.items()]
    for mode in NearCliSender.SIGN_MODES:
        items.append(("signed write (NearCliSender.argv, %s)" % mode,
                      NearCliSender("c.testnet", "g.testnet", sign_with=mode).argv({"k": 1})[1:]))
    items.append(("deploy + init (legacy keychain)", shlex.split(COMMANDS["deploy + init"].replace("sign-with-keychain", "sign-with-legacy-keychain"))))
    for name, argv in items:
        good, tail = run(a.near, argv)
        ok &= good
        print("%-4s %s %s" % ("OK" if good else "FAIL", name, "" if good else tail))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
