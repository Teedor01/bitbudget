import base64
import json
import urllib.error
import urllib.request


class NearRpcUnavailable(Exception):
    """Network failure, timeout, HTTP 429/5xx, or malformed reply: outcome of the READ is unknown."""


class NearRpcError(Exception):
    """The node answered with an error (unknown account/method, contract panic, ...)."""


def _urllib_transport(url, body: bytes, timeout):
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise NearRpcUnavailable("HTTP %s" % e.code) from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise NearRpcUnavailable(str(e)) from e


class NearRpc:
    def __init__(self, url, transport=None, timeout=10.0):
        self.url, self.timeout = url, timeout
        self._transport = transport or _urllib_transport

    def _call(self, method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": "bitbudget", "method": method, "params": params}).encode()
        raw = self._transport(self.url, body, self.timeout)
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError) as e:
            raise NearRpcUnavailable("non-JSON reply") from e
        if not isinstance(obj, dict):
            raise NearRpcUnavailable("unexpected reply shape")
        if obj.get("error") is not None:
            raise NearRpcError(json.dumps(obj["error"])[:300])
        if "result" not in obj:
            raise NearRpcUnavailable("reply has neither result nor error")
        return obj["result"]

    def view_function(self, account_id, method_name, args=None, finality="final"):
        """Returns the JSON-decoded return value of a view method."""
        params = {"request_type": "call_function", "finality": finality, "account_id": account_id,
                  "method_name": method_name,
                  "args_base64": base64.b64encode(json.dumps(args or {}).encode()).decode()}
        res = self._call("query", params)
        if not isinstance(res, dict):
            raise NearRpcUnavailable("unexpected result shape")
        if res.get("error"):
            raise NearRpcError(str(res["error"])[:300])
        try:
            return json.loads(bytes(res["result"]).decode())
        except (KeyError, TypeError, ValueError) as e:
            raise NearRpcUnavailable("undecodable view result") from e

    def status(self):
        """Node status: {"chain_id", "protocol_version", ...}. Validates the fields the preflight relies on."""
        res = self._call("status", [])
        if (not isinstance(res, dict) or not isinstance(res.get("chain_id"), str)
                or not isinstance(res.get("protocol_version"), int) or isinstance(res.get("protocol_version"), bool)):
            raise NearRpcUnavailable("unexpected status shape")
        return res

    def view_account(self, account_id, finality="final"):
        """Account summary ({"amount", "code_hash", "storage_usage", ...}); NearRpcError if it does not exist."""
        res = self._call("query", {"request_type": "view_account", "finality": finality, "account_id": account_id})
        if not isinstance(res, dict):
            raise NearRpcUnavailable("unexpected result shape")
        if res.get("error"):
            raise NearRpcError(str(res["error"])[:300])
        return res
