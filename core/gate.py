import secrets

from core.interfaces import Anchor, AnchorUnavailable, Authenticator, CasResult, GateConfigError, Sealer
from core.policy import Decision, Kind, Policy, Reason, advance, decide, quota_exceeded
from core.records import (MIN_BLINDING_BYTES, Header, Record, Request, Response, State, VerifierState,
                          policy_digest, status_commitment)


class Gate:
    def __init__(self, policy: Policy, scope_id: str, secret: int, anchor: Anchor,
                 sealer: Sealer, authenticator: Authenticator, writer_key):
        if not (policy.lo <= secret <= policy.hi):
            raise ValueError("secret outside the public domain")
        self.policy, self.scope_id, self.secret = policy, scope_id, secret
        self.anchor, self.sealer, self.auth, self.writer_key = anchor, sealer, authenticator, writer_key
        self.pd = policy_digest(policy)

    def _load(self):
        rec = self.anchor.read()                      # may raise AnchorUnavailable
        if rec.header.scope_id != self.scope_id or rec.header.policy_digest != self.pd:
            raise GateConfigError("anchor record does not match this gate's scope/policy")
        st = State.from_bytes(self.sealer.unseal(rec.sealed_state))
        if st.scope_id != self.scope_id or st.policy_digest != self.pd:
            raise GateConfigError("sealed state does not match this gate's scope/policy")
        return rec, st

    @staticmethod
    def _replay(vs: VerifierState) -> Response:
        if vs.last_response == "YES":
            return Response.answered(True)
        if vs.last_response == "NO":
            return Response.answered(False)
        return Response.refused()

    def handle(self, req: Request) -> Response:
        if req.scope_id != self.scope_id or req.policy_digest != self.pd:
            return Response.rejected()
        if not isinstance(req.blinding, (bytes, bytearray)) or len(req.blinding) < MIN_BLINDING_BYTES:
            return Response.rejected()       
        if not self.auth.verify(req):
            return Response.rejected()
        try:
            rec, st = self._load()
        except AnchorUnavailable:
            return Response.retry()
        vs = st.verifiers.get(req.verifier_id)
        if vs is None:
            return Response.rejected()
        d = req.digest()
        if req.nonce == vs.last_nonce and vs.last_nonce >= 1:
            return self._replay(vs) if d == vs.last_digest else Response.rejected()
        if req.nonce != vs.last_nonce + 1:
            return Response.rejected()
        if quota_exceeded(self.policy, vs.requests):
            return Response.rejected()
        iv = st.interval
        dec = decide(self.policy, iv, req.threshold, vs.informative)
        new_iv, informative = iv, vs.informative
        if dec.kind is Kind.REFUSED:
            resp, code = Response.refused(), "REFUSED"
        else:
            if dec.kind is Kind.DETERMINED:
                answer = dec.forced_answer
                if not (iv.lo <= self.secret <= iv.hi) or answer != (self.secret > req.threshold):
                    raise GateConfigError("secret inconsistent with authoritative state")
            else:
                answer = self.secret > req.threshold
                new_iv = advance(iv, req.threshold, answer)
                informative += 1
            resp = Response.answered(answer)
            code = ("YES" if answer else "NO")
        gamma = secrets.token_bytes(32)
        st2 = State(st.scope_id, st.policy_digest, new_iv.lo, new_iv.hi, dict(st.verifiers))
        st2.verifiers[req.verifier_id] = VerifierState(
            req.nonce, d, informative, vs.requests + 1, code, gamma.hex())
        hdr = Header(self.scope_id, rec.header.version + 1, rec.digest(), req.verifier_id, req.nonce, d,
                     status_commitment(dec.kind.value + ":" + code, gamma), self.pd)
        new_rec = Record(hdr, self.sealer.seal(st2.to_bytes()))
        try:
            result = self.anchor.compare_and_swap(self.writer_key, rec.header.version, rec.digest(), new_rec)
        except AnchorUnavailable:
            return Response.retry()
        if result is CasResult.COMMITTED:
            return resp
        if result is CasResult.CONFLICT:
            return Response.retry()
        if result is CasResult.UNKNOWN:
            return self._resolve_unknown(rec, new_rec, resp)
        raise GateConfigError("anchor refused the transition: " + result.value)

    def _resolve_unknown(self, rec: Record, new_rec: Record, resp: Response) -> Response:
        """Never repeat the CAS blindly: reread the authoritative state."""
        try:
            cur = self.anchor.read()
        except AnchorUnavailable:
            return Response.retry()
        if cur.header.version == rec.header.version + 1 and cur.digest() == new_rec.digest():
            return resp
        return Response.retry()
