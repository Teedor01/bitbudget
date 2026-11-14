//! Bit Budget anchor contract. Stores ONLY the head of a hash chain: (version, record digest). It never sees the
//! secret, the sealed state, or any request blinding. Each committed header is emitted as a log line (public audit
//! trail). The contract CANNOT verify that `new_digest` matches a record's contents; the gate-side client
//! (integrations/near_anchor.py) does that, and the single writer account is trusted not to commit a false digest.
//!
//! Verification status is recorded in NEAR_EVIDENCE.md (what ran: native unit tests, execution of the compiled wasm in
//! the nearcore VM crate; what has NOT run: any real NEAR network).
use near_sdk::serde_json::{self, json, Value};
use near_sdk::{env, near, require, AccountId, PanicOnDefault};

#[near(serializers = [json])]
pub struct Head {
    pub version: u64,
    pub digest: String,
    pub scope_id: String,
    pub policy_digest: String,
    pub writer: AccountId,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Anchor {
    writer: AccountId,
    scope_id: String,
    policy_digest: String,
    version: u64,
    digest: String,
}

const MAX_HEADER_BYTES: usize = 1024;

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[near]
impl Anchor {
    #[init]
    pub fn new(writer: AccountId, scope_id: String, policy_digest: String, genesis_digest: String) -> Self {
        require!(is_hex64(&genesis_digest) && is_hex64(&policy_digest), "bad digest");
        Self { writer, scope_id, policy_digest, version: 0, digest: genesis_digest }
    }

    pub fn get_head(&self) -> Head {
        Head {
            version: self.version,
            digest: self.digest.clone(),
            scope_id: self.scope_id.clone(),
            policy_digest: self.policy_digest.clone(),
            writer: self.writer.clone(),
        }
    }

    /// Returns "COMMITTED" | "CONFLICT" | "UNAUTHORIZED" | "MALFORMED". Never panics on those paths, so the
    /// transaction itself succeeds; clients must decide by re-reading `get_head`, not by parsing the return.
    /// Check order: authorization, then format, then compare-and-swap.
    pub fn cas(&mut self, expected_version: u64, expected_digest: String, new_digest: String, header: String) -> String {
        if env::predecessor_account_id() != self.writer {
            return "UNAUTHORIZED".to_string();
        }
        if !is_hex64(&expected_digest) || !is_hex64(&new_digest) || header.len() > MAX_HEADER_BYTES {
            return "MALFORMED".to_string();
        }
        let header_json: Value = match serde_json::from_str::<Value>(&header) {
            Ok(v) if v.is_object() => v,
            _ => return "MALFORMED".to_string(),
        };
        if expected_version != self.version || expected_digest != self.digest {
            return "CONFLICT".to_string();
        }
        self.version += 1;
        self.digest = new_digest.clone();
        let event = json!({"standard": "bitbudget-anchor", "version": self.version,
                           "digest": new_digest, "header": header_json});
        env::log_str(&format!("EVENT_JSON:{}", event));
        "COMMITTED".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{get_logs, VMContextBuilder};
    use near_sdk::testing_env;

    const D0: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const D1: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const D2: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const PD: &str = "00000000000000000000000000000000000000000000000000000000000000aa";
    const H: &str = "{\"nonce\":1}";

    fn ctx(who: &str) {
        testing_env!(VMContextBuilder::new().predecessor_account_id(who.parse().unwrap()).build());
    }
    fn fresh() -> Anchor {
        ctx("gate.testnet");
        Anchor::new("gate.testnet".parse().unwrap(), "s".into(), PD.into(), D0.into())
    }
    fn cas(c: &mut Anchor, ev: u64, ed: &str, nd: &str, h: &str) -> String {
        c.cas(ev, ed.into(), nd.into(), h.into())
    }
    fn head(c: &Anchor) -> (u64, String) {
        let h = c.get_head();
        (h.version, h.digest)
    }

    #[test]
    fn genesis_head_reports_all_fields() {
        let c = fresh();
        let h = c.get_head();
        assert_eq!((h.version, h.digest.as_str(), h.scope_id.as_str(), h.policy_digest.as_str()), (0, D0, "s", PD));
        assert_eq!(h.writer.as_str(), "gate.testnet");
    }

    #[test]
    fn commit_advances_head_and_emits_one_valid_event() {
        let mut c = fresh();
        assert_eq!(cas(&mut c, 0, D0, D1, H), "COMMITTED");
        assert_eq!(head(&c), (1, D1.to_string()));
        let logs = get_logs();
        assert_eq!(logs.len(), 1);
        let ev: Value = serde_json::from_str(logs[0].strip_prefix("EVENT_JSON:").expect("prefix")).expect("valid json");
        assert_eq!((ev["version"].as_u64(), ev["digest"].as_str()), (Some(1), Some(D1)));
        assert_eq!(ev["header"]["nonce"], 1);
    }

    #[test]
    fn chain_continues_from_new_head() {
        let mut c = fresh();
        assert_eq!(cas(&mut c, 0, D0, D1, H), "COMMITTED");
        assert_eq!(cas(&mut c, 1, D1, D2, H), "COMMITTED");
        assert_eq!(head(&c), (2, D2.to_string()));
    }

    #[test]
    fn stale_compare_and_swap_conflicts_and_changes_nothing() {
        let mut c = fresh();
        assert_eq!(cas(&mut c, 0, D0, D1, H), "COMMITTED");
        let before = get_logs().len();
        assert_eq!(cas(&mut c, 0, D0, D2, H), "CONFLICT");
        assert_eq!(head(&c), (1, D1.to_string()));
        assert_eq!(get_logs().len(), before, "a conflict must not log");
    }

    #[test]
    fn wrong_digest_with_right_version_conflicts() {
        let mut c = fresh();
        assert_eq!(cas(&mut c, 0, D2, D1, H), "CONFLICT");
        assert_eq!(head(&c), (0, D0.to_string()));
    }

    #[test]
    fn wrong_version_with_right_digest_conflicts() {
        let mut c = fresh();
        assert_eq!(cas(&mut c, 1, D0, D1, H), "CONFLICT");
        assert_eq!(head(&c), (0, D0.to_string()));
    }

    #[test]
    fn other_account_is_unauthorized_even_with_a_perfect_request() {
        let mut c = fresh();
        ctx("mallory.testnet");
        assert_eq!(cas(&mut c, 0, D0, D1, H), "UNAUTHORIZED");
        assert_eq!(head(&c), (0, D0.to_string()));
        assert!(get_logs().is_empty());
        // authorization is checked before format: a malformed request from a stranger is still UNAUTHORIZED
        assert_eq!(cas(&mut c, 0, "x", "y", "z"), "UNAUTHORIZED");
    }

    #[test]
    fn malformed_digests_are_rejected() {
        let mut c = fresh();
        for bad in ["xyz", "", &"A".repeat(64), &"0".repeat(63), &"0".repeat(65)] {
            assert_eq!(cas(&mut c, 0, D0, bad, H), "MALFORMED", "new_digest {bad:?}");
            assert_eq!(cas(&mut c, 0, bad, D1, H), "MALFORMED", "expected_digest {bad:?}");
        }
        assert_eq!(head(&c), (0, D0.to_string()));
        assert!(get_logs().is_empty());
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let mut c = fresh();
        for bad in ["not json", "[1]", "\"s\"", "null", "{\"a\":", &format!("{{\"k\":\"{}\"}}", "x".repeat(2000))] {
            assert_eq!(cas(&mut c, 0, D0, D1, bad), "MALFORMED", "header {:?}", &bad[..bad.len().min(20)]);
        }
        assert_eq!(head(&c), (0, D0.to_string()));
        assert!(get_logs().is_empty());
    }

    #[test]
    #[should_panic(expected = "bad digest")]
    fn non_hex_genesis_digest_panics() {
        ctx("gate.testnet");
        let _ = Anchor::new("gate.testnet".parse().unwrap(), "s".into(), PD.into(), "nothex".into());
    }

    #[test]
    #[should_panic(expected = "bad digest")]
    fn non_hex_policy_digest_panics() {
        ctx("gate.testnet");
        let _ = Anchor::new("gate.testnet".parse().unwrap(), "s".into(), "nothex".into(), D0.into());
    }
}
