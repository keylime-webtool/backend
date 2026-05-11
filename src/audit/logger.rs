use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Severity levels for audit events (FR-042).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditSeverity {
    Critical,
    Warning,
    Info,
}

/// A single tamper-evident audit log entry (FR-061, SR-015).
///
/// Each entry includes a SHA-256 hash of the previous entry,
/// forming a hash chain. The chain root is anchored via RFC 3161.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub severity: AuditSeverity,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub result: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

impl AuditEntry {
    /// Compute the SHA-256 hash for this entry's content (excluding entry_hash itself).
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.to_le_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.actor.as_bytes());
        hasher.update(self.action.as_bytes());
        hasher.update(self.resource.as_bytes());
        hasher.update(self.result.as_bytes());
        hasher.update(self.previous_hash.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Parameters for creating an audit entry.
pub struct AuditEntryParams<'a> {
    pub severity: AuditSeverity,
    pub actor: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    pub source_ip: &'a str,
    pub user_agent: Option<&'a str>,
    pub result: &'a str,
}

/// Audit logger that maintains the hash chain.
pub struct AuditLogger {
    last_hash: String,
    next_id: u64,
}

impl AuditLogger {
    /// Create a new logger, optionally resuming from a previous chain tip.
    pub fn new(last_hash: Option<String>, next_id: u64) -> Self {
        Self {
            last_hash: last_hash.unwrap_or_else(|| "0".repeat(64)),
            next_id,
        }
    }

    /// Create a new audit entry and advance the chain.
    pub fn create_entry(&mut self, params: AuditEntryParams<'_>) -> AuditEntry {
        let AuditEntryParams {
            severity,
            actor,
            action,
            resource,
            source_ip,
            user_agent,
            result,
        } = params;
        let mut entry = AuditEntry {
            id: self.next_id,
            timestamp: Utc::now(),
            severity,
            actor: actor.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            source_ip: source_ip.to_string(),
            user_agent: user_agent.map(String::from),
            result: result.to_string(),
            previous_hash: self.last_hash.clone(),
            entry_hash: String::new(),
        };
        entry.entry_hash = entry.compute_hash();
        self.last_hash = entry.entry_hash.clone();
        self.next_id += 1;
        entry
    }

    /// Verify the integrity of a chain of entries.
    pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), ChainVerificationError> {
        for window in entries.windows(2) {
            let prev = &window[0];
            let curr = &window[1];

            // Verify the current entry's own hash is valid.
            let computed = curr.compute_hash();
            if computed != curr.entry_hash {
                return Err(ChainVerificationError::TamperedEntry(curr.id));
            }

            // Verify chain linkage.
            if curr.previous_hash != prev.entry_hash {
                return Err(ChainVerificationError::BrokenChain(curr.id));
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainVerificationError {
    #[error("hash chain broken at entry {0}")]
    BrokenChain(u64),
    #[error("entry {0} has been tampered with")]
    TamperedEntry(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_is_valid() {
        let mut logger = AuditLogger::new(None, 1);
        let e1 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "admin@example.com",
            action: "LOGIN",
            resource: "session",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });
        let e2 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Warning,
            actor: "admin@example.com",
            action: "UPDATE_POLICY",
            resource: "production-v2",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });

        assert_eq!(e2.previous_hash, e1.entry_hash);
        assert!(AuditLogger::verify_chain(&[e1, e2]).is_ok());
    }

    #[test]
    fn tampered_entry_detected() {
        let mut logger = AuditLogger::new(None, 1);
        let e1 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "admin@example.com",
            action: "LOGIN",
            resource: "session",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });
        let mut e2 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "admin@example.com",
            action: "READ",
            resource: "agents",
            source_ip: "10.0.0.1",
            user_agent: None,
            result: "SUCCESS",
        });

        // Tamper with e2
        e2.action = "DELETE".to_string();

        let result = AuditLogger::verify_chain(&[e1, e2]);
        assert!(result.is_err());
    }

    #[test]
    fn verify_empty_chain() {
        assert!(AuditLogger::verify_chain(&[]).is_ok());
    }

    #[test]
    fn verify_single_entry() {
        let mut logger = AuditLogger::new(None, 1);
        let e = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "user",
            action: "READ",
            resource: "agents",
            source_ip: "127.0.0.1",
            user_agent: None,
            result: "OK",
        });
        assert!(AuditLogger::verify_chain(&[e]).is_ok());
    }

    #[test]
    fn custom_starting_hash() {
        let custom = "abc123".repeat(10);
        let mut logger = AuditLogger::new(Some(custom.clone()), 42);
        let e = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Critical,
            actor: "sys",
            action: "STARTUP",
            resource: "system",
            source_ip: "0.0.0.0",
            user_agent: None,
            result: "OK",
        });
        assert_eq!(e.id, 42);
        assert_eq!(e.previous_hash, custom);
    }

    #[test]
    fn id_auto_increments() {
        let mut logger = AuditLogger::new(None, 1);
        let params = || AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "u",
            action: "A",
            resource: "R",
            source_ip: "0",
            user_agent: None,
            result: "OK",
        };
        let e1 = logger.create_entry(params());
        let e2 = logger.create_entry(params());
        let e3 = logger.create_entry(params());
        assert_eq!(e1.id, 1);
        assert_eq!(e2.id, 2);
        assert_eq!(e3.id, 3);
    }

    #[test]
    fn broken_chain_detected() {
        let mut logger = AuditLogger::new(None, 1);
        let e1 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "u",
            action: "A",
            resource: "R",
            source_ip: "0",
            user_agent: None,
            result: "OK",
        });
        let mut e2 = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "u",
            action: "B",
            resource: "R",
            source_ip: "0",
            user_agent: None,
            result: "OK",
        });
        e2.previous_hash = "wrong".to_string();
        e2.entry_hash = e2.compute_hash();
        let result = AuditLogger::verify_chain(&[e1, e2]);
        assert!(matches!(
            result,
            Err(ChainVerificationError::BrokenChain(2))
        ));
    }

    #[test]
    fn severity_serde_roundtrip() {
        for sev in [
            AuditSeverity::Critical,
            AuditSeverity::Warning,
            AuditSeverity::Info,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let deserialized: AuditSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, sev);
        }
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let mut logger = AuditLogger::new(None, 1);
        let e = logger.create_entry(AuditEntryParams {
            severity: AuditSeverity::Info,
            actor: "test",
            action: "CHECK",
            resource: "x",
            source_ip: "1.2.3.4",
            user_agent: Some("test-agent"),
            result: "OK",
        });
        assert_eq!(e.entry_hash, e.compute_hash());
    }
}
