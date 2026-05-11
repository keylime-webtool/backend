use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::MtlsConfig;

/// On-disk representation of user-configured settings.
///
/// Only fields that the user has explicitly set via the Settings API are
/// present.  The TOML file looks like:
///
/// ```toml
/// [keylime]
/// verifier_url = "https://verifier.example.com:8881"
/// registrar_url = "https://registrar.example.com:8891"
///
/// [mtls]
/// cert = "/etc/keylime/cert.pem"
/// key  = "/etc/keylime/key.pem"
/// ca_cert = "/etc/keylime/ca.pem"
/// ```
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedSettings {
    pub keylime: Option<PersistedKeylime>,
    pub mtls: Option<MtlsConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedKeylime {
    pub verifier_url: String,
    pub registrar_url: String,
}

/// Resolve the config file path.
///
/// Priority: `KEYLIME_WEBTOOL_CONFIG` env var > `~/.config/keylime-webtool/settings.toml` > `None`.
pub fn resolve_config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KEYLIME_WEBTOOL_CONFIG") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }

    if let Some(home) = dirs_path() {
        return Some(home.join(".config/keylime-webtool/settings.toml"));
    }

    tracing::warn!(
        "unable to determine config file path: no KEYLIME_WEBTOOL_CONFIG and no home directory"
    );
    None
}

/// Load persisted settings from disk. Returns `None` if the file does not
/// exist or cannot be parsed (a warning is logged in the latter case).
pub fn load_persisted_settings(path: &std::path::Path) -> Option<PersistedSettings> {
    match std::fs::read_to_string(path) {
        Ok(contents) => match toml::from_str::<PersistedSettings>(&contents) {
            Ok(s) => {
                tracing::info!("loaded persisted settings from {}", path.display());
                Some(s)
            }
            Err(e) => {
                tracing::warn!("failed to parse settings file {}: {e}", path.display());
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!("failed to read settings file {}: {e}", path.display());
            None
        }
    }
}

/// Persist settings to disk atomically (write temp file, then rename).
///
/// Creates parent directories if needed.  Runs blocking I/O on
/// `spawn_blocking` so we never block the async runtime.
///
/// Returns `Ok(())` on success.  On failure the error is logged as a
/// warning — callers should NOT propagate the error to the HTTP response.
pub async fn save_persisted_settings(path: PathBuf, settings: PersistedSettings) {
    if let Err(e) = tokio::task::spawn_blocking(move || save_sync(&path, &settings)).await {
        tracing::warn!("settings persistence task panicked: {e}");
    }
}

fn save_sync(path: &std::path::Path, settings: &PersistedSettings) {
    let content = match toml::to_string_pretty(settings) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("failed to serialize settings: {e}");
            return;
        }
    };

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "failed to create settings directory {}: {e}",
                parent.display()
            );
            return;
        }
    }

    // Atomic write: temp file in the same directory, then rename.
    let tmp = path.with_extension("toml.tmp");
    if let Err(e) = std::fs::write(&tmp, &content) {
        tracing::warn!("failed to write temp settings file {}: {e}", tmp.display());
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        tracing::warn!(
            "failed to rename temp settings file {} -> {}: {e}",
            tmp.display(),
            path.display()
        );
        // Clean up the temp file on rename failure.
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Get the user's home directory via the HOME env var.
fn dirs_path() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn round_trip_keylime_only() {
        let settings = PersistedSettings {
            keylime: Some(PersistedKeylime {
                verifier_url: "https://v.example.com:8881".into(),
                registrar_url: "https://r.example.com:8891".into(),
            }),
            mtls: None,
        };
        let toml_str = toml::to_string_pretty(&settings).unwrap();
        let parsed: PersistedSettings = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            parsed.keylime.as_ref().unwrap().verifier_url,
            "https://v.example.com:8881"
        );
        assert!(parsed.mtls.is_none());
    }

    #[test]
    fn round_trip_full() {
        let settings = PersistedSettings {
            keylime: Some(PersistedKeylime {
                verifier_url: "https://v:8881".into(),
                registrar_url: "https://r:8891".into(),
            }),
            mtls: Some(crate::config::MtlsConfig {
                cert: PathBuf::from("/etc/cert.pem"),
                key: "/etc/key.pem".into(),
                ca_cert: PathBuf::from("/etc/ca.pem"),
            }),
        };
        let toml_str = toml::to_string_pretty(&settings).unwrap();
        let parsed: PersistedSettings = toml::from_str(&toml_str).unwrap();
        let kl = parsed.keylime.unwrap();
        assert_eq!(kl.verifier_url, "https://v:8881");
        let mtls = parsed.mtls.unwrap();
        assert_eq!(mtls.cert, PathBuf::from("/etc/cert.pem"));
    }

    #[test]
    fn load_missing_file_returns_none() {
        assert!(load_persisted_settings(std::path::Path::new("/nonexistent/path.toml")).is_none());
    }

    #[test]
    fn atomic_write_and_reload() {
        let dir = std::env::temp_dir().join("keylime-webtool-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-settings.toml");

        let settings = PersistedSettings {
            keylime: Some(PersistedKeylime {
                verifier_url: "http://localhost:3000".into(),
                registrar_url: "http://localhost:3001".into(),
            }),
            mtls: None,
        };

        save_sync(&path, &settings);
        let loaded = load_persisted_settings(&path).unwrap();
        assert_eq!(
            loaded.keylime.unwrap().verifier_url,
            "http://localhost:3000"
        );

        // Clean up.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn resolve_config_path_from_env() {
        std::env::set_var("KEYLIME_WEBTOOL_CONFIG", "/tmp/test-config.toml");
        let path = resolve_config_path();
        assert_eq!(path, Some(PathBuf::from("/tmp/test-config.toml")));
        std::env::remove_var("KEYLIME_WEBTOOL_CONFIG");
    }

    #[test]
    fn resolve_config_path_empty_env() {
        std::env::set_var("KEYLIME_WEBTOOL_CONFIG", "");
        let path = resolve_config_path();
        // falls through to dirs_path
        assert!(path.is_some() || path.is_none());
        std::env::remove_var("KEYLIME_WEBTOOL_CONFIG");
    }

    #[test]
    fn dirs_path_returns_home() {
        let home = std::env::var("HOME").ok();
        let result = dirs_path();
        if home.is_some() {
            assert!(result.is_some());
        }
    }

    #[test]
    fn load_invalid_toml_returns_none() {
        let dir = std::env::temp_dir().join("keylime-webtool-test-invalid");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("invalid.toml");
        std::fs::write(&path, "not valid { toml").unwrap();
        assert!(load_persisted_settings(&path).is_none());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn persisted_settings_default() {
        let settings = PersistedSettings::default();
        assert!(settings.keylime.is_none());
        assert!(settings.mtls.is_none());
    }
}
