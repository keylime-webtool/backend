use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use x509_parser::prelude::*;

use crate::models::certificate::{CertificateStatus, ExpiryCategory};

/// Parsed fields from an X.509 certificate.
#[derive(Debug, Clone)]
pub struct ParsedCertInfo {
    pub subject_dn: String,
    pub issuer_dn: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub public_key_algorithm: String,
    pub public_key_size: u32,
    pub signature_algorithm: String,
    pub sans: Vec<String>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub pem_data: String,
    pub der_data: Vec<u8>,
}

/// Try to parse cert data into X.509.
///
/// Accepts three formats produced by the Keylime Registrar API:
/// 1. Raw PEM string  (`"-----BEGIN CERTIFICATE-----\n..."`)  — `mtls_cert` field
/// 2. Base64-encoded PEM  (`"LS0tLS1CRUdJTi..."`)            — mock data compat
/// 3. Base64-encoded DER  (`"MIIE..."`)                       — `ekcert` field
///
/// Returns `None` if the data is not a valid X.509 certificate.
pub fn try_parse_x509(raw: &str) -> Option<ParsedCertInfo> {
    let trimmed = raw.trim();

    // Raw PEM string (real Keylime Registrar returns mtls_cert this way)
    if trimmed.starts_with("-----BEGIN") {
        let (_, pem) = x509_parser::pem::parse_x509_pem(trimmed.as_bytes()).ok()?;
        if pem.label != "CERTIFICATE" {
            return None;
        }
        let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;
        return Some(extract_cert_info(&cert, trimmed, pem.contents.to_vec()));
    }

    // Base64-encoded data (PEM or DER)
    let decoded = B64.decode(trimmed).ok()?;

    if decoded.starts_with(b"-----BEGIN") {
        let pem_str = String::from_utf8(decoded).ok()?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem_str.as_bytes()).ok()?;
        if pem.label != "CERTIFICATE" {
            return None;
        }
        let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;
        return Some(extract_cert_info(&cert, &pem_str, pem.contents.to_vec()));
    }

    // Base64-encoded DER (real Keylime Registrar returns ekcert this way)
    let der_copy = decoded.clone();
    if let Ok((_, cert)) = X509Certificate::from_der(&der_copy) {
        let pem_str = pem_encode(&decoded, "CERTIFICATE");
        return Some(extract_cert_info(&cert, &pem_str, decoded));
    }

    None
}

fn extract_cert_info(cert: &X509Certificate<'_>, pem: &str, der: Vec<u8>) -> ParsedCertInfo {
    let subject_dn = cert.subject().to_string();
    let issuer_dn = cert.issuer().to_string();
    let serial_number = cert.serial.to_str_radix(16);

    let not_before = asn1_to_chrono(cert.validity().not_before);
    let not_after = asn1_to_chrono(cert.validity().not_after);

    let (pub_alg, pub_size) = extract_public_key_info(cert);
    let sig_alg = cert.signature_algorithm.algorithm.to_id_string();

    let sans = extract_sans(cert);
    let key_usage = extract_key_usage(cert);
    let extended_key_usage = extract_extended_key_usage(cert);

    ParsedCertInfo {
        subject_dn,
        issuer_dn,
        serial_number,
        not_before,
        not_after,
        public_key_algorithm: pub_alg,
        public_key_size: pub_size,
        signature_algorithm: sig_alg,
        sans,
        key_usage,
        extended_key_usage,
        pem_data: pem.to_string(),
        der_data: der,
    }
}

fn asn1_to_chrono(t: ASN1Time) -> DateTime<Utc> {
    Utc.timestamp_opt(t.timestamp(), 0)
        .single()
        .unwrap_or_else(Utc::now)
}

fn extract_public_key_info(cert: &X509Certificate<'_>) -> (String, u32) {
    let spki = cert.public_key();
    let alg_oid = spki.algorithm.algorithm.to_id_string();

    let alg_name = match alg_oid.as_str() {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.10045.2.1" => "EC",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => &alg_oid,
    };

    let key_size = (spki.subject_public_key.data.len() as u32) * 8;

    (alg_name.to_string(), key_size)
}

fn extract_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                GeneralName::IPAddress(ip) => {
                    if ip.len() == 4 {
                        sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    } else {
                        sans.push(format!("{ip:?}"));
                    }
                }
                GeneralName::RFC822Name(email) => sans.push(email.to_string()),
                GeneralName::URI(uri) => sans.push(uri.to_string()),
                _ => {}
            }
        }
    }
    sans
}

fn extract_key_usage(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut usages = Vec::new();
    if let Ok(Some(ext)) = cert.key_usage() {
        let ku = &ext.value;
        if ku.digital_signature() {
            usages.push("digitalSignature".into());
        }
        if ku.non_repudiation() {
            usages.push("nonRepudiation".into());
        }
        if ku.key_encipherment() {
            usages.push("keyEncipherment".into());
        }
        if ku.data_encipherment() {
            usages.push("dataEncipherment".into());
        }
        if ku.key_agreement() {
            usages.push("keyAgreement".into());
        }
        if ku.key_cert_sign() {
            usages.push("keyCertSign".into());
        }
        if ku.crl_sign() {
            usages.push("cRLSign".into());
        }
    }
    usages
}

fn extract_extended_key_usage(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut usages = Vec::new();
    if let Ok(Some(ext)) = cert.extended_key_usage() {
        let eku = &ext.value;
        if eku.server_auth {
            usages.push("serverAuth".into());
        }
        if eku.client_auth {
            usages.push("clientAuth".into());
        }
        if eku.code_signing {
            usages.push("codeSigning".into());
        }
        if eku.email_protection {
            usages.push("emailProtection".into());
        }
        if eku.time_stamping {
            usages.push("timeStamping".into());
        }
        if eku.ocsp_signing {
            usages.push("OCSPSigning".into());
        }
        for oid in &eku.other {
            usages.push(oid.to_id_string());
        }
    }
    usages
}

fn pem_encode(der: &[u8], label: &str) -> String {
    let b64 = B64.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// Determine certificate status based on expiry relative to `now` (SDD 3.3.5).
pub fn compute_status(not_after: DateTime<Utc>, now: DateTime<Utc>) -> CertificateStatus {
    if not_after < now {
        CertificateStatus::Expired
    } else if not_after < now + chrono::Duration::days(7) {
        CertificateStatus::Critical
    } else if not_after < now + chrono::Duration::days(30) {
        CertificateStatus::ExpiringSoon
    } else {
        CertificateStatus::Valid
    }
}

/// Six-tier expiry category matching the frontend contract (FR-051).
pub fn compute_expiry_category(not_after: DateTime<Utc>, now: DateTime<Utc>) -> ExpiryCategory {
    if not_after < now {
        ExpiryCategory::Expired
    } else if not_after < now + chrono::Duration::days(1) {
        ExpiryCategory::Critical1d
    } else if not_after < now + chrono::Duration::days(7) {
        ExpiryCategory::Critical7d
    } else if not_after < now + chrono::Duration::days(30) {
        ExpiryCategory::Warning30d
    } else if not_after < now + chrono::Duration::days(90) {
        ExpiryCategory::Warning90d
    } else {
        ExpiryCategory::Valid
    }
}

/// Best-effort EK chain validation against TPM vendor CAs.
///
/// Returns `None` until a CA bundle is configured — no bundled TPM vendor
/// CA roots are shipped yet (air-gapped deployment constraint).
pub fn validate_ek_chain(_cert_der: &[u8]) -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn chrono_to_time(dt: chrono::DateTime<Utc>) -> ::time::OffsetDateTime {
        ::time::OffsetDateTime::from_unix_timestamp(dt.timestamp())
            .unwrap_or(::time::OffsetDateTime::now_utc())
    }

    fn make_test_cert_b64(not_before: i64, not_after: i64) -> String {
        use rcgen::{CertificateParams, KeyPair};

        let mut params = CertificateParams::default();
        let nb = Utc::now() + Duration::days(not_before);
        let na = Utc::now() + Duration::days(not_after);
        params.not_before = chrono_to_time(nb);
        params.not_after = chrono_to_time(na);

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        B64.encode(cert.pem())
    }

    fn make_test_cert_der_b64(not_before: i64, not_after: i64) -> String {
        use rcgen::{CertificateParams, KeyPair};

        let mut params = CertificateParams::default();
        let nb = Utc::now() + Duration::days(not_before);
        let na = Utc::now() + Duration::days(not_after);
        params.not_before = chrono_to_time(nb);
        params.not_after = chrono_to_time(na);

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        B64.encode(cert.der())
    }

    #[test]
    fn parse_valid_pem_certificate() {
        let b64 = make_test_cert_b64(-30, 365);
        let parsed = try_parse_x509(&b64);
        assert!(parsed.is_some(), "should parse valid PEM cert");
        let info = parsed.unwrap();
        assert!(!info.subject_dn.is_empty());
        assert!(!info.issuer_dn.is_empty());
        assert!(!info.serial_number.is_empty());
        assert!(!info.pem_data.is_empty());
        assert!(!info.der_data.is_empty());
    }

    #[test]
    fn parse_valid_der_certificate() {
        let b64 = make_test_cert_der_b64(-30, 365);
        let parsed = try_parse_x509(&b64);
        assert!(parsed.is_some(), "should parse valid DER cert");
        let info = parsed.unwrap();
        assert!(!info.subject_dn.is_empty());
    }

    #[test]
    fn parse_public_key_returns_none() {
        // Base64 of "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----"
        let pem_key = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4eHlGdFE9PQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K";
        assert!(try_parse_x509(pem_key).is_none());
    }

    #[test]
    fn parse_garbage_returns_none() {
        assert!(try_parse_x509("not-valid-base64!!!").is_none());
        assert!(try_parse_x509("aGVsbG8gd29ybGQ=").is_none()); // "hello world"
    }

    #[test]
    fn compute_status_expired() {
        let now = Utc::now();
        let past = now - Duration::days(1);
        assert_eq!(compute_status(past, now), CertificateStatus::Expired);
    }

    #[test]
    fn compute_status_critical() {
        let now = Utc::now();
        let soon = now + Duration::days(3);
        assert_eq!(compute_status(soon, now), CertificateStatus::Critical);
    }

    #[test]
    fn compute_status_expiring_soon() {
        let now = Utc::now();
        let in_15d = now + Duration::days(15);
        assert_eq!(compute_status(in_15d, now), CertificateStatus::ExpiringSoon);
    }

    #[test]
    fn compute_status_valid() {
        let now = Utc::now();
        let far = now + Duration::days(365);
        assert_eq!(compute_status(far, now), CertificateStatus::Valid);
    }

    #[test]
    fn ek_chain_validation_returns_none() {
        assert_eq!(validate_ek_chain(b"dummy"), None);
    }

    #[test]
    fn expiry_category_expired() {
        let now = Utc::now();
        assert_eq!(
            compute_expiry_category(now - Duration::days(1), now),
            ExpiryCategory::Expired
        );
    }

    #[test]
    fn expiry_category_critical_1d() {
        let now = Utc::now();
        assert_eq!(
            compute_expiry_category(now + Duration::hours(12), now),
            ExpiryCategory::Critical1d
        );
    }

    #[test]
    fn expiry_category_critical_7d() {
        let now = Utc::now();
        assert_eq!(
            compute_expiry_category(now + Duration::days(3), now),
            ExpiryCategory::Critical7d
        );
    }

    #[test]
    fn expiry_category_warning_30d() {
        let now = Utc::now();
        assert_eq!(
            compute_expiry_category(now + Duration::days(15), now),
            ExpiryCategory::Warning30d
        );
    }

    #[test]
    fn expiry_category_warning_90d() {
        let now = Utc::now();
        assert_eq!(
            compute_expiry_category(now + Duration::days(60), now),
            ExpiryCategory::Warning90d
        );
    }

    #[test]
    fn expiry_category_valid() {
        let now = Utc::now();
        assert_eq!(
            compute_expiry_category(now + Duration::days(365), now),
            ExpiryCategory::Valid
        );
    }

    #[test]
    fn parse_base64_der_certificate() {
        let b64_der = make_test_cert_der_b64(-30, 365);
        let parsed = try_parse_x509(&b64_der);
        assert!(
            parsed.is_some(),
            "base64(DER) cert should parse (Keylime ekcert format)"
        );
        let info = parsed.unwrap();
        assert!(!info.subject_dn.is_empty());
        assert!(!info.der_data.is_empty());
        assert!(info.pem_data.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn parse_raw_pem_certificate() {
        use rcgen::{CertificateParams, KeyPair};
        let mut params = CertificateParams::default();
        let nb = Utc::now() - Duration::days(30);
        let na = Utc::now() + Duration::days(365);
        params.not_before = chrono_to_time(nb);
        params.not_after = chrono_to_time(na);
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let raw_pem = cert.pem();

        let parsed = try_parse_x509(&raw_pem);
        assert!(
            parsed.is_some(),
            "raw PEM string should parse (Keylime mtls_cert format)"
        );
        let info = parsed.unwrap();
        assert!(!info.subject_dn.is_empty());
        assert!(!info.der_data.is_empty());
    }

    #[test]
    fn parse_raw_pem_public_key_returns_none() {
        let raw_pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----\n";
        assert!(try_parse_x509(raw_pem).is_none());
    }

    #[test]
    fn parse_disabled_mtls_cert_returns_none() {
        assert!(try_parse_x509("disabled").is_none());
    }
}
