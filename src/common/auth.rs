//! iperf3-compatible RSA authentication (client) and authz (server).
//!
//! Protocol: client encrypts `"{unix_ts}\n{username}\n{sha256hex(password)}"`
//! with RSA-OAEP-SHA256 using the server's public key, base64-encodes the
//! result as `authtoken`. Server decrypts, splits, validates timestamp
//! skew ≤ 10s, looks up `(user, sha256hex)` in the authorized users file.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TIMESTAMP_SKEW_SECS: u64 = 10;

pub fn load_public_key_pem(path: &Path) -> Result<RsaPublicKey, String> {
    let pem = fs::read_to_string(path).map_err(|e| format!("read pubkey: {}", e))?;
    // Try PKCS#8 SubjectPublicKeyInfo first; fall back to PKCS#1.
    RsaPublicKey::from_public_key_pem(&pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(&pem))
        .map_err(|e| format!("parse pubkey: {}", e))
}

pub fn load_private_key_pem(path: &Path) -> Result<RsaPrivateKey, String> {
    let pem = fs::read_to_string(path).map_err(|e| format!("read privkey: {}", e))?;
    RsaPrivateKey::from_pkcs8_pem(&pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
        .map_err(|e| format!("parse privkey: {}", e))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn build_authtoken(
    pubkey: &RsaPublicKey,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("clock: {}", e))?
        .as_secs();
    let payload = format!("{}\n{}\n{}", ts, username, sha256_hex(password));
    let mut rng = rand::thread_rng();
    let padding = Oaep::new::<Sha256>();
    let ciphertext = pubkey
        .encrypt(&mut rng, padding, payload.as_bytes())
        .map_err(|e| format!("rsa encrypt: {}", e))?;
    Ok(B64.encode(&ciphertext))
}

pub struct AuthClaim {
    pub timestamp: u64,
    pub username: String,
    pub password_sha256_hex: String,
}

pub fn decode_authtoken(privkey: &RsaPrivateKey, token: &str) -> Result<AuthClaim, String> {
    let bytes = B64.decode(token).map_err(|e| format!("b64: {}", e))?;
    let padding = Oaep::new::<Sha256>();
    let plain = privkey
        .decrypt(padding, &bytes)
        .map_err(|e| format!("rsa decrypt: {}", e))?;
    let s = String::from_utf8(plain).map_err(|_| "authtoken not utf8".to_string())?;
    let mut parts = s.splitn(3, '\n');
    let ts: u64 = parts
        .next()
        .ok_or("missing timestamp")?
        .parse()
        .map_err(|e| format!("bad timestamp: {}", e))?;
    let username = parts.next().ok_or("missing username")?.to_string();
    let password_sha256_hex = parts.next().ok_or("missing password hash")?.to_string();
    Ok(AuthClaim {
        timestamp: ts,
        username,
        password_sha256_hex,
    })
}

pub fn validate_timestamp(claim: &AuthClaim, skew_secs: u64) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("clock: {}", e))?
        .as_secs();
    let delta = now.abs_diff(claim.timestamp);
    if delta > skew_secs {
        return Err(format!("timestamp skew {} > {}", delta, skew_secs));
    }
    Ok(())
}

pub fn load_authorized_users(path: &Path) -> Result<HashMap<String, String>, String> {
    let contents = fs::read_to_string(path).map_err(|e| format!("read authz: {}", e))?;
    let mut map = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ',');
        let user = parts
            .next()
            .ok_or_else(|| format!("bad line: {}", line))?
            .trim();
        let hash = parts
            .next()
            .ok_or_else(|| format!("bad line: {}", line))?
            .trim();
        map.insert(user.to_string(), hash.to_string());
    }
    Ok(map)
}

pub fn authorize(claim: &AuthClaim, users: &HashMap<String, String>) -> Result<(), String> {
    match users.get(&claim.username) {
        Some(expected) if expected.eq_ignore_ascii_case(&claim.password_sha256_hex) => Ok(()),
        Some(_) => Err("bad password".to_string()),
        None => Err(format!("unknown user: {}", claim.username)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;

    fn fresh_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate");
        let pub_key = RsaPublicKey::from(&priv_key);
        (priv_key, pub_key)
    }

    #[test]
    fn roundtrip_authtoken() {
        let (priv_key, pub_key) = fresh_keypair();
        let token = build_authtoken(&pub_key, "alice", "secret").unwrap();
        let claim = decode_authtoken(&priv_key, &token).unwrap();
        assert_eq!(claim.username, "alice");
        assert_eq!(claim.password_sha256_hex, sha256_hex("secret"));
        validate_timestamp(&claim, TIMESTAMP_SKEW_SECS).unwrap();
    }

    #[test]
    fn stale_timestamp_rejected() {
        let claim = AuthClaim {
            timestamp: 0,
            username: "a".into(),
            password_sha256_hex: "x".into(),
        };
        assert!(validate_timestamp(&claim, 10).is_err());
    }

    #[test]
    fn authorize_known_user() {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), sha256_hex("secret"));
        let claim = AuthClaim {
            timestamp: 0,
            username: "alice".into(),
            password_sha256_hex: sha256_hex("secret"),
        };
        authorize(&claim, &users).unwrap();
    }

    #[test]
    fn authorize_bad_password_rejected() {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), sha256_hex("secret"));
        let claim = AuthClaim {
            timestamp: 0,
            username: "alice".into(),
            password_sha256_hex: sha256_hex("wrong"),
        };
        assert!(authorize(&claim, &users).is_err());
    }

    #[test]
    fn authorize_unknown_user_rejected() {
        let users = HashMap::new();
        let claim = AuthClaim {
            timestamp: 0,
            username: "alice".into(),
            password_sha256_hex: sha256_hex("secret"),
        };
        assert!(authorize(&claim, &users).is_err());
    }
}
