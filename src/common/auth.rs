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
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const TIMESTAMP_SKEW_SECS: u64 = 10;

/// Minimum acceptable RSA modulus size in bytes. 256 bytes = 2048 bits,
/// the floor recommended by NIST SP 800-57 for new deployments.
const MIN_RSA_KEY_BYTES: usize = 256;

/// On Unix, refuse to load any secret file whose mode grants any
/// permission to group/other. Equivalent to OpenSSH's check on
/// `~/.ssh/id_*`. On non-Unix this is a no-op since file modes do
/// not have an equivalent meaning.
#[cfg(unix)]
fn check_secret_file_mode(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).map_err(|e| format!("stat {}: {}", path.display(), e))?;
    let mode = meta.mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "{}: insecure permissions (mode 0o{:o}); chmod 0600 (or stricter) and retry",
            path.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secret_file_mode(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Replay cache: SHA-256 of every authtoken ciphertext we've recently
/// accepted, mapped to the deadline after which the entry can be evicted.
/// TTL is `2 * TIMESTAMP_SKEW_SECS`, the full window during which a
/// captured token would still pass `validate_timestamp`.
pub struct NonceCache {
    seen: Mutex<HashMap<[u8; 32], Instant>>,
    ttl: std::time::Duration,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::with_ttl(std::time::Duration::from_secs(TIMESTAMP_SKEW_SECS * 2))
    }

    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Record `token_ciphertext` as seen. Returns `Err` if it was already
    /// seen within the TTL window (i.e. this is a replay).
    pub fn check_and_record(&self, token_ciphertext: &[u8]) -> Result<(), String> {
        let mut hasher = Sha256::new();
        hasher.update(token_ciphertext);
        let digest: [u8; 32] = hasher.finalize().into();

        let now = Instant::now();
        let mut seen = self.seen.lock().map_err(|e| format!("nonce lock: {}", e))?;

        // Opportunistic eviction of expired entries to keep the map bounded.
        seen.retain(|_, deadline| *deadline > now);

        if seen.contains_key(&digest) {
            return Err("authtoken replay detected".to_string());
        }
        seen.insert(digest, now + self.ttl);
        Ok(())
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn load_public_key_pem(path: &Path) -> Result<RsaPublicKey, String> {
    let pem = fs::read_to_string(path).map_err(|e| format!("read pubkey: {}", e))?;
    // Try PKCS#8 SubjectPublicKeyInfo first; fall back to PKCS#1.
    let key = RsaPublicKey::from_public_key_pem(&pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(&pem))
        .map_err(|e| format!("parse pubkey: {}", e))?;
    if key.size() < MIN_RSA_KEY_BYTES {
        return Err(format!(
            "pubkey too small: {} bits (minimum {} bits)",
            key.size() * 8,
            MIN_RSA_KEY_BYTES * 8
        ));
    }
    Ok(key)
}

pub fn load_private_key_pem(path: &Path) -> Result<RsaPrivateKey, String> {
    check_secret_file_mode(path)?;
    let pem = fs::read_to_string(path).map_err(|e| format!("read privkey: {}", e))?;
    let key = RsaPrivateKey::from_pkcs8_pem(&pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
        .map_err(|e| format!("parse privkey: {}", e))?;
    if key.size() < MIN_RSA_KEY_BYTES {
        return Err(format!(
            "privkey too small: {} bits (minimum {} bits)",
            key.size() * 8,
            MIN_RSA_KEY_BYTES * 8
        ));
    }
    Ok(key)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Refuse usernames or passwords containing characters that would
/// confuse the newline-delimited payload in `build_authtoken`. A
/// malicious-but-authenticated user with `username = "victim\n<hash>"`
/// could otherwise inject an extra field and authenticate as a
/// different account whose hash they know.
fn validate_credential_field(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{}: must not be empty", label));
    }
    if let Some(bad) = value.chars().find(|c| c.is_control()) {
        return Err(format!(
            "{}: rejects control character (U+{:04X})",
            label, bad as u32
        ));
    }
    Ok(())
}

pub fn build_authtoken(
    pubkey: &RsaPublicKey,
    username: &str,
    password: &str,
) -> Result<String, String> {
    validate_credential_field("username", username)?;
    validate_credential_field("password", password)?;
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
    decode_authtoken_bytes(privkey, &bytes)
}

/// Same as [`decode_authtoken`] but takes the already-base64-decoded
/// ciphertext bytes. Callers that need to key a replay cache on the raw
/// ciphertext should use this directly.
pub fn decode_authtoken_bytes(
    privkey: &RsaPrivateKey,
    ciphertext: &[u8],
) -> Result<AuthClaim, String> {
    let padding = Oaep::new::<Sha256>();
    let plain = privkey
        .decrypt(padding, ciphertext)
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
    if username.is_empty() || username.chars().any(|c| c.is_control()) {
        return Err("username: invalid characters".into());
    }
    if password_sha256_hex.len() != 64
        || !password_sha256_hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err("password hash: malformed".into());
    }
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
    check_secret_file_mode(path)?;
    let contents = fs::read_to_string(path).map_err(|e| format!("read authz: {}", e))?;
    let mut map: HashMap<String, String> = HashMap::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ',');
        let user = parts
            .next()
            .ok_or_else(|| format!("bad line {}: {}", lineno + 1, line))?
            .trim()
            .to_ascii_lowercase();
        let hash = parts
            .next()
            .ok_or_else(|| format!("bad line {}: {}", lineno + 1, line))?
            .trim()
            .to_ascii_lowercase();
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "bad line {}: hash must be 64 lowercase hex chars",
                lineno + 1
            ));
        }
        if map.insert(user.clone(), hash).is_some() {
            return Err(format!("duplicate user '{}' on line {}", user, lineno + 1));
        }
    }
    Ok(map)
}

/// Constant-time equality on equal-length byte slices. Returns `false`
/// fast if lengths differ (lengths are public). Otherwise compares every
/// byte with no early exit, so the compare time depends only on length.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A fixed-length sentinel used as the dummy comparator when the
/// claimed username is unknown. Ensures the unknown-user code path
/// performs the same constant-time hash compare that the known-user
/// path does, so the two cannot be distinguished by timing.
const DUMMY_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub fn authorize(claim: &AuthClaim, users: &HashMap<String, String>) -> Result<(), String> {
    let lookup_username = claim.username.to_ascii_lowercase();
    let claim_hash = claim.password_sha256_hex.to_ascii_lowercase();
    let expected = users
        .get(&lookup_username)
        .map(String::as_str)
        .unwrap_or(DUMMY_HASH);
    let matched = constant_time_eq(expected.as_bytes(), claim_hash.as_bytes());
    let user_exists = users.contains_key(&lookup_username);
    if matched && user_exists {
        Ok(())
    } else {
        // Single opaque error — server logs distinguish, wire does not.
        Err("authentication failed".to_string())
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
    fn build_authtoken_rejects_newline_in_username() {
        let (_, pub_key) = fresh_keypair();
        let err = build_authtoken(&pub_key, "victim\nmalicious", "secret").unwrap_err();
        assert!(err.contains("username"), "got: {}", err);
    }

    #[test]
    fn build_authtoken_rejects_empty_username() {
        let (_, pub_key) = fresh_keypair();
        assert!(build_authtoken(&pub_key, "", "secret").is_err());
    }

    #[test]
    fn build_authtoken_rejects_newline_in_password() {
        let (_, pub_key) = fresh_keypair();
        assert!(build_authtoken(&pub_key, "alice", "secret\nthing").is_err());
    }

    #[test]
    fn nonce_cache_rejects_replay() {
        let cache = NonceCache::new();
        let ciphertext = b"some-rsa-oaep-ciphertext-bytes";
        cache.check_and_record(ciphertext).expect("first use ok");
        assert!(
            cache.check_and_record(ciphertext).is_err(),
            "replay must be rejected"
        );
    }

    #[test]
    fn nonce_cache_distinct_ciphertexts_both_accepted() {
        let cache = NonceCache::new();
        cache.check_and_record(b"ciphertext-A").expect("A ok");
        cache.check_and_record(b"ciphertext-B").expect("B ok");
    }

    #[test]
    fn nonce_cache_expires_old_entries() {
        let cache = NonceCache::with_ttl(std::time::Duration::from_millis(50));
        cache.check_and_record(b"token").expect("first ok");
        std::thread::sleep(std::time::Duration::from_millis(80));
        cache
            .check_and_record(b"token")
            .expect("post-TTL re-acceptance");
    }

    #[test]
    fn authorize_unknown_user_rejected() {
        let users = HashMap::new();
        let claim = AuthClaim {
            timestamp: 0,
            username: "alice".into(),
            password_sha256_hex: sha256_hex("secret"),
        };
        let err = authorize(&claim, &users).unwrap_err();
        assert_eq!(
            err, "authentication failed",
            "unknown-user error must be opaque",
        );
    }

    #[test]
    fn authorize_bad_password_returns_opaque_error() {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), sha256_hex("secret"));
        let claim = AuthClaim {
            timestamp: 0,
            username: "alice".into(),
            password_sha256_hex: sha256_hex("wrong"),
        };
        let err = authorize(&claim, &users).unwrap_err();
        assert_eq!(
            err, "authentication failed",
            "bad-password error must match unknown-user error",
        );
    }

    #[test]
    fn authorize_canonicalizes_username_case() {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), sha256_hex("secret"));
        let claim = AuthClaim {
            timestamp: 0,
            username: "ALICE".into(),
            password_sha256_hex: sha256_hex("secret"),
        };
        authorize(&claim, &users).expect("uppercase username should match canonical entry");
    }

    #[test]
    fn constant_time_eq_matches_equal_bytes() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abcdef", b"abc"));
    }

    /// Helper: write a file at a test path and (on Unix) chmod it 0600 so
    /// our secret-file-mode check doesn't reject it.
    fn write_secret_file(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(path).unwrap().permissions();
            perm.set_mode(0o600);
            std::fs::set_permissions(path, perm).unwrap();
        }
    }

    #[test]
    fn load_authorized_users_rejects_duplicate_user() {
        let dir = std::env::temp_dir().join(format!(
            "authz-dup-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("users.csv");
        let h = sha256_hex("secret");
        write_secret_file(&path, &format!("alice,{}\nalice,{}\n", h, h));
        let err = load_authorized_users(&path).unwrap_err();
        assert!(err.contains("duplicate"), "got: {}", err);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_authorized_users_rejects_bad_hash() {
        let dir = std::env::temp_dir().join(format!(
            "authz-badhash-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("users.csv");
        write_secret_file(&path, "alice,not-a-real-hash\n");
        let err = load_authorized_users(&path).unwrap_err();
        assert!(err.contains("hash"), "got: {}", err);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn load_authorized_users_rejects_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "authz-perm-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("users.csv");
        std::fs::write(&path, format!("alice,{}\n", sha256_hex("secret"))).unwrap();
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(&path, perm).unwrap();
        let err = load_authorized_users(&path).unwrap_err();
        assert!(err.contains("insecure permissions"), "got: {}", err);
        let _ = std::fs::remove_file(&path);
    }
}
