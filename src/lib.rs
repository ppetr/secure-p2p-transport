use iroh::key::{SecretKey, PublicKey};
use std::path::Path;
use std::str::FromStr;
use std::io;

/// Saves the secret key to disk.
pub fn save_key_to_disk(path: impl AsRef<Path>, key: &SecretKey) -> io::Result<()> {
    let bytes = key.to_bytes();
    std::fs::write(path, bytes)
}

/// Loads the secret key from disk.
pub fn load_key_from_disk(path: impl AsRef<Path>) -> io::Result<SecretKey> {
    let bytes = std::fs::read(path)?;
    if bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "key file must be exactly 32 bytes",
        ));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(SecretKey::from_bytes(&array))
}

/// Converts a string representation of a public key back to PublicKey.
pub fn public_key_from_str(s: &str) -> anyhow::Result<PublicKey> {
    PublicKey::from_str(s).map_err(|e| anyhow::anyhow!(e))
}

/// Converts a PublicKey to its string representation.
pub fn public_key_to_string(key: &PublicKey) -> String {
    key.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_conversion() {
        let secret = SecretKey::generate();
        let public = secret.public();
        let public_str = public_key_to_string(&public);
        let parsed_public = public_key_from_str(&public_str).expect("Failed to parse public key");
        assert_eq!(public, parsed_public);
    }

    #[test]
    fn test_key_persistence() {
        let secret = SecretKey::generate();
        let public = secret.public();
        let file_path = Path::new("test_key.bin");

        save_key_to_disk(&file_path, &secret).expect("Failed to save key");
        let loaded_secret = load_key_from_disk(&file_path).expect("Failed to load key");
        let loaded_public = loaded_secret.public();

        assert_eq!(public, loaded_public);

        // Cleanup
        std::fs::remove_file(file_path).expect("Failed to remove temp key file");
    }
}
