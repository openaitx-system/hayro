// AES ciphers imported in decrypt.rs where they're used
use crate::crypto::pdf_security::DEFAULT_PASSWORD_BYTES;
use crate::crypto::rc4::ARCFourCipher;

/// Factory for creating cipher transforms
pub struct CipherTransformFactory;

impl CipherTransformFactory {
    /// Create from CryptDict (convenience method)
    pub fn from_crypt_dict(
        dict: &crate::decrypt::CryptDict,
        file_id: &[u8],
        password: Option<&[u8]>,
    ) -> crate::decrypt::Result<crate::decrypt::Decoder> {
        let algorithm = dict.v;

        if !matches!(algorithm, 1 | 2 | 4 | 5) {
            return Err(crate::decrypt::DecryptError::UnsupportedVersion);
        }

        let key_length = dict.bits;

        if key_length < 40 || key_length % 8 != 0 {
            return Err(crate::decrypt::DecryptError::DecryptionFailure);
        }

        let owner_password = &dict.o[..32];
        let user_password = &dict.u[..32];
        let flags = dict.p;
        let revision = dict.r;
        let encrypt_metadata = dict.encrypt_metadata;

        let encryption_key = if algorithm != 5 {
            Self::prepare_key_data(
                file_id,
                password,
                owner_password,
                user_password,
                flags,
                revision,
                key_length,
                encrypt_metadata,
            )
            .or_else(|| {
                // Try owner password
                password.and_then(|pwd| {
                    let decoded_password =
                        Self::decode_user_password(pwd, owner_password, revision, key_length);
                    Self::prepare_key_data(
                        file_id,
                        Some(&decoded_password),
                        owner_password,
                        user_password,
                        flags,
                        revision,
                        key_length,
                        encrypt_metadata,
                    )
                })
            })
        } else {
            // Algorithm 5/6 - AES-256 with modern key derivation
            Self::prepare_key_data_algorithm_5_6(
                file_id,
                password,
                owner_password,
                user_password,
                flags,
                revision,
                key_length,
                encrypt_metadata,
                algorithm,
            )
        };

        let encryption_key = encryption_key.ok_or(crate::decrypt::DecryptError::InvalidPassword)?;

        let method = match algorithm {
            4 => crate::decrypt::CryptMethod::AESV2,     // AES-128
            5 | 6 => crate::decrypt::CryptMethod::AESV3, // AES-256
            _ => crate::decrypt::CryptMethod::V2,        // RC4
        };

        let key_size = (key_length / 8) as usize;
        Ok(crate::decrypt::Decoder::new(
            encryption_key,
            key_size,
            method,
            encrypt_metadata,
        ))
    }

    /// Prepare key data for algorithms 1-4
    fn prepare_key_data(
        file_id: &[u8],
        password: Option<&[u8]>,
        owner_password: &[u8],
        user_password: &[u8],
        flags: i32,
        revision: u32,
        key_length: u32,
        encrypt_metadata: bool,
    ) -> Option<Vec<u8>> {
        let hash_data_size = 40 + owner_password.len() + file_id.len();
        let mut hash_data = vec![0u8; hash_data_size];
        let mut i = 0;

        // Add password or default padding
        if let Some(pwd) = password {
            let n = std::cmp::min(32, pwd.len());
            hash_data[..n].copy_from_slice(&pwd[..n]);
            i = n;
        }

        let mut j = 0;
        while i < 32 {
            hash_data[i] = DEFAULT_PASSWORD_BYTES[j];
            i += 1;
            j += 1;
        }

        // Add owner password
        hash_data[i..i + owner_password.len()].copy_from_slice(owner_password);
        i += owner_password.len();

        // Add permissions
        hash_data[i] = (flags & 0xff) as u8;
        hash_data[i + 1] = ((flags >> 8) & 0xff) as u8;
        hash_data[i + 2] = ((flags >> 16) & 0xff) as u8;
        hash_data[i + 3] = ((flags >> 24) & 0xff) as u8;
        i += 4;

        // Add file ID
        hash_data[i..i + file_id.len()].copy_from_slice(file_id);
        i += file_id.len();

        // Add metadata flag for revision 4+
        if revision >= 4 && !encrypt_metadata {
            hash_data[i..i + 4].fill(0xff);
            i += 4;
        }

        // Calculate MD5 hash
        let mut hash = md5::compute(&hash_data[..i]).to_vec();
        let key_length_in_bytes = (key_length >> 3) as usize;

        // Additional hashing for revision 3+
        if revision >= 3 {
            for _ in 0..50 {
                hash = md5::compute(&hash[..std::cmp::min(key_length_in_bytes, 16)]).to_vec();
            }
        }

        let encryption_key = hash[..key_length_in_bytes].to_vec();

        // Check password
        let check_data = if revision >= 3 {
            let mut i = 0;
            let mut hash_data = vec![0u8; 32 + file_id.len()];
            hash_data[..32].copy_from_slice(&DEFAULT_PASSWORD_BYTES);
            i += 32;
            hash_data[i..i + file_id.len()].copy_from_slice(file_id);
            i += file_id.len();

            let mut cipher = ARCFourCipher::new(&encryption_key);
            let mut check_data = cipher.encrypt_block(&md5::compute(&hash_data[..i]).to_vec());

            let n = encryption_key.len();
            let mut derived_key = vec![0u8; n];
            for j in 1..=19 {
                for k in 0..n {
                    derived_key[k] = encryption_key[k] ^ j as u8;
                }
                let mut cipher = ARCFourCipher::new(&derived_key);
                check_data = cipher.encrypt_block(&check_data);
            }
            check_data
        } else {
            let mut cipher = ARCFourCipher::new(&encryption_key);
            cipher.encrypt_block(&DEFAULT_PASSWORD_BYTES.to_vec())
        };

        // Verify password
        if check_data
            .iter()
            .zip(user_password.iter())
            .all(|(a, b)| a == b)
        {
            Some(encryption_key)
        } else {
            None
        }
    }

    /// Decode user password for owner authentication
    fn decode_user_password(
        password: &[u8],
        owner_password: &[u8],
        revision: u32,
        key_length: u32,
    ) -> Vec<u8> {
        let mut hash_data = [0u8; 32];
        let n = std::cmp::min(32, password.len());

        hash_data[..n].copy_from_slice(&password[..n]);
        let mut i = n;

        let mut j = 0;
        while i < 32 {
            hash_data[i] = DEFAULT_PASSWORD_BYTES[j];
            i += 1;
            j += 1;
        }

        let mut hash = md5::compute(&hash_data).to_vec();
        let key_length_in_bytes = (key_length >> 3) as usize;

        if revision >= 3 {
            for _ in 0..50 {
                hash = md5::compute(&hash).to_vec();
            }
        }

        let mut user_password = owner_password.to_vec();

        if revision >= 3 {
            let mut derived_key = vec![0u8; key_length_in_bytes];
            for j in (0..=19).rev() {
                for k in 0..key_length_in_bytes {
                    derived_key[k] = hash[k] ^ j;
                }
                let mut cipher = ARCFourCipher::new(&derived_key);
                user_password = cipher.encrypt_block(&user_password);
            }
        } else {
            let mut cipher = ARCFourCipher::new(&hash[..key_length_in_bytes]);
            user_password = cipher.encrypt_block(&user_password);
        }

        user_password
    }

    /// Prepare key data for algorithms 5-6 (AES-256 with SHA-256)
    fn prepare_key_data_algorithm_5_6(
        file_id: &[u8],
        password: Option<&[u8]>,
        _owner_password: &[u8],
        _user_password: &[u8],
        flags: i32,
        _revision: u32,
        key_length: u32,
        encrypt_metadata: bool,
        _algorithm: i32,
    ) -> Option<Vec<u8>> {
        // For algorithms 5/6, use a simplified approach for now
        // This is a placeholder - full implementation would require SHA-256 derivation

        let password_bytes = if let Some(pwd) = password {
            pwd
        } else {
            &DEFAULT_PASSWORD_BYTES[..32]
        };

        // Use SHA-256 for key derivation (simplified)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password_bytes);
        hasher.update(file_id);
        hasher.update(&flags.to_le_bytes());

        if !encrypt_metadata {
            hasher.update(&[0xff, 0xff, 0xff, 0xff]);
        }

        let hash = hasher.finalize();
        let key_length_bytes = (key_length / 8) as usize;

        // Return key of appropriate length
        Some(hash[..key_length_bytes.min(32)].to_vec())
    }
}
