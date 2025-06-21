use crate::crypto::aes::{AES128Cipher, AES256Cipher};
use crate::crypto::cipher_transform::CipherTransformFactory;
use crate::crypto::rc4::ARCFourCipher;
use crate::object::ObjectIdentifier;
/// PDF "cryptography" – This is why you don't write your own crypto.
use crate::object::dict::Dict;
use crate::object::dict::keys::*;
use crate::object::name::Name;
use crate::object::string::String as PdfString;
use std::collections::HashMap;
use std::fmt;

/// 7.6.1 Table 20 + 7.6.3.2 Table 21
#[derive(Debug, Clone)]
pub struct CryptDict {
    pub(crate) o: Vec<u8>,
    pub(crate) u: Vec<u8>,
    pub(crate) r: u32,
    pub(crate) p: i32,
    pub(crate) v: i32,
    pub(crate) bits: u32,
    pub(crate) crypt_filters: HashMap<String, CryptFilter>,
    pub(crate) default_crypt_filter: Option<String>,
    pub(crate) encrypt_metadata: bool,
    pub(crate) oe: Option<Vec<u8>>,
    pub(crate) ue: Option<Vec<u8>>,
}

impl CryptDict {
    /// Parse a CryptDict from a PDF dictionary
    pub fn from_dict(dict: &Dict) -> Option<CryptDict> {
        let o = dict.get::<PdfString>(O)?;
        let u = dict.get::<PdfString>(U)?;
        let r = dict.get::<u32>(R)?;
        let p = dict.get::<i32>(P)?;
        let v = dict.get::<i32>(V)?;
        let bits = dict.get::<u32>(LENGTH).unwrap_or(40);

        let crypt_filters = if let Some(cf_dict) = dict.get::<Dict>(CF) {
            let mut filters = HashMap::new();
            let keys: Vec<_> = cf_dict.keys().collect();
            for key in keys {
                if let Some(filter_dict) = cf_dict.get::<Dict>(key.clone()) {
                    if let Some(filter) = CryptFilter::from_dict(&filter_dict) {
                        filters.insert(key.as_str().to_string(), filter);
                    }
                }
            }
            filters
        } else {
            HashMap::new()
        };

        let default_crypt_filter = dict.get::<Name>(STM_F).map(|n| n.as_str().to_string());
        let encrypt_metadata = dict.get::<bool>(ENCRYPT_META_DATA).unwrap_or(true);
        let oe = dict.get::<PdfString>(OE).map(|s| s.get().to_vec());
        let ue = dict.get::<PdfString>(UE).map(|s| s.get().to_vec());

        Some(CryptDict {
            o: o.get().to_vec(),
            u: u.get().to_vec(),
            r,
            p,
            v,
            bits,
            crypt_filters,
            default_crypt_filter,
            encrypt_metadata,
            oe,
            ue,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CryptMethod {
    None,
    V2,    // RC4
    AESV2, // AES-128
    AESV3, // AES-256
}

impl<'a> CryptMethod {
    fn from_name(name: &Name<'a>) -> Option<Self> {
        match name.as_str() {
            "None" => Some(CryptMethod::None),
            "V2" => Some(CryptMethod::V2),
            "AESV2" => Some(CryptMethod::AESV2),
            "AESV3" => Some(CryptMethod::AESV3),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CryptFilter {
    pub(crate) method: CryptMethod,
}

impl CryptFilter {
    /// Parse a CryptFilter from a PDF dictionary
    fn from_dict(dict: &Dict) -> Option<Self> {
        let method = dict
            .get::<Name>(CFM)
            .and_then(|name| CryptMethod::from_name(&name))
            .unwrap_or(CryptMethod::None);

        Some(CryptFilter { method })
    }
}

#[derive(Debug)]
pub enum DecryptError {
    InvalidPassword,
    DecryptionFailure,
    UnsupportedVersion,
    MissingEntry { typ: &'static str, field: String },
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::InvalidPassword => write!(f, "Invalid password"),
            DecryptError::DecryptionFailure => write!(f, "Decryption failure"),
            DecryptError::UnsupportedVersion => write!(f, "Unsupported version"),
            DecryptError::MissingEntry { typ, field } => {
                write!(f, "Missing entry '{}' in {}", field, typ)
            }
        }
    }
}

impl std::error::Error for DecryptError {}

pub type Result<T> = std::result::Result<T, DecryptError>;

#[derive(Clone)]
pub struct Decoder {
    key_size: usize,
    key: Vec<u8>, // maximum length
    method: CryptMethod,
    /// A reference to the /Encrypt dictionary, if it is in an indirect
    /// object. The strings in this dictionary are not encrypted, so
    /// decryption must be skipped when accessing them.
    pub(crate) encrypt_indirect_object: Option<ObjectIdentifier>,
    /// A reference to the /Metadata dictionary, if it is an indirect
    /// object. If /EncryptMedata is set to false in the /Encrypt dictionary,
    /// then the strings in the /Metadata dictionary are not encrypted, so
    /// decryption must be skipped when accessing them.
    pub(crate) metadata_indirect_object: Option<ObjectIdentifier>,
    /// Whether the metadata is encrypted, as indicated by /EncryptMetadata
    /// in the /Encrypt dictionary.
    encrypt_metadata: bool,
}

impl Decoder {
    pub fn default(dict: &CryptDict, id: &[u8]) -> Result<Decoder> {
        Decoder::from_password(dict, id, b"")
    }

    fn key(&self) -> &[u8] {
        &self.key[..std::cmp::min(self.key_size, 16)]
    }

    pub fn new(
        key: Vec<u8>,
        key_size: usize,
        method: CryptMethod,
        encrypt_metadata: bool,
    ) -> Decoder {
        Decoder {
            key_size,
            key,
            method,
            encrypt_indirect_object: None,
            metadata_indirect_object: None,
            encrypt_metadata,
        }
    }

    pub fn from_password(dict: &CryptDict, id: &[u8], pass: &[u8]) -> Result<Decoder> {
        // Use the new CipherTransformFactory to create the decoder
        let password = if pass.is_empty() { None } else { Some(pass) };
        CipherTransformFactory::from_crypt_dict(dict, id, password)
    }

    pub fn decrypt<'buf>(&self, id: ObjectIdentifier, data: &'buf mut [u8]) -> Result<&'buf [u8]> {
        if self.encrypt_indirect_object == Some(id) {
            // Strings inside the /Encrypt dictionary are not encrypted
            return Ok(data);
        }

        if !self.encrypt_metadata && self.metadata_indirect_object == Some(id) {
            // Strings inside the /Metadata dictionary are not encrypted when /EncryptMetadata is
            // false
            return Ok(data);
        }

        if data.is_empty() {
            return Ok(data);
        }

        // Algorithm 1
        // a) we have those already

        match self.method {
            CryptMethod::None => {
                // No encryption - return data as-is
                Ok(data)
            }
            CryptMethod::V2 => {
                // RC4 decryption (Algorithm 1-2)
                // b) Build object key
                let mut key = [0; 16 + 5];
                let n = self.key().len();
                key[..n].copy_from_slice(self.key());
                key[n..n + 3].copy_from_slice(&id.obj_num.to_le_bytes()[..3]);
                key[n + 3..n + 5].copy_from_slice(&id.gen_num.to_le_bytes()[..2]);

                // c) Hash the key
                let key = *md5::compute(&key[..n + 5]);

                // d) Decrypt with RC4
                let mut cipher = ARCFourCipher::new(&key[..(n + 5).min(16)]);
                let decrypted = cipher.decrypt_block(data);
                data.copy_from_slice(&decrypted);
                Ok(data)
            }
            CryptMethod::AESV2 => {
                // AES-128 decryption (Algorithm 4)
                if data.len() < 16 {
                    return Err(DecryptError::DecryptionFailure);
                }

                // Extract IV (first 16 bytes)
                let mut iv = [0u8; 16];
                iv.copy_from_slice(&data[..16]);
                let encrypted_data = &data[16..];

                // Build object key for AES
                let mut key_data = [0; 16 + 5 + 4]; // +4 for "sAlT"
                let n = self.key().len();
                key_data[..n].copy_from_slice(self.key());
                key_data[n..n + 3].copy_from_slice(&id.obj_num.to_le_bytes()[..3]);
                key_data[n + 3..n + 5].copy_from_slice(&id.gen_num.to_le_bytes()[..2]);
                key_data[n + 5..n + 9].copy_from_slice(b"sAlT"); // AES salt

                // Hash the key
                let key_hash = *md5::compute(&key_data[..n + 9]);
                let mut aes_key = [0u8; 16];
                aes_key.copy_from_slice(&key_hash[..(n + 5).min(16)]);

                // Decrypt with AES-128 CBC
                let cipher = AES128Cipher::new(&aes_key);
                let decrypted = cipher.decrypt_cbc(encrypted_data, &iv);

                if decrypted.len() <= data.len() {
                    data[..decrypted.len()].copy_from_slice(&decrypted);
                    Ok(&data[..decrypted.len()])
                } else {
                    Err(DecryptError::DecryptionFailure)
                }
            }
            CryptMethod::AESV3 => {
                // AES-256 decryption (Algorithm 5/6)
                if data.len() < 16 {
                    return Err(DecryptError::DecryptionFailure);
                }

                // Extract IV (first 16 bytes)
                let mut iv = [0u8; 16];
                iv.copy_from_slice(&data[..16]);
                let encrypted_data = &data[16..];

                // For AES-256, use the file-level key directly (no per-object derivation)
                if self.key().len() < 32 {
                    return Err(DecryptError::DecryptionFailure);
                }

                let mut aes_key = [0u8; 32];
                aes_key.copy_from_slice(&self.key()[..32]);

                // Decrypt with AES-256 CBC
                let cipher = AES256Cipher::new(&aes_key);
                let decrypted = cipher.decrypt_cbc(encrypted_data, &iv);

                if decrypted.len() <= data.len() {
                    data[..decrypted.len()].copy_from_slice(&decrypted);
                    Ok(&data[..decrypted.len()])
                } else {
                    Err(DecryptError::DecryptionFailure)
                }
            }
        }
    }
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("key", &self.key())
            .field("method", &self.method)
            .finish()
    }
}
