use std::ptr::null_mut;

use winapi::shared::ntdef::{PUCHAR, ULONG, ULONGLONG};
use winapi::shared::bcrypt::*;

#[derive(Debug, PartialOrd, PartialEq, Clone)]
pub struct AuthenticatedCipherModeInfo {
    pub nonce: Vec<u8>,
    pub auth_data: Option<Vec<u8>>,
    pub tag: Option<Vec<u8>>,
    pub mac_context: Option<Vec<u8>>,
    pub aad_size: ULONG,
    pub data_size: ULONGLONG,
    pub flags: ULONG,
}

impl AuthenticatedCipherModeInfo {
    pub fn new(
        nonce: Vec<u8>,
        tag: Option<Vec<u8>>,
        auth_data: Option<Vec<u8>>,
        is_chained: bool,
    ) -> Self {
        let mut flags = 0;
        let mut mac_context: Option<Vec<u8>> = None;
        if is_chained {
            flags |= BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
            mac_context = Some(vec![0u8; 16]);
        }
        
        Self {
            nonce: nonce,
            auth_data: auth_data,
            tag: tag,
            mac_context: mac_context,
            aad_size: 0,
            data_size: 0,
            flags: flags,
        }
    }


    pub fn to_bcrypt_struct(&mut self) -> BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: self.nonce.as_mut_ptr() as PUCHAR,
            cbNonce: self.nonce.len() as ULONG,
            pbAuthData: self.auth_data.as_mut().map_or(null_mut(), |v| v.as_mut_ptr() as PUCHAR),
            cbAuthData: self.auth_data.as_mut().map_or(0, |v| v.len() as ULONG),
            pbTag:  self.tag.as_mut().map_or(null_mut(), |v| v.as_mut_ptr() as PUCHAR),
            cbTag: self.tag.as_mut().map_or(0, |v| v.len() as ULONG),
            pbMacContext: self.mac_context.as_mut().map_or(null_mut(), |v| v.as_mut_ptr() as PUCHAR),
            cbMacContext: self.mac_context.as_mut().map_or(0, |v| v.len() as ULONG),
            cbAAD: self.aad_size,
            cbData: self.data_size,
            dwFlags: self.flags,
        }
    }    

    pub fn update_from_raw(&mut self, data: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO) {
        self.aad_size = data.cbAAD;
        self.data_size = data.cbData;
        self.flags = data.dwFlags;
    }
}