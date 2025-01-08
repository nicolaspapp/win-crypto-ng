use std::ptr::null_mut;

use winapi::shared::ntdef::{PUCHAR, ULONG, ULONGLONG};
use winapi::shared::bcrypt::*;

use crate::buffer::Buffer;

#[derive(Debug, PartialOrd, PartialEq, Clone)]
pub struct AuthenticatedCipherModeInfo {
    pub nonce: Option<Buffer>,
    pub auth_data: Option<Buffer>,
    pub tag: Option<Buffer>,
    pub mac_context: Option<Buffer>,
    pub aad_size: ULONG,
    pub data_size: ULONGLONG,
    pub flags: ULONG,
}

impl AuthenticatedCipherModeInfo {
    pub fn to_bcrypt_struct(&self) -> BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: self.nonce.as_ref().map_or(null_mut(), |v| v.as_ptr() as PUCHAR),
            cbNonce: self.nonce.as_ref().map_or(0, |v| v.len() as ULONG),
            pbAuthData: self.auth_data.as_ref().map_or(null_mut(), |v| v.as_ptr() as PUCHAR),
            cbAuthData: self.auth_data.as_ref().map_or(0, |v| v.len() as ULONG),
            pbTag:  self.tag.as_ref().map_or(null_mut(), |v| v.as_ptr() as PUCHAR),
            cbTag: self.tag.as_ref().map_or(0, |v| v.len() as ULONG),
            pbMacContext: self.mac_context.as_ref().map_or(null_mut(), |v| v.as_ptr() as PUCHAR),
            cbMacContext: self.mac_context.as_ref().map_or(0, |v| v.len() as ULONG),
            cbAAD: self.aad_size,
            cbData: self.data_size,
            dwFlags: self.flags,
        }
    }

    pub fn as_box(&self) -> Box<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO> {
        return Box::new(self.to_bcrypt_struct())
    }
}