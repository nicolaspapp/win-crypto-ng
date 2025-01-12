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

    pub fn from_boxed(&self, bcrypt_info: Box<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>) -> Self {
        Self {
            nonce: if bcrypt_info.pbNonce.is_null() {
                None
            } else {
                Some(Buffer::from(unsafe { std::slice::from_raw_parts(bcrypt_info.pbNonce as *const u8, bcrypt_info.cbNonce as usize) }))
            },
            auth_data: if bcrypt_info.pbAuthData.is_null() {
                None
            } else {
                Some(Buffer::from(unsafe { std::slice::from_raw_parts(bcrypt_info.pbAuthData as *const u8, bcrypt_info.cbAuthData as usize) }))
            },
            tag: if bcrypt_info.pbTag.is_null() {
                None
            } else {
                Some(Buffer::from(unsafe { std::slice::from_raw_parts(bcrypt_info.pbTag as *const u8, bcrypt_info.cbTag as usize) }))
            },
            mac_context: if bcrypt_info.pbMacContext.is_null() {
                None
            } else {
                Some(Buffer::from(unsafe { std::slice::from_raw_parts(bcrypt_info.pbMacContext as *const u8, bcrypt_info.cbMacContext as usize) }))
            },
            aad_size: bcrypt_info.cbAAD,
            data_size: bcrypt_info.cbData,
            flags: bcrypt_info.dwFlags,
        }
    }

    pub fn update_from_raw(&mut self, data: *mut winapi::ctypes::c_void) {
        let bcrypt_info = unsafe { Box::from_raw(data as *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO) };
        *self = self.from_boxed(bcrypt_info);
    }
    
}