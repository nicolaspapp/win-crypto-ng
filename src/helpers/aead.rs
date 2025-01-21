use std::ptr::null_mut;

use winapi::shared::ntdef::{PUCHAR, ULONG, ULONGLONG};
use winapi::shared::bcrypt::*;

use crate::buffer::Buffer;

#[derive(Debug, PartialOrd, PartialEq, Clone)]
pub struct AuthenticatedCipherModeInfo {
    pub nonce: Buffer,
    pub auth_data: Option<Buffer>,
    pub tag: Option<Buffer>,
    pub mac_context: Option<Buffer>,
    pub aad_size: ULONG,
    pub data_size: ULONGLONG,
    pub flags: ULONG,
}

impl AuthenticatedCipherModeInfo {
    pub fn new(
        nonce: Buffer,
        tag: Option<Buffer>,
        auth_data: Option<Buffer>,
        is_chained: bool,
    ) -> Self {
        let mut flags = 0;
        let mut mac_context: Option<Buffer> = None;
        if is_chained {
            flags |= BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
            mac_context = Some(Buffer::from_vec(vec![0u8; 16]));
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

    pub fn as_box(&mut self) -> Box<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO> {
        return Box::new(self.to_bcrypt_struct())
    }

    pub fn from_boxed(&self, bcrypt_info: Box<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>) -> Self {
        Self {
            nonce: Buffer::from(unsafe { std::slice::from_raw_parts(bcrypt_info.pbNonce as *const u8, bcrypt_info.cbNonce as usize) }),
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

    pub fn update_from_raw(&mut self, data: *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO) {
        let bcrypt_info = unsafe { Box::from_raw(data as *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO) };
        *self = self.from_boxed(bcrypt_info);
    }
    
}