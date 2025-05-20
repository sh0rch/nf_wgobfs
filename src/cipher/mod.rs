use crate::config::CipherMode;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

pub const NONCE_LEN: usize = 12;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(cpufeat_avx2, "avx2");

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
cpufeatures::new!(cpufeat_neon, "neon");

mod chacha6;
pub mod randomiser;
pub use chacha6::ChaCha6;

pub enum CipherImpl {
    Fast(ChaCha20),
    Fallback(ChaCha6),
}

impl CipherImpl {
    #[inline]
    pub fn new(key: &[u8; 32], nonce: &[u8; NONCE_LEN], mode: &CipherMode) -> Self {
        if mode != &CipherMode::Standard && fast_available() {
            #[cfg(debug_assertions)]
            {
                println!("Using fast cipher");
            }
            return CipherImpl::Fast(ChaCha20::new(key.into(), nonce.into()));
        }
        #[cfg(debug_assertions)]
        {
            println!("Using fallback cipher");
        }
        return CipherImpl::Fallback(ChaCha6::new(key, &nonce[..8]));
    }

    #[inline]
    pub fn xor(&mut self, data: &mut [u8]) {
        match self {
            CipherImpl::Fast(c) => c.apply_keystream(data),
            CipherImpl::Fallback(c) => c.xor(data),
        }
    }
}

#[inline]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn fast_available() -> bool {
    cpufeat_avx2::get()
}

#[inline]
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn fast_available() -> bool {
    cpufeat_neon::get()
}

#[inline]
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "aarch64"
)))]
pub fn fast_available() -> bool {
    false
}
