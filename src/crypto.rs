//! AES helpers: ECB for key unwrapping, XTS for NCA headers, CTR for NCA sections.

use aes::cipher::{
    Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher,
};
use aes::{Aes128, Block};
use ctr::Ctr128BE;
use xts_mode::Xts128;

/// AES-128-ECB encrypt in place. `data` length must be a multiple of 16.
pub fn ecb_encrypt(key: &[u8; 16], data: &mut [u8]) {
    assert!(
        data.len().is_multiple_of(16),
        "ECB data must be a multiple of 16 bytes"
    );
    let cipher = Aes128::new(&Array::from(*key));
    for chunk in data.chunks_exact_mut(16) {
        cipher.encrypt_block(<&mut Block>::try_from(chunk).unwrap());
    }
}

/// AES-128-ECB decrypt in place. `data` length must be a multiple of 16.
pub fn ecb_decrypt(key: &[u8; 16], data: &mut [u8]) {
    assert!(
        data.len().is_multiple_of(16),
        "ECB data must be a multiple of 16 bytes"
    );
    let cipher = Aes128::new(&Array::from(*key));
    for chunk in data.chunks_exact_mut(16) {
        cipher.decrypt_block(<&mut Block>::try_from(chunk).unwrap());
    }
}

fn nintendo_tweak(sector: u128) -> Array<u8, aes::cipher::consts::U16> {
    Array::from(sector.to_be_bytes())
}

fn xts(key: &[u8; 32]) -> Xts128<Aes128> {
    let c1 = Aes128::new(&Array::from(<[u8; 16]>::try_from(&key[..16]).unwrap()));
    let c2 = Aes128::new(&Array::from(<[u8; 16]>::try_from(&key[16..]).unwrap()));
    Xts128::new(c1, c2)
}

/// AES-128-XTS encrypt with Nintendo tweaks (sector number big-endian), sectors from 0.
pub fn xts_encrypt(key: &[u8; 32], data: &mut [u8], sector_size: usize) {
    xts(key).encrypt_area(data, sector_size, 0, nintendo_tweak);
}

/// AES-128-XTS decrypt with Nintendo tweaks (sector number big-endian), sectors from 0.
pub fn xts_decrypt(key: &[u8; 32], data: &mut [u8], sector_size: usize) {
    xts(key).decrypt_area(data, sector_size, 0, nintendo_tweak);
}

/// Apply the AES-CTR keystream (encrypt and decrypt are identical) to `data`, which sits at
/// `absolute_offset` within the section. Counter = `ctr_high` ++ (offset / 16) big-endian.
pub fn ctr_apply(key: &[u8; 16], ctr_high: [u8; 8], absolute_offset: u64, data: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&ctr_high);
    iv[8..].copy_from_slice(&(absolute_offset / 16).to_be_bytes());
    let mut cipher = Ctr128BE::<Aes128>::new(&Array::from(*key), &Array::from(iv));
    let skip = (absolute_offset % 16) as usize;
    if skip > 0 {
        let mut dummy = [0u8; 16];
        cipher.apply_keystream(&mut dummy[..skip]);
    }
    cipher.apply_keystream(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecb_matches_fips197_vector() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let plain: [u8; 16] = core::array::from_fn(|i| (i * 0x11) as u8);
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let mut buf = plain;
        ecb_encrypt(&key, &mut buf);
        assert_eq!(buf, expected);
        ecb_decrypt(&key, &mut buf);
        assert_eq!(buf, plain);
    }

    #[test]
    fn xts_round_trip_and_sector_tweak_differs() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let plain = vec![0x5au8; 0x400];
        let mut buf = plain.clone();
        xts_encrypt(&key, &mut buf, 0x200);
        assert_ne!(buf, plain);
        // identical plaintext in each sector must encrypt differently
        assert_ne!(buf[..0x200], buf[0x200..]);
        xts_decrypt(&key, &mut buf, 0x200);
        assert_eq!(buf, plain);
    }

    #[test]
    fn ctr_offset_matches_contiguous_stream() {
        let key: [u8; 16] = core::array::from_fn(|i| (i * 3 + 5) as u8);
        let high = [1, 2, 3, 4, 5, 6, 7, 8];
        let data: Vec<u8> = (0..0x100u32).map(|i| i as u8).collect();
        let mut whole = data.clone();
        ctr_apply(&key, high, 0, &mut whole);
        assert_ne!(whole, data);
        for start in [0x20usize, 0x23, 0x2f, 0x31] {
            let mut part = data[start..start + 0x40].to_vec();
            ctr_apply(&key, high, start as u64, &mut part);
            assert_eq!(part, whole[start..start + 0x40], "start {start:#x}");
        }
    }
}
