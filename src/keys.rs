//! Loader for `prod.keys` style files, with key derivation. Key values are never put in errors.

use crate::crypto::ecb_decrypt;
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct Keys {
    path: PathBuf,
    map: HashMap<String, Vec<u8>>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Keys({} keys from {})",
            self.map.len(),
            self.path.display()
        )
    }
}

impl Keys {
    pub fn load(path: &Path) -> Result<Keys> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read keys file {}", path.display()))?;
        let mut map = HashMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            let bytes = hex::decode(value.trim()).map_err(|_| {
                anyhow::anyhow!(
                    "{}:{}: value of key {name} is not valid hex",
                    path.display(),
                    n + 1
                )
            })?;
            map.insert(name, bytes);
        }
        Ok(Keys {
            path: path.to_path_buf(),
            map,
        })
    }

    fn get<const N: usize>(&self, name: &str) -> Option<[u8; N]> {
        self.map.get(name)?.as_slice().try_into().ok()
    }

    fn require<const N: usize>(&self, name: &str) -> Result<[u8; N]> {
        match self.map.get(name) {
            None => bail!("key {name} not found in {}", self.path.display()),
            Some(v) if v.len() != N => {
                bail!("key {name} in {} must be {N} bytes", self.path.display())
            }
            Some(v) => Ok(v.as_slice().try_into().unwrap()),
        }
    }

    pub fn header_key(&self) -> Result<[u8; 32]> {
        self.require("header_key")
    }

    pub fn xci_header_key(&self) -> Option<[u8; 16]> {
        self.get("xci_header_key")
    }

    /// `kaek_index`: 0 = application, 1 = ocean, 2 = system.
    pub fn key_area_key(&self, master_index: u8, kaek_index: u8) -> Result<[u8; 16]> {
        let kind = match kaek_index {
            0 => "application",
            1 => "ocean",
            2 => "system",
            n => bail!("invalid key area key index {n}"),
        };
        let name = format!("key_area_key_{kind}_{master_index:02x}");
        if let Some(k) = self.get(&name) {
            return Ok(k);
        }
        let derived = (|| {
            let master: [u8; 16] = self.get(&format!("master_key_{master_index:02x}"))?;
            let mut kek: [u8; 16] = self.get("aes_kek_generation_source")?;
            ecb_decrypt(&master, &mut kek);
            let mut src_kek: [u8; 16] = self.get(&format!("key_area_key_{kind}_source"))?;
            ecb_decrypt(&kek, &mut src_kek);
            let mut out: [u8; 16] = self.get("aes_key_generation_source")?;
            ecb_decrypt(&src_kek, &mut out);
            Some(out)
        })();
        derived.with_context(|| {
            format!(
                "key {name} not found in {} and cannot be derived (needs master_key_{master_index:02x} and the key generation sources)",
                self.path.display()
            )
        })
    }

    pub fn titlekek(&self, master_index: u8) -> Result<[u8; 16]> {
        let name = format!("titlekek_{master_index:02x}");
        if let Some(k) = self.get(&name) {
            return Ok(k);
        }
        let derived = (|| {
            let master: [u8; 16] = self.get(&format!("master_key_{master_index:02x}"))?;
            let mut out: [u8; 16] = self.get("titlekek_source")?;
            ecb_decrypt(&master, &mut out);
            Some(out)
        })();
        derived.with_context(|| {
            format!(
                "key {name} not found in {} and cannot be derived (needs master_key_{master_index:02x} and titlekek_source)",
                self.path.display()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecb_decrypt;
    use std::io::Write;

    fn hexs(b: &[u8]) -> String {
        hex::encode(b)
    }

    fn write_keys(text: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(text.as_bytes()).unwrap();
        f
    }

    #[test]
    fn keys_parses_lowercase_and_uppercase_names_and_ignores_comments() {
        let hk = hexs(&[0xab; 32]);
        let f = write_keys(&format!(
            "; comment\n# another\n\nHEADER_KEY = {hk}\nXCI_HEADER_KEY=   {}\r\nkey_area_key_ocean_03 = {}\n",
            hexs(&[1; 16]),
            hexs(&[2; 16]),
        ));
        let keys = Keys::load(f.path()).unwrap();
        assert_eq!(keys.header_key().unwrap(), [0xab; 32]);
        assert_eq!(keys.xci_header_key(), Some([1; 16]));
        assert_eq!(keys.key_area_key(3, 1).unwrap(), [2; 16]);
    }

    #[test]
    fn missing_key_error_names_key() {
        let f = write_keys("header_key = 00\n");
        let keys = Keys::load(f.path()).unwrap();
        let err = keys.key_area_key(10, 0).unwrap_err().to_string();
        assert!(err.contains("key_area_key_application_0a"), "{err}");
        assert!(keys.xci_header_key().is_none());
    }

    type Fixture = (
        tempfile::NamedTempFile,
        [u8; 16],
        [u8; 16],
        [u8; 16],
        [u8; 16],
        [u8; 16],
    );

    fn derive_fixture() -> Fixture {
        let master = [0x11u8; 16];
        let kek_gen_src = [0x22u8; 16];
        let kaek_app_src = [0x33u8; 16];
        let aes_key_gen_src = [0x44u8; 16];
        let titlekek_src = [0x55u8; 16];
        let f = write_keys(&format!(
            "master_key_02 = {}\naes_kek_generation_source = {}\nkey_area_key_application_source = {}\naes_key_generation_source = {}\ntitlekek_source = {}\n",
            hexs(&master),
            hexs(&kek_gen_src),
            hexs(&kaek_app_src),
            hexs(&aes_key_gen_src),
            hexs(&titlekek_src),
        ));
        (
            f,
            master,
            kek_gen_src,
            kaek_app_src,
            aes_key_gen_src,
            titlekek_src,
        )
    }

    #[test]
    fn derives_key_area_key_when_absent() {
        let (f, master, kek_gen_src, kaek_app_src, aes_key_gen_src, _) = derive_fixture();
        let mut kek = kek_gen_src;
        ecb_decrypt(&master, &mut kek);
        let mut src_kek = kaek_app_src;
        ecb_decrypt(&kek, &mut src_kek);
        let mut expected = aes_key_gen_src;
        ecb_decrypt(&src_kek, &mut expected);

        let keys = Keys::load(f.path()).unwrap();
        assert_eq!(keys.key_area_key(2, 0).unwrap(), expected);
    }

    #[test]
    fn derives_titlekek_when_absent() {
        let (f, master, _, _, _, titlekek_src) = derive_fixture();
        let mut expected = titlekek_src;
        ecb_decrypt(&master, &mut expected);
        let keys = Keys::load(f.path()).unwrap();
        assert_eq!(keys.titlekek(2).unwrap(), expected);
        let err = keys.titlekek(3).unwrap_err().to_string();
        assert!(err.contains("titlekek_03"), "{err}");
    }

    #[test]
    fn error_never_contains_key_value() {
        let secret = hexs(&[0xc7; 16]);
        // wrong length for a header key, and a non-hex value
        let f = write_keys(&format!(
            "header_key = {secret}\nmaster_key_00 = {secret}zz\n"
        ));
        let err = Keys::load(f.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(!msg.contains(&secret) && !msg.contains("c7c7"), "{msg}");
        let f = write_keys(&format!("header_key = {secret}\n"));
        let keys = Keys::load(f.path()).unwrap();
        let msg = format!("{:#}", keys.header_key().unwrap_err());
        assert!(msg.contains("header_key"), "{msg}");
        assert!(!msg.contains("c7c7"), "{msg}");
    }
}
