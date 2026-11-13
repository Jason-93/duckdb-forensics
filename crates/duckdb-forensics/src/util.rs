use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

pub fn open_regular_file(path: &Path) -> io::Result<(File, Metadata)> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input is not a regular file",
        ));
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "opened input is not a regular file",
        ));
    }
    Ok((file, metadata))
}

pub fn path_text(path: &Path) -> (String, &'static str) {
    if let Some(text) = path.to_str() {
        return (text.to_owned(), "utf8");
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        (hex(path.as_os_str().as_bytes()), "unix_bytes_hex")
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut encoded = String::new();
        for unit in path.as_os_str().encode_wide() {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{unit:04x}");
        }
        (encoded, "windows_utf16_hex")
    }
}

pub fn decode_text(bytes: &[u8]) -> (String, bool, Option<String>) {
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_owned(), true, None),
        Err(_) => (String::new(), false, Some(hex(bytes))),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_utf8_bytes_are_empty_text_plus_raw_hex() {
        let (text, valid, raw) = decode_text(&[0xff, b'1', b'\n']);
        assert!(text.is_empty());
        assert!(!valid);
        assert_eq!(raw.as_deref(), Some("ff310a"));
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_input_path_has_reversible_encoding() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path =
            std::path::PathBuf::from(OsString::from_vec(vec![b'i', b'n', b'p', b'u', b't', 0xff]));
        let (encoded, encoding) = path_text(&path);
        assert_eq!(encoding, "unix_bytes_hex");
        assert_eq!(encoded, "696e707574ff");
        assert!(!encoded.contains('\u{fffd}'));
    }
}
