//! Helpers for building a Windows `VS_VERSION_INFO` resource blob.
//!
//! Reference: <https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo>

use crate::pe_edit::CODE_PAGE_ID_EN_US;
use zerocopy::AsBytes;

/// English (United States), used by the version resource and `040904B0` string table.
///
/// `MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)`:
/// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-makelangid>
pub(crate) const VERSION_LANGUAGE_EN_US: u16 = 0x0409;

// ── VS_FIXEDFILEINFO ──────────────────────────────────────────────────────────

#[repr(C)]
#[derive(zerocopy::AsBytes)]
pub(crate) struct FixedFileInfo {
    pub dw_signature: u32,       // 0xFEEF04BD
    pub dw_struc_version: u32,   // 0x00010000
    pub dw_file_version_ms: u32, // major.minor
    pub dw_file_version_ls: u32, // patch.build
    pub dw_product_version_ms: u32,
    pub dw_product_version_ls: u32,
    pub dw_file_flags_mask: u32, // 0x0000003F
    pub dw_file_flags: u32,
    pub dw_file_os: u32,   // VOS_NT_WINDOWS32  = 0x00040004
    pub dw_file_type: u32, // VFT_APP           = 0x00000001
    pub dw_file_subtype: u32,
    pub dw_file_date_ms: u32,
    pub dw_file_date_ls: u32,
}

impl FixedFileInfo {
    pub fn new(major: u16, minor: u16, patch: u16, build: u16) -> Self {
        let ms = ((major as u32) << 16) | (minor as u32);
        let ls = ((patch as u32) << 16) | (build as u32);
        Self {
            dw_signature: 0xFEEF04BD,
            dw_struc_version: 0x00010000,
            dw_file_version_ms: ms,
            dw_file_version_ls: ls,
            dw_product_version_ms: ms,
            dw_product_version_ls: ls,
            dw_file_flags_mask: 0x0000003F,
            dw_file_flags: 0,
            dw_file_os: 0x00040004,
            dw_file_type: 0x00000001,
            dw_file_subtype: 0,
            dw_file_date_ms: 0,
            dw_file_date_ls: 0,
        }
    }
}

// ── Low-level encoding helpers ────────────────────────────────────────────────

/// Encode `s` as null-terminated UTF-16 LE bytes.
fn encode_utf16le_nul_terminated(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

/// Pad `buf` in-place to the next 4-byte boundary.
fn pad4(buf: &mut Vec<u8>) {
    let rem = buf.len() % 4;
    if rem != 0 {
        buf.resize(buf.len() + (4 - rem), 0);
    }
}

/// Write a `VERSION_INFO`-style node header: `[wLength(2), wValueLength(2), wType(2), szKey(utf16), Padding]`.
/// `wLength` is written as 0 and must be patched by the caller once the node is complete.
fn write_node_header(buf: &mut Vec<u8>, value_len: u16, node_type: u16, key: &str) {
    buf.extend_from_slice(&0u16.to_le_bytes()); // wLength  — filled by caller
    buf.extend_from_slice(&value_len.to_le_bytes()); // wValueLength
    buf.extend_from_slice(&node_type.to_le_bytes()); // wType
    buf.extend_from_slice(&encode_utf16le_nul_terminated(key)); // szKey
    pad4(buf); // Padding1
}

/// Patch `buf[0..2]` with the total byte length of `buf`.
fn seal_length(buf: &mut [u8]) {
    let len = buf.len() as u16;
    buf[0..2].copy_from_slice(&len.to_le_bytes());
}

// ── VS_VERSION_INFO children ──────────────────────────────────────────────────

/// Build a single `String` leaf node (wType = 1, text value).
///
/// `wValueLength` = number of UTF-16 code units in `value`, including the null terminator.
fn build_string_entry(key: &str, value: &str) -> Vec<u8> {
    let val_enc = encode_utf16le_nul_terminated(value);
    let val_char_len = (val_enc.len() / size_of::<u16>()) as u16;

    let mut entry = Vec::new();
    write_node_header(&mut entry, val_char_len, 1 /* text */, key);
    entry.extend_from_slice(&val_enc);
    seal_length(&mut entry);
    entry
}

/// Build a `StringTable` node (language/codepage `"040904B0"`) containing
/// `FileVersion` and `ProductVersion` string entries.
fn build_string_table(ver_str: &str) -> Vec<u8> {
    let mut fv = build_string_entry("FileVersion", ver_str);
    pad4(&mut fv); // sibling padding
    let pv = build_string_entry("ProductVersion", ver_str);

    let mut table = Vec::new();
    write_node_header(
        &mut table, 0,          /* no binary value */
        1,          /* text */
        "040904B0", // English (United States), UTF-16LE.
    );
    table.extend_from_slice(&fv);
    table.extend_from_slice(&pv);
    seal_length(&mut table);
    table
}

/// Build a `StringFileInfo` node wrapping a single `StringTable`.
fn build_string_file_info(ver_str: &str) -> Vec<u8> {
    let string_table = build_string_table(ver_str);

    let mut sfi = Vec::new();
    write_node_header(&mut sfi, 0, 1 /* text */, "StringFileInfo");
    sfi.extend_from_slice(&string_table);
    seal_length(&mut sfi);
    sfi
}

/// Build a `VarFileInfo` node that maps English-US to the UTF-16 code page.
fn build_var_file_info() -> Vec<u8> {
    let mut translation = Vec::new();
    write_node_header(
        &mut translation,
        size_of::<u32>() as u16,
        0, /* binary */
        "Translation",
    );
    let translation_value =
        (u32::from(CODE_PAGE_ID_EN_US) << 16) | u32::from(VERSION_LANGUAGE_EN_US);
    translation.extend_from_slice(&translation_value.to_le_bytes());
    seal_length(&mut translation);

    let mut var_file_info = Vec::new();
    write_node_header(&mut var_file_info, 0, 1 /* text */, "VarFileInfo");
    var_file_info.extend_from_slice(&translation);
    seal_length(&mut var_file_info);
    var_file_info
}

// ── Top-level builder ─────────────────────────────────────────────────────────

/// Build the complete `VS_VERSION_INFO` resource blob.
pub fn build_version_info(version: &[u16; 4], version_str: Option<&str>) -> Vec<u8> {
    let [major, minor, patch, build] = *version;

    let fixed = FixedFileInfo::new(major, minor, patch, build);
    let fixed_bytes = fixed.as_bytes();

    let derived;
    let ver_str = match version_str {
        Some(s) => s,
        None => {
            derived = format!("{}.{}.{}.{}", major, minor, patch, build);
            &derived
        }
    };

    let sfi = build_string_file_info(ver_str);
    let var_file_info = build_var_file_info();

    let mut info = Vec::new();
    write_node_header(
        &mut info,
        fixed_bytes.len() as u16, // wValueLength = sizeof(VS_FIXEDFILEINFO)
        0,                        // wType = binary
        "VS_VERSION_INFO",
    );
    info.extend_from_slice(fixed_bytes);
    pad4(&mut info); // Padding2 (after value, before children)
    info.extend_from_slice(&sfi);
    pad4(&mut info); // Align the next root child without extending StringFileInfo.
    info.extend_from_slice(&var_file_info);
    seal_length(&mut info);
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Node<'a> {
        bytes: &'a [u8],
        value_len: u16,
        node_type: u16,
        key: String,
        value_start: usize,
    }

    fn parse_node(bytes: &[u8]) -> Node<'_> {
        let length = u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as usize;
        assert!(length >= 6 && length <= bytes.len(), "invalid node length");

        let value_len = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        let node_type = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let mut key_end = 6;
        while bytes[key_end..key_end + 2] != [0, 0] {
            key_end += 2;
        }
        let key = String::from_utf16(
            &bytes[6..key_end]
                .chunks_exact(2)
                .map(|code_unit| u16::from_le_bytes(code_unit.try_into().unwrap()))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let value_start = (key_end + 2 + 3) & !3;

        Node {
            bytes: &bytes[..length],
            value_len,
            node_type,
            key,
            value_start,
        }
    }

    fn text_value(node: &Node<'_>) -> String {
        let value_end = node.value_start + usize::from(node.value_len) * 2;
        String::from_utf16(
            &node.bytes[node.value_start..value_end - 2]
                .chunks_exact(2)
                .map(|code_unit| u16::from_le_bytes(code_unit.try_into().unwrap()))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn builds_well_formed_version_info_with_derived_version() {
        let version = [1, 2, 3, 0];
        let info = build_version_info(&version, None);

        let root = parse_node(&info);
        assert_eq!(root.key, "VS_VERSION_INFO");
        assert_eq!(root.node_type, 0);
        assert_eq!(usize::from(root.value_len), size_of::<FixedFileInfo>());
        let fixed = &root.bytes[root.value_start..root.value_start + size_of::<FixedFileInfo>()];
        assert_eq!(
            u32::from_le_bytes(fixed[8..12].try_into().unwrap()),
            0x0001_0002
        );
        assert_eq!(
            u32::from_le_bytes(fixed[12..16].try_into().unwrap()),
            0x0003_0000
        );

        let string_file_info = parse_node(&root.bytes[(root.value_start + fixed.len() + 3) & !3..]);
        assert_eq!(string_file_info.key, "StringFileInfo");
        assert_eq!(string_file_info.node_type, 1);

        let string_table = parse_node(&string_file_info.bytes[string_file_info.value_start..]);
        assert_eq!(string_table.key, "040904B0");

        let file_version = parse_node(&string_table.bytes[string_table.value_start..]);
        assert_eq!(file_version.key, "FileVersion");
        assert_eq!(file_version.node_type, 1);
        assert_eq!(file_version.value_len, 8, "includes UTF-16 null terminator");
        assert_eq!(text_value(&file_version), "1.2.3.0");

        let product_offset = string_table.value_start + ((file_version.bytes.len() + 3) & !3);
        let product_version = parse_node(&string_table.bytes[product_offset..]);
        assert_eq!(product_version.key, "ProductVersion");
        assert_eq!(text_value(&product_version), "1.2.3.0");

        let var_offset = (root.value_start + fixed.len() + 3) & !3;
        let var_offset = var_offset + ((string_file_info.bytes.len() + 3) & !3);
        let var_file_info = parse_node(&root.bytes[var_offset..]);
        assert_eq!(var_file_info.key, "VarFileInfo");

        let translation = parse_node(&var_file_info.bytes[var_file_info.value_start..]);
        assert_eq!(translation.key, "Translation");
        assert_eq!(translation.node_type, 0);
        assert_eq!(translation.value_len, size_of::<u32>() as u16);
        assert_eq!(
            u32::from_le_bytes(
                translation.bytes[translation.value_start..translation.value_start + 4]
                    .try_into()
                    .unwrap()
            ),
            (u32::from(CODE_PAGE_ID_EN_US) << 16) | u32::from(VERSION_LANGUAGE_EN_US)
        );
    }

    #[test]
    fn preserves_a_custom_version_string() {
        let info = build_version_info(&[10, 20, 30, 40], Some("10.20.30-preview"));
        let root = parse_node(&info);
        let child_start = (root.value_start + usize::from(root.value_len) + 3) & !3;
        let string_file_info = parse_node(&root.bytes[child_start..]);
        let string_table = parse_node(&string_file_info.bytes[string_file_info.value_start..]);
        let file_version = parse_node(&string_table.bytes[string_table.value_start..]);

        assert_eq!(text_value(&file_version), "10.20.30-preview");
        assert_eq!(
            file_version.value_len,
            "10.20.30-preview".encode_utf16().count() as u16 + 1
        );
    }
}
