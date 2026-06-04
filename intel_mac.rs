/*
 * "Sui: embed and extract auxillary data from binaries"
 *
 * Copyright (c) 2024 Divy Srivastava
 * Copyright (c) 2024 the Deno authors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

// Intel macOS doesn't support named Mach-O sections appended after link via
// `getsectdata`, so we use a sentinel-based trailer format at the end of the
// file. Each appended section is encoded as a self-contained trailer; multiple
// trailers chain back-to-back at the end of the binary.
//
// Trailer layout (per section):
//
//   sentinel:  16 bytes  "<~sui-data~>" (12) + magic (4)
//   name_len:   1 byte   u8
//   name:    name_len bytes (UTF-8, not NUL-terminated)
//   data_len:   8 bytes  u64 little-endian
//   data:    data_len bytes
//
// Two magic values are recognized:
//   * `LEGACY_MAGIC` (0xEFBEADDE) — older format without a name field. Reader
//     treats the "name" implicitly as the empty string; this is what early
//     deno-compile binaries used.
//   * `MAGIC` (0xDEADC0DE) — current format with a name field.
//
// `find_section(name)` walks backwards from EOF: it scans for a sentinel, and
// if the trailer's name doesn't match, continues searching strictly before that
// sentinel's start. This is how multiple appended sections coexist.

fn parse_c_str(buf: &[u8]) -> Option<String> {
    for (i, &byte) in buf.iter().enumerate() {
        if byte == 0 {
            return String::from_utf8(buf[..i].to_vec()).ok();
        }
    }
    None
}

fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    let bytes: [u8; 8] = buf[offset..offset + 8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

fn write_u64_le(buf: &mut [u8], offset: usize, value: u64) {
    let bytes = value.to_le_bytes();
    buf[offset..offset + 8].copy_from_slice(&bytes);
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    let bytes: [u8; 4] = buf[offset..offset + 4].try_into().unwrap();
    u32::from_le_bytes(bytes)
}

fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

/// Patch a Mach-O load command
fn patch_command(cmd_type: u32, buf: &mut [u8], file_len: usize) {
    // LC_SEGMENT_64
    if cmd_type == 0x19 {
        if let Some(name) = parse_c_str(&buf[..16]) {
            if name == "__LINKEDIT" {
                let fileoff = read_u64_le(buf, 32);
                let vmsize_patched = file_len as u64 - fileoff;
                let filesize_patched = vmsize_patched;

                write_u64_le(buf, 24, vmsize_patched);
                write_u64_le(buf, 40, filesize_patched);
            }
        }
    }

    // LC_SYMTAB
    if cmd_type == 0x2 {
        let stroff = read_u32_le(buf, 8);
        let strsize_patched = file_len as u32 - stroff;

        write_u32_le(buf, 12, strsize_patched);
    }
}

const SENTINEL_PREFIX_LEN: usize = 12;
const MAGIC_LEN: usize = 4;
const SENTINEL_LEN: usize = SENTINEL_PREFIX_LEN + MAGIC_LEN;

/// New trailer format: sentinel includes a section-name prefix.
const MAGIC: [u8; 4] = [0xDE, 0xC0, 0xAD, 0xDE]; // 0xDEADC0DE, little-endian
/// Legacy trailer format (no name); old deno-compile binaries.
const LEGACY_MAGIC: [u8; 4] = [0xEF, 0xBE, 0xAD, 0xDE]; // 0xDEADBEEF, little-endian

fn sentinel_prefix() -> [u8; SENTINEL_PREFIX_LEN] {
    // Reverse the literal so the sentinel bytes don't appear contiguously in
    // the binary itself, only in appended trailers.
    let reversed = std::hint::black_box(b">~atad-ius~<");
    let mut out = [0u8; SENTINEL_PREFIX_LEN];
    for i in 0..SENTINEL_PREFIX_LEN {
        out[i] = reversed[SENTINEL_PREFIX_LEN - 1 - i];
    }
    out
}

fn build_sentinel(magic: [u8; 4]) -> [u8; SENTINEL_LEN] {
    let prefix = sentinel_prefix();
    let magic = std::hint::black_box(magic);
    let mut out = [0u8; SENTINEL_LEN];
    out[..SENTINEL_PREFIX_LEN].copy_from_slice(&prefix);
    out[SENTINEL_PREFIX_LEN..].copy_from_slice(&magic);
    out
}

/// Append a section trailer to `buf` in the current (named) format.
pub fn append_trailer(buf: &mut Vec<u8>, name: &str, data: &[u8]) {
    let sentinel = build_sentinel(MAGIC);
    buf.extend_from_slice(&sentinel);
    let name_bytes = name.as_bytes();
    assert!(
        name_bytes.len() <= u8::MAX as usize,
        "libsui section name too long ({} > 255 bytes)",
        name_bytes.len()
    );
    buf.push(name_bytes.len() as u8);
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(data);
}

/// Match the trailer at `file[s..]` against `name`.
///
/// Returns `Some(Ok(data_range))` if the trailer matches the requested name,
/// `Some(Err(()))` if the trailer is well-formed but the name doesn't match
/// (caller should continue scanning earlier in the file), or `None` if the
/// candidate sentinel position isn't a valid trailer header (probably a stray
/// match — treat as not-a-trailer).
fn match_trailer_at(
    file: &[u8],
    s: usize,
    name: &str,
) -> Option<Result<std::ops::Range<usize>, ()>> {
    let magic_off = s + SENTINEL_PREFIX_LEN;
    if magic_off + MAGIC_LEN > file.len() {
        return None;
    }
    let magic: [u8; 4] = file[magic_off..magic_off + MAGIC_LEN].try_into().ok()?;
    let (name_match, data_off, data_len) = if magic == MAGIC {
        let name_len_off = s + SENTINEL_LEN;
        if name_len_off + 1 > file.len() {
            return None;
        }
        let name_len = file[name_len_off] as usize;
        let name_off = name_len_off + 1;
        let data_len_off = name_off + name_len;
        if data_len_off + 8 > file.len() {
            return None;
        }
        let candidate = &file[name_off..name_off + name_len];
        let data_len = read_u64_le(file, data_len_off) as usize;
        let data_off = data_len_off + 8;
        (candidate == name.as_bytes(), data_off, data_len)
    } else if magic == LEGACY_MAGIC {
        // Legacy trailer: no name, treat as matching only an empty query.
        let data_len_off = s + SENTINEL_LEN;
        if data_len_off + 8 > file.len() {
            return None;
        }
        let data_len = read_u64_le(file, data_len_off) as usize;
        let data_off = data_len_off + 8;
        (name.is_empty(), data_off, data_len)
    } else {
        return None;
    };
    if data_off + data_len > file.len() {
        return None;
    }
    if name_match {
        Some(Ok(data_off..data_off + data_len))
    } else {
        Some(Err(()))
    }
}

/// Find section data in an Intel Mac Mach-O executable.
///
/// Searches backward from EOF for trailers matching `name`. Multiple trailers
/// may be chained; non-matching trailers are skipped over.
pub fn find_section(name: &str) -> std::io::Result<Option<&'static [u8]>> {
    use std::io::Read;

    let exe = std::env::current_exe()?;
    let mut file = std::fs::File::open(exe)?;
    // For simplicity, read the whole file. Existing deno binaries are
    // ~100MB at most; this is a one-shot at startup.
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    let prefix = sentinel_prefix();
    // Walk backward looking for sentinel prefixes. Each candidate is validated
    // by `match_trailer_at`.
    let mut end = buf.len();
    while end >= SENTINEL_LEN {
        let search_end = end.saturating_sub(SENTINEL_PREFIX_LEN - 1).max(1);
        let Some(rel) =
            buf[..search_end].windows(SENTINEL_PREFIX_LEN).rposition(|w| w == prefix)
        else {
            return Ok(None);
        };
        let s = rel;
        match match_trailer_at(&buf, s, name) {
            Some(Ok(range)) => {
                let data = buf[range].to_vec();
                return Ok(Some(Box::leak(data.into_boxed_slice())));
            }
            Some(Err(())) => {
                // Trailer was valid but name didn't match: continue searching
                // strictly before this sentinel.
                end = s;
            }
            None => {
                // Stray sentinel bytes (e.g., inside arbitrary data). Skip
                // past this candidate and keep walking backward.
                end = s;
            }
        }
    }

    Ok(None)
}

/// Patch a Mach-O executable file
///
/// This function modifies the Mach-O header to fix up segment and symbol table sizes.
/// It specifically patches:
/// - The __LINKEDIT segment's vmsize and filesize
/// - The symbol table's string size
///
/// # Arguments
///
/// * `file` - A mutable reference to the Mach-O executable bytes
///
/// # Returns
///
/// Returns `true` if patching was successful, `false` otherwise
pub fn patch_macho_executable(file: &mut [u8]) -> bool {
    const ALIGN: usize = 8;
    const HSIZE: usize = 32;

    if file.len() < HSIZE + 4 {
        return false;
    }

    let ncmds = read_u32_le(file, 16);
    let file_len = file.len();

    let mut offset = HSIZE;

    for _ in 0..ncmds {
        if offset + 8 > file.len() {
            return false;
        }

        let cmd_type = read_u32_le(file, offset);
        offset += 4;

        let size = read_u32_le(file, offset) as usize - 8;
        offset += 4;

        if offset + size > file.len() {
            return false;
        }

        // Split the file slice to allow mutable access to the command buffer
        // while keeping file_len available
        let (_, rest) = file.split_at_mut(offset);
        let cmd_buf = &mut rest[..size];
        patch_command(cmd_type, cmd_buf, file_len);

        offset += size;
        if offset & ALIGN != 0 {
            offset += ALIGN - (offset & ALIGN);
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_c_str() {
        let buf = b"__LINKEDIT\0extra";
        assert_eq!(parse_c_str(buf), Some("__LINKEDIT".to_string()));

        let buf = b"test";
        assert_eq!(parse_c_str(buf), None);

        let buf = b"\0";
        assert_eq!(parse_c_str(buf), Some("".to_string()));
    }

    #[test]
    fn test_read_write_u64_le() {
        let mut buf = vec![0u8; 16];
        write_u64_le(&mut buf, 0, 0x0123456789ABCDEF);
        assert_eq!(read_u64_le(&buf, 0), 0x0123456789ABCDEF);

        write_u64_le(&mut buf, 8, 0xFEDCBA9876543210);
        assert_eq!(read_u64_le(&buf, 8), 0xFEDCBA9876543210);
    }

    #[test]
    fn test_read_write_u32_le() {
        let mut buf = vec![0u8; 8];
        write_u32_le(&mut buf, 0, 0x01234567);
        assert_eq!(read_u32_le(&buf, 0), 0x01234567);

        write_u32_le(&mut buf, 4, 0xFEDCBA98);
        assert_eq!(read_u32_le(&buf, 4), 0xFEDCBA98);
    }

    #[test]
    fn test_patch_macho_executable_invalid() {
        let mut buf = vec![0u8; 10];
        assert_eq!(patch_macho_executable(&mut buf), false);
    }

    fn find_in(buf: &[u8], name: &str) -> Option<Vec<u8>> {
        let prefix = sentinel_prefix();
        let mut end = buf.len();
        while end >= SENTINEL_LEN {
            let search_end = end.saturating_sub(SENTINEL_PREFIX_LEN - 1).max(1);
            let Some(s) =
                buf[..search_end].windows(SENTINEL_PREFIX_LEN).rposition(|w| w == prefix)
            else {
                return None;
            };
            match match_trailer_at(buf, s, name) {
                Some(Ok(range)) => return Some(buf[range].to_vec()),
                Some(Err(())) | None => end = s,
            }
        }
        None
    }

    #[test]
    fn append_and_find_single() {
        let mut buf = b"some-binary-body".to_vec();
        append_trailer(&mut buf, "dnclbk", b"hello world");
        assert_eq!(find_in(&buf, "dnclbk").as_deref(), Some(&b"hello world"[..]));
        assert_eq!(find_in(&buf, "other"), None);
    }

    #[test]
    fn append_and_find_chained() {
        let mut buf = b"binary".to_vec();
        append_trailer(&mut buf, "dnclbk", &vec![0xAAu8; 4096]);
        append_trailer(&mut buf, "d3n0l4nd", &vec![0xBBu8; 1638]);
        assert_eq!(find_in(&buf, "d3n0l4nd").map(|v| v.len()), Some(1638));
        assert_eq!(find_in(&buf, "dnclbk").map(|v| v.len()), Some(4096));
        assert!(find_in(&buf, "d3n0l4nd").unwrap().iter().all(|&b| b == 0xBB));
        assert!(find_in(&buf, "dnclbk").unwrap().iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn legacy_trailer_matches_empty_name() {
        // Construct a legacy trailer manually: sentinel(LEGACY_MAGIC) + data_len + data.
        let mut buf = b"old-binary".to_vec();
        let sentinel = build_sentinel(LEGACY_MAGIC);
        buf.extend_from_slice(&sentinel);
        let data = b"legacy-data";
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        buf.extend_from_slice(data);
        assert_eq!(find_in(&buf, "").as_deref(), Some(&data[..]));
        assert_eq!(find_in(&buf, "dnclbk"), None);
    }
}
