use std::io::{self, Read, Write};

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

/// Strip the Security Directory (Certificate Table) from a PE32+ (x64) image.
/// Works entirely in memory: input = any `Read + Seek`, output = any `Write`.
pub fn strip_security_from_reader<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    if buf.len() < 0x40 {
        return Err(invalid_data("File too small to be a valid PE"));
    }

    let dos_magic = read_u16(&buf, 0)?;
    if dos_magic != IMAGE_DOS_SIGNATURE {
        return Err(invalid_data("Missing MZ signature"));
    }

    let e_lfanew = read_u32(&buf, 0x3C)? as usize;
    if e_lfanew + 4 + 20 > buf.len() {
        return Err(invalid_data("Invalid e_lfanew"));
    }

    let nt_signature = read_u32(&buf, e_lfanew)?;
    if nt_signature != IMAGE_NT_SIGNATURE {
        return Err(invalid_data("Missing PE\\0\\0 signature"));
    }

    let coff_offset = e_lfanew + 4;
    let size_of_optional_header = read_u16(&buf, coff_offset + 16)? as usize;
    let optional_header_offset = coff_offset + 20;

    if optional_header_offset + size_of_optional_header > buf.len() {
        return Err(invalid_data("Corrupt Optional Header"));
    }

    const MAGIC_PE32_PLUS: u16 = 0x20B;
    let magic = read_u16(&buf, optional_header_offset)?;
    if magic != MAGIC_PE32_PLUS {
        return Err(invalid_data("Not a PE32+ (x64) binary"));
    }

    let number_of_rva_and_sizes = read_u32(&buf, optional_header_offset + 108)? as usize;
    if number_of_rva_and_sizes <= IMAGE_DIRECTORY_ENTRY_SECURITY {
        // Nothing to remove
        writer.write_all(&buf)?;
        return Ok(());
    }

    // DataDirectory array begins at offset 112 for PE32+
    let data_dir_base = optional_header_offset + 112;
    let security_entry = data_dir_base + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;

    if security_entry + 8 > buf.len() {
        return Err(invalid_data("Security Directory entry out of range"));
    }

    let cert_offset = read_u32(&buf, security_entry)? as usize;
    let cert_size = read_u32(&buf, security_entry + 4)? as usize;

    // Zero out header entry
    write_u32(&mut buf, security_entry, 0)?;
    write_u32(&mut buf, security_entry + 4, 0)?;

    // If certificate blob is at EOF, truncate
    if cert_offset > 0 && cert_size > 0 {
        if cert_offset + cert_size == buf.len() {
            buf.truncate(cert_offset);
        }
    }

    writer.write_all(&buf)?;
    Ok(())
}

fn invalid_data(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn read_u16(buf: &[u8], offset: usize) -> io::Result<u16> {
    if offset + 2 > buf.len() {
        return Err(invalid_data("Unexpected EOF while reading u16"));
    }
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> io::Result<u32> {
    if offset + 4 > buf.len() {
        return Err(invalid_data("Unexpected EOF while reading u32"));
    }
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) -> io::Result<()> {
    if offset + 4 > buf.len() {
        return Err(invalid_data("Unexpected EOF while writing u32"));
    }
    let bytes = value.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
    Ok(())
}
