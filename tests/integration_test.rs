use libsui::{utils, Elf, Macho, PortableExecutable};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const RESOURCE_NAME: &str = "sui_test_data";

static PROCESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

macro_rules! with_dollar_sign {
    ($($body:tt)*) => {
        macro_rules! __with_dollar_sign { $($body)* }
        __with_dollar_sign!($);
    }
}

macro_rules! parameterized_test {
    ($name:ident, $args:pat, $body:tt) => {
        with_dollar_sign! {
        ($d:tt) => {
            macro_rules! $name {
                ($d($d pname:ident: $d values:expr,)*) => {
                    mod $name {
                        use super::*;
                        $d(
                            #[test]
                            fn $d pname() {
                                let $args = $d values;
                                $body
                            }
                        )*
                    }}}}}
    };
}

parameterized_test! { test_macho, size, {
test_macho(size, false) } }

parameterized_test! { test_macho_sign, size, {
test_macho(size, true) } }

parameterized_test! { test_elf, size, {
test_elf(size) } }

parameterized_test! { test_pe, size, {
test_pe(size) } }

#[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
fn build_macho() {
    assert_eq!(
        std::process::Command::new("rustc")
            .args(&["exec.rs", "-o", "exec_mach64"])
            .current_dir("./tests")
            .status()
            .unwrap()
            .code(),
        Some(0),
    );
}

fn test_macho(size: usize, sign: bool) {
    let _lock = PROCESS_LOCK.lock().unwrap();

    #[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
    build_macho();

    let input = std::fs::read("tests/exec_mach64").unwrap();
    let macho = Macho::from(input).unwrap();
    let path = std::env::temp_dir().join("exec_mach64_out");
    // Remove the file if it exists
    #[cfg(target_vendor = "apple")]
    {
        let _ = std::fs::remove_file(&path);
    }

    let data = vec![0; size];
    #[cfg(not(target_vendor = "apple"))]
    let mut out = std::io::sink();
    #[cfg(target_vendor = "apple")]
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(&path)
        .unwrap();
    let m = macho.write_section(RESOURCE_NAME, data).unwrap();
    if sign {
        m.build_and_sign(&mut out).unwrap();
    } else {
        m.build(&mut out).unwrap();
    }

    #[cfg(target_vendor = "apple")]
    if sign || cfg!(target_arch = "x86_64") {
        drop(out);
        // Run the output
        let output = std::process::Command::new(&path).output().unwrap();
        eprintln!("status: {}", output.status);
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success());
        if sign && cfg!(target_arch = "aarch64") {
            // Verify the signature
            let output = std::process::Command::new("codesign")
                .arg("--verify")
                .arg("--deep")
                .arg("--strict")
                .arg("--verbose=2")
                .arg(&path)
                .output()
                .unwrap();
            assert!(output.status.success());
        }
    }
}

test_macho! {
    test_macho_1: 1,
    test_macho_10: 10,
    test_macho_64: 64,
    test_macho_512: 512,
    test_macho_1024: 1024,
    test_macho_1024_1024: 1024 * 1024,
    test_macho_1024_1024_5 : 1024 * 1024 * 5,
}

test_macho_sign! {
    test_macho_1: 1,
    test_macho_10: 10,
    test_macho_64: 64,
    test_macho_512: 512,
    test_macho_1024: 1024,
    test_macho_1024_1024: 1024 * 1024,
    test_macho_1024_1024_5 : 1024 * 1024 * 5,
}

fn test_elf(size: usize) {
    let _lock = PROCESS_LOCK.lock().unwrap();

    let input = std::fs::read("tests/exec_elf64").unwrap();
    let elf = Elf::new(&input);
    let _path = std::env::temp_dir().join("exec_elf64_out");

    let data = vec![0; size];
    #[cfg(not(all(unix, not(target_vendor = "apple"))))]
    let mut out = std::io::sink();
    #[cfg(all(unix, not(target_vendor = "apple")))]
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(&_path)
        .unwrap();

    elf.append(RESOURCE_NAME, &data, &mut out).unwrap();

    #[cfg(all(unix, not(target_vendor = "apple"), target_arch = "x86_64"))]
    {
        drop(out);
        // Run the output
        let output = std::process::Command::new(&_path).output().unwrap();
        assert!(output.status.success());
    }
}

test_elf! {
    test_elf_1: 1,
    test_elf_10: 10,
    test_elf_64: 64,
    test_elf_512: 512,
    test_elf_1024: 1024,
    test_elf_1024_1024: 1024 * 1024,
    test_elf_1024_1024_5 : 1024 * 1024 * 5,
}

#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn test_elf_note_survives_strip() {
    let _lock = PROCESS_LOCK.lock().unwrap();

    let input = std::fs::read("tests/exec_elf64").unwrap();
    let elf = Elf::new(&input);
    let path = std::env::temp_dir().join("exec_elf64_strip_out");

    let payload = b"hello-strip-note".to_vec();
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(&path)
        .unwrap();
    elf.append(RESOURCE_NAME, &payload, &mut out).unwrap();
    drop(out);

    let bytes = std::fs::read(&path).unwrap();
    let section = find_section_in_bytes(&bytes, RESOURCE_NAME).unwrap();
    assert_eq!(section, payload.as_slice());

    let output = std::process::Command::new("strip").arg(&path).output();
    match output {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_lower = stderr.to_ascii_lowercase();
            if stderr_lower.contains("unable to recognise the format")
                || stderr_lower.contains("file format not recognized")
            {
                return;
            }
            panic!("strip failed");
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
        Err(err) => panic!("failed to run strip: {}", err),
    }

    let stripped = std::fs::read(&path).unwrap();
    let section = find_section_in_bytes(&stripped, RESOURCE_NAME).unwrap();
    assert_eq!(section, payload.as_slice());
}

// Regression for a segfault of appended binaries after `eu-strip`
// (as run by e.g. flatpak-builder): elfutils lays the stripped output out
// itself and zero-fills every file gap between two allocated sections. The
// relocated program header table sits in the gap before the note, so unless an
// allocated section covers it (`.sui.phdrs`) eu-strip clobbers it into all-zero
// program headers and the binary segfaults on exec.
#[cfg(all(unix, not(target_vendor = "apple"), target_arch = "x86_64"))]
#[test]
fn test_elf_note_survives_eu_strip() {
    let _lock = PROCESS_LOCK.lock().unwrap();

    let input = std::fs::read("tests/exec_elf64").unwrap();
    let elf = Elf::new(&input);
    let path = std::env::temp_dir().join("exec_elf64_eu_strip_out");

    let payload = b"hello-eu-strip-note".to_vec();
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(&path)
        .unwrap();
    elf.append(RESOURCE_NAME, &payload, &mut out).unwrap();
    drop(out);

    let output = std::process::Command::new("eu-strip").arg(&path).output();
    match output {
        Ok(output) if output.status.success() => {}
        // eu-strip not installed / refused the file: nothing to assert.
        Ok(_) => return,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
        Err(err) => panic!("failed to run eu-strip: {}", err),
    }

    // The note still round-trips out of the stripped binary...
    let stripped = std::fs::read(&path).unwrap();
    let section = find_section_in_bytes(&stripped, RESOURCE_NAME).unwrap();
    assert_eq!(section, payload.as_slice());

    // ...the program header table was not zero-filled...
    let r64 = |b: &[u8]| u64::from_le_bytes(b[..8].try_into().unwrap());
    let r16 = |b: &[u8]| u16::from_le_bytes(b[..2].try_into().unwrap());
    let e_phoff = r64(&stripped[0x20..0x28]) as usize;
    let e_phentsize = r16(&stripped[0x36..0x38]) as usize;
    let e_phnum = r16(&stripped[0x38..0x3a]) as usize;
    assert!(e_phnum > 0, "no program headers");
    let all_zero = (0..e_phnum).all(|i| {
        let p = &stripped[e_phoff + i * e_phentsize..e_phoff + (i + 1) * e_phentsize];
        p.iter().all(|&b| b == 0)
    });
    assert!(!all_zero, "eu-strip zero-filled the program header table");

    // ...and the stripped binary still runs.
    let status = std::process::Command::new(&path).status().unwrap();
    assert!(
        status.success(),
        "stripped binary failed to run: {}",
        status
    );
}

#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn test_elf_note_mapped_and_preserves() {
    let _lock = PROCESS_LOCK.lock().unwrap();

    let input = std::fs::read("tests/exec_elf64").unwrap();
    let elf = Elf::new(&input);

    let payload = b"hello-section".to_vec();
    let mut out = Vec::new();
    elf.append(RESOURCE_NAME, &payload, &mut out).unwrap();

    use object::endian::Endianness;
    use object::read::elf::{ElfFile64, FileHeader, ProgramHeader};

    let elf_file = ElfFile64::<Endianness, _>::parse(&out[..]).unwrap();
    let endian = elf_file.endian();
    let header = elf_file.elf_header();
    let segments = header.program_headers(endian, &out[..]).unwrap();

    // The SUI note is carried by its own PT_NOTE program header (not a
    // section), whose mapped range must fall entirely within a PT_LOAD so the
    // runtime `dl_iterate_phdr` scan can read it.
    let mut sui_note_segment = None;
    let mut has_gnu = false;
    for segment in segments {
        let Ok(Some(mut notes)) = segment.notes(endian, &out[..]) else {
            continue;
        };
        while let Ok(Some(note)) = notes.next() {
            let name = trim_note_name(note.name());
            if name == b"GNU" {
                has_gnu = true;
            } else if name == b"SUI" {
                sui_note_segment = Some((
                    segment.p_offset(endian).into(),
                    segment.p_filesz(endian).into(),
                    segment.p_vaddr(endian).into(),
                    segment.p_memsz(endian).into(),
                ));
            }
        }
    }

    let (note_off, note_filesz, note_vaddr, note_memsz): (u64, u64, u64, u64) =
        sui_note_segment.expect("PT_NOTE carrying the SUI note missing");
    assert!(note_filesz > 0, "SUI note is empty");

    let segments = header.program_headers(endian, &out[..]).unwrap();
    let mut load_covers = false;
    for segment in segments {
        if segment.p_type(endian) != object::elf::PT_LOAD {
            continue;
        }
        let p_offset: u64 = segment.p_offset(endian).into();
        let p_filesz: u64 = segment.p_filesz(endian).into();
        let p_vaddr: u64 = segment.p_vaddr(endian).into();
        let p_memsz: u64 = segment.p_memsz(endian).into();
        if note_off >= p_offset
            && note_off + note_filesz <= p_offset + p_filesz
            && note_vaddr >= p_vaddr
            && note_vaddr + note_memsz <= p_vaddr + p_memsz
        {
            load_covers = true;
        }
    }

    assert!(load_covers, "SUI note is not mapped by a PT_LOAD segment");
    assert!(has_gnu, "expected GNU note to be preserved");
}

/// Return a copy of `input` whose largest non-TLS `.bss` (`SHT_NOBITS`) and
/// its carrier `PT_LOAD` are grown by `extra` bytes of *memory* (no file
/// bytes). This widens the gap between the carrier segment's file image
/// (`p_filesz`) and memory image (`p_memsz`), the condition under which the
/// note-placement math matters.
#[cfg(all(unix, not(target_vendor = "apple")))]
fn inflate_bss(input: &[u8], extra: u64) -> Vec<u8> {
    use object::build::elf as e;

    let mut builder = e::Builder::read(input).expect("parse fixture ELF");

    let bss_id = builder
        .sections
        .iter()
        .filter(|s| {
            s.sh_type == object::elf::SHT_NOBITS
                && s.sh_flags & object::elf::SHF_ALLOC as u64 != 0
                && s.sh_flags & object::elf::SHF_TLS as u64 == 0
        })
        .max_by_key(|s| s.sh_addr)
        .map(|s| s.id())
        .expect("fixture has a .bss");
    {
        // `.bss` size is carried by `SectionData::UninitializedData`, which
        // `set_section_sizes` recomputes `sh_size` from — bump the data, not
        // just `sh_size`, or the change is undone on write.
        let bss = builder.sections.get_mut(bss_id);
        let new_size = bss.sh_size + extra;
        bss.sh_size = new_size;
        bss.data = e::SectionData::UninitializedData(new_size);
    }

    let seg_id = builder
        .segments
        .iter()
        .filter(|s| s.is_load())
        .max_by_key(|s| s.p_offset + s.p_filesz)
        .map(|s| s.id())
        .expect("fixture has a load segment");
    builder.segments.get_mut(seg_id).p_memsz += extra;

    let mut out = Vec::new();
    builder.write(&mut out).expect("write inflated fixture");
    out
}

/// Regression test for the `.bss`/`.note.sui` overlap bug.
///
/// `append` placed `.note.sui` at a virtual address derived from its file
/// offset, ignoring that a trailing `.bss` (`SHT_NOBITS`) makes the carrier
/// segment's memory image larger than its file image. With a large enough
/// `.bss` the note's mapped range landed *inside* `.bss`, so the program's
/// zero-initialized globals aliased the embedded data — corrupting it (and
/// `.bss`) at startup. The note's memory range must not overlap any allocated
/// section.
#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn test_elf_note_does_not_overlap_bss() {
    use object::endian::Endianness;
    use object::read::elf::{ElfFile64, FileHeader, ProgramHeader, SectionHeader};

    let _lock = PROCESS_LOCK.lock().unwrap();

    let fixture = std::fs::read("tests/exec_elf64").unwrap();
    // 256 KiB of extra .bss — well past a page, so the buggy placement would
    // overlap.
    let input = inflate_bss(&fixture, 0x40000);

    let payload = b"no-bss-overlap".to_vec();
    let mut out = Vec::new();
    Elf::new(&input)
        .append(RESOURCE_NAME, &payload, &mut out)
        .unwrap();

    let elf_file = ElfFile64::<Endianness, _>::parse(&out[..]).unwrap();
    let endian = elf_file.endian();

    // The note lives in its own PT_NOTE program header; its mapped memory range
    // must clear every allocated section (notably the inflated .bss).
    let header = elf_file.elf_header();
    let segments = header.program_headers(endian, &out[..]).unwrap();
    let mut note_range = None;
    for segment in segments {
        let Ok(Some(mut notes)) = segment.notes(endian, &out[..]) else {
            continue;
        };
        while let Ok(Some(note)) = notes.next() {
            if trim_note_name(note.name()) == b"SUI" {
                let addr: u64 = segment.p_vaddr(endian).into();
                let size: u64 = segment.p_memsz(endian).into();
                note_range = Some((addr, addr + size));
            }
        }
    }
    let (note_addr, note_end) = note_range.expect("PT_NOTE carrying the SUI note missing");
    assert!(note_end > note_addr, "SUI note is empty");

    let section_table = elf_file.elf_section_table();

    for section in section_table.iter() {
        if section.sh_flags(endian) & object::elf::SHF_ALLOC as u64 == 0 {
            continue;
        }
        let name = section_table.section_name(endian, section).unwrap_or(b"");
        if name == b".note.sui" {
            continue;
        }
        let addr = section.sh_addr(endian);
        let size = section.sh_size(endian);
        if size == 0 {
            continue;
        }
        assert!(
            note_addr >= addr + size || addr >= note_end,
            "note [{note_addr:#x}, {note_end:#x}) overlaps section {} [{addr:#x}, {:#x})",
            String::from_utf8_lossy(name),
            addr + size,
        );
    }

    // The embedded payload is still recoverable through the public reader.
    assert_eq!(
        find_section_in_bytes(&out, RESOURCE_NAME).unwrap(),
        payload.as_slice()
    );
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn find_section_in_bytes<'a>(data: &'a [u8], name: &str) -> Option<&'a [u8]> {
    use object::endian::Endianness;
    use object::read::elf::{ElfFile64, FileHeader, ProgramHeader, SectionHeader};

    let elf_file = ElfFile64::<Endianness, _>::parse(data).ok()?;
    let endian = elf_file.endian();

    // `append` adds the note via a PT_NOTE program header, not a section, so
    // it is discoverable even after the section table is stripped — scan the
    // section table first (if any), then fall back to program headers, mirroring
    // the runtime `find_section` which uses `dl_iterate_phdr`.
    let section_table = elf_file.elf_section_table();
    if !section_table.is_empty() {
        for section in section_table.iter() {
            let Ok(Some(mut notes)) = section.notes(endian, data) else {
                continue;
            };
            while let Ok(Some(note)) = notes.next() {
                if trim_note_name(note.name()) != b"SUI" {
                    continue;
                }
                if note.n_type(endian) != 0x5355_4901 {
                    continue;
                }
                if let Some(section_data) = parse_elf_note_desc(note.desc(), name) {
                    return Some(section_data);
                }
            }
        }
    }

    let header = elf_file.elf_header();
    let segments = header.program_headers(endian, data).ok()?;
    for segment in segments {
        let Ok(Some(mut notes)) = segment.notes(endian, data) else {
            continue;
        };
        while let Ok(Some(note)) = notes.next() {
            if trim_note_name(note.name()) != b"SUI" {
                continue;
            }
            if note.n_type(endian) != 0x5355_4901 {
                continue;
            }
            if let Some(section_data) = parse_elf_note_desc(note.desc(), name) {
                return Some(section_data);
            }
        }
    }
    None
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn parse_elf_note_desc<'a>(desc: &'a [u8], name: &str) -> Option<&'a [u8]> {
    if desc.len() < 2 {
        return None;
    }
    let name_len = u16::from_le_bytes(desc[0..2].try_into().ok()?) as usize;
    if desc.len() < 2 + name_len {
        return None;
    }
    if desc.get(2..2 + name_len)? != name.as_bytes() {
        return None;
    }
    Some(&desc[2 + name_len..])
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn trim_note_name(name: &[u8]) -> &[u8] {
    let mut end = name.len();
    while end > 0 && name[end - 1] == 0 {
        end -= 1;
    }
    &name[..end]
}

fn test_pe(size: usize) {
    let _lock = PROCESS_LOCK.lock().unwrap();

    let input = std::fs::read("tests/exec_pe64").unwrap();
    let pe = PortableExecutable::from(&input).unwrap();
    let _path = std::env::temp_dir().join("exec_pe64_out");

    let data = vec![0; size];
    #[cfg(not(windows))]
    let mut out = std::io::sink();
    #[cfg(windows)]
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&_path)
        .unwrap();
    pe.write_resource(RESOURCE_NAME, data)
        .unwrap()
        .build(&mut out)
        .unwrap();

    #[cfg(windows)]
    {
        drop(out);
        // Run the output
        let output = std::process::Command::new(&_path).output().unwrap();
        assert!(output.status.success());
    }
}

test_pe! {
    test_pe_1: 1,
    test_pe_10: 10,
    test_pe_64: 64,
    test_pe_512: 512,
    test_pe_1024: 1024,
    test_pe_1024_1024: 1024 * 1024,
    test_pe_1024_1024_5 : 1024 * 1024 * 5,
}

#[test]
fn utils() {
    let _lock = PROCESS_LOCK.lock().unwrap();

    let elf = std::fs::read("tests/exec_elf64").unwrap();
    let macho = std::fs::read("tests/exec_mach64").unwrap();
    let pe = std::fs::read("tests/exec_pe64").unwrap();

    assert!(utils::is_elf(&elf));
    assert!(utils::is_macho(&macho));
    assert!(utils::is_pe(&pe));

    assert!(!utils::is_elf(&macho));
    assert!(!utils::is_macho(&elf));
    assert!(!utils::is_pe(&elf));

    assert!(!utils::is_elf(&pe));
    assert!(!utils::is_macho(&pe));
    assert!(!utils::is_pe(&macho));
}

#[test]
fn test_macho_section_name_length_limit() {
    let _lock = PROCESS_LOCK.lock().unwrap();

    let input = std::fs::read("tests/exec_mach64").unwrap();

    // 16 bytes is the documented limit and should succeed.
    let exactly_16 = "0123456789abcdef";
    assert_eq!(exactly_16.len(), 16);
    assert!(Macho::from(input.clone())
        .unwrap()
        .write_section(exactly_16, vec![0; 32])
        .is_ok());

    // 17 bytes must return an error, not panic.
    let too_long = "0123456789abcdefg";
    assert_eq!(too_long.len(), 17);
    match Macho::from(input)
        .unwrap()
        .write_section(too_long, vec![0; 32])
    {
        Ok(_) => panic!("section name longer than 16 bytes must error"),
        Err(err) => {
            let msg = format!("{}", err);
            assert!(
                msg.contains("16 bytes"),
                "error should mention the 16-byte limit, got: {msg}",
            );
        }
    }
}

/// This test ensures that processing Intel Mac binaries works even when
/// codesign is not available (e.g., when cross-compiling from Linux).
#[test]
fn test_cross_platform_intel_mac_injection() {
    let _lock = PROCESS_LOCK.lock().unwrap();

    let input = std::fs::read("tests/exec_mach64_intel").unwrap();
    let macho = Macho::from(input).unwrap();

    let data = vec![0x42; 1024];
    let macho = macho.write_section(RESOURCE_NAME, data).unwrap();

    let mut output = Vec::new();
    macho.build_and_sign(&mut output).unwrap();

    // Verify we got some output
    assert!(!output.is_empty());
    assert!(utils::is_macho(&output));
}

/// Regression test for the ELF note append: the rewrite must preserve every
/// original byte of the file (so relocations such as `.relr.dyn`, and any
/// segment bytes not covered by a surviving section, survive unchanged). Only
/// the ELF header's table pointers are repointed; the original program and
/// section header tables are copied (enlarged) past EOF, never edited in
/// place. It must also leave the note discoverable via a PT_NOTE program
/// header. See the `Elf::append` docs.
#[test]
fn test_elf_append_preserves_original_bytes() {
    let _lock = PROCESS_LOCK.lock().unwrap();

    let input = std::fs::read("tests/exec_elf64").unwrap();
    let data = vec![0x42u8; 4096];

    let mut out = Vec::new();
    Elf::new(&input)
        .append(RESOURCE_NAME, &data, &mut out)
        .unwrap();

    assert!(utils::is_elf(&out));

    // Everything past the 64-byte ELF header is preserved verbatim: the
    // original program/section header tables, segment contents, and all
    // relocations survive untouched. Only the header's table pointers
    // (e_phoff/e_phnum, e_shoff/e_shnum) are updated.
    assert!(out.len() >= input.len());
    assert_eq!(
        &out[64..input.len()],
        &input[64..],
        "original bytes mutated"
    );

    let r64 = |b: &[u8]| u64::from_le_bytes(b[..8].try_into().unwrap());
    let r16 = |b: &[u8]| u16::from_le_bytes(b[..2].try_into().unwrap());

    // Two allocated sections were added (.sui.phdrs covering the relocated
    // program header table and .note.sui covering the note), so the section
    // header table was relocated (past EOF) and grew by exactly two entries.
    assert!(
        r64(&out[0x28..0x30]) >= input.len() as u64,
        "section header table not relocated past the original image"
    );
    assert_eq!(
        r16(&out[0x3c..0x3e]),
        r16(&input[0x3c..0x3e]) + 2,
        "e_shnum did not grow by 2"
    );

    // Program header table grew by exactly two entries (PT_LOAD + PT_NOTE).
    assert_eq!(
        r16(&out[0x38..0x3a]),
        r16(&input[0x38..0x3a]) + 2,
        "e_phnum did not grow by 2"
    );

    // Walk the (relocated) program headers and confirm a PT_NOTE points at a
    // SUI note whose payload round-trips back to what we appended.
    let e_phoff = r64(&out[0x20..0x28]) as usize;
    let e_phentsize = r16(&out[0x36..0x38]) as usize;
    let e_phnum = r16(&out[0x38..0x3a]) as usize;

    let mut found = false;
    'outer: for i in 0..e_phnum {
        let p = &out[e_phoff + i * e_phentsize..];
        if u32::from_le_bytes(p[0..4].try_into().unwrap()) != 4
        /* PT_NOTE */
        {
            continue;
        }
        let off = r64(&p[8..16]) as usize;
        let filesz = r64(&p[32..40]) as usize;
        let seg = &out[off..off + filesz];
        // Parse notes in this segment.
        let mut pos = 0usize;
        while pos + 12 <= seg.len() {
            let namesz = u32::from_le_bytes(seg[pos..pos + 4].try_into().unwrap()) as usize;
            let descsz = u32::from_le_bytes(seg[pos + 4..pos + 8].try_into().unwrap()) as usize;
            pos += 12;
            let mut nm = &seg[pos..pos + namesz];
            while let [rest @ .., 0] = nm {
                nm = rest;
            }
            pos = (pos + namesz + 3) & !3;
            let desc = &seg[pos..pos + descsz];
            pos = (pos + descsz + 3) & !3;
            if nm == b"SUI" {
                // desc = u16 name_len | name | payload
                let nl = u16::from_le_bytes(desc[0..2].try_into().unwrap()) as usize;
                assert_eq!(&desc[2..2 + nl], RESOURCE_NAME.as_bytes());
                assert_eq!(&desc[2 + nl..], &data[..], "note payload mismatch");
                found = true;
                break 'outer;
            }
        }
    }
    assert!(found, "appended SUI note not found via PT_NOTE");
}
