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
    use object::read::elf::{ElfFile64, FileHeader, ProgramHeader, SectionHeader};

    let elf_file = ElfFile64::<Endianness, _>::parse(&out[..]).unwrap();
    let endian = elf_file.endian();

    let section_table = elf_file.elf_section_table();
    let (_, note_section) = section_table
        .section_by_name(endian, b".note.sui")
        .expect(".note.sui section missing");

    let sh_offset: u64 = note_section.sh_offset(endian).into();
    let sh_size: u64 = note_section.sh_size(endian).into();
    assert!(sh_size > 0, ".note.sui is empty");

    let header = elf_file.elf_header();
    let segments = header.program_headers(endian, &out[..]).unwrap();

    let mut load_covers = false;
    let mut note_segment_matches = false;
    for segment in segments {
        let p_type = segment.p_type(endian);
        let p_offset: u64 = segment.p_offset(endian).into();
        let p_filesz: u64 = segment.p_filesz(endian).into();

        if p_type == object::elf::PT_LOAD {
            if sh_offset >= p_offset && sh_offset + sh_size <= p_offset + p_filesz {
                load_covers = true;
            }
        }
        if p_type == object::elf::PT_NOTE {
            if sh_offset == p_offset && sh_size == p_filesz {
                note_segment_matches = true;
            }
        }
    }

    assert!(load_covers, ".note.sui is not mapped by a PT_LOAD segment");
    assert!(
        note_segment_matches,
        "PT_NOTE segment does not point at .note.sui"
    );

    let Ok(Some(mut notes)) = note_section.notes(endian, &out[..]) else {
        panic!("failed to read notes from .note.sui");
    };

    let mut has_gnu = false;
    let mut has_sui = false;
    while let Ok(Some(note)) = notes.next() {
        let name = trim_note_name(note.name());
        if name == b"GNU" {
            has_gnu = true;
        } else if name == b"SUI" {
            has_sui = true;
        }
    }

    assert!(has_gnu, "expected GNU note to be preserved");
    assert!(has_sui, "expected SUI note to be appended");
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
    use object::read::elf::{ElfFile64, SectionHeader};

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
    let section_table = elf_file.elf_section_table();

    let (_, note) = section_table
        .section_by_name(endian, b".note.sui")
        .expect(".note.sui section missing");
    let note_addr = note.sh_addr(endian);
    let note_end = note_addr + note.sh_size(endian);
    assert!(note_end > note_addr, ".note.sui is empty");

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
        return None;
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
