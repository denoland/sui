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
