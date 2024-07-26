use libsui::{Elf, Macho, PortableExecutable};

const RESOURCE_NAME: &str = "sui_test_data";

macro_rules! binary_tests {
    ($test_fn:ident, $($name:ident: $value:expr),*) => {
    $(
        #[test]
        fn $name() {
            $test_fn($value);
        }
    )*
    }
}

fn test_macho(size: usize) {
    let input = std::fs::read("tests/exec_mach64").unwrap();
    let mut macho = Macho::from(input).unwrap();

    let data = vec![0; size];
    macho
        .write_section(RESOURCE_NAME, data)
        .unwrap()
        .build_and_sign(std::io::sink())
        .unwrap();
}

binary_tests! {
    test_macho,
    test_macho_0: 0,
    test_macho_1: 1,
    test_macho_10: 10,
    test_macho_64: 64,
    test_macho_512: 512,
    test_macho_1024: 1024,
    test_macho_1024_1024: 1024 * 1024,
    test_macho_1024_1024_5 : 1024 * 1024 * 5
}

fn test_elf(size: usize) {
    let input = std::fs::read("tests/exec_elf64").unwrap();
    let elf = Elf::new(&input);

    let data = vec![0; size];
    let mut out = std::io::sink();
    elf.append(&data, &mut out).unwrap();

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let out = std::env::temp_dir().join("exec_elf64_out");
        // Write the output to a file
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o755)
            .open(&out)
            .unwrap();
        elf.append(&data, &mut out).unwrap();

        drop(out);
        // Run the output
        let output = std::process::Command::new("tests/exec_elf64_out")
            .output()
            .unwrap();
        assert_eq!(output.status.success(), true);
    }
}

binary_tests! {
    test_elf,
    test_elf_0: 0,
    test_elf_1: 1,
    test_elf_10: 10,
    test_elf_64: 64,
    test_elf_512: 512,
    test_elf_1024: 1024,
    test_elf_1024_1024: 1024 * 1024,
    test_elf_1024_1024_5 : 1024 * 1024 * 5
}

#[test]
fn test_pe() {}
