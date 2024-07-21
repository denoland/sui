#![no_main]

use libfuzzer_sys::fuzz_target;
use libsui::Macho;
use std::os::unix::fs::OpenOptionsExt;

static EXE: &[u8] = include_bytes!("../../tests/exec_mach64");

fuzz_target!(|data: &[u8]| {
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open("./fuzz_out")
        .unwrap();
    Macho::from(EXE.to_vec())
        .unwrap()
        .write_section("__SUI", data.to_vec())
        .unwrap()
        .build(&mut out)
        .unwrap();

    // Codesign
    let output = std::process::Command::new("codesign")
        .arg("-s")
        .arg("-")
        .arg("./fuzz_out")
        .output()
        .unwrap();
    assert_eq!(output.status.success(), true);
    // Run the binary
    let output = std::process::Command::new("./fuzz_out").output().unwrap();
    assert_eq!(output.status.success(), true);
});
