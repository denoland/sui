#![no_main]

use libfuzzer_sys::fuzz_target;
use libsui::Macho;

// Fuzz the *input image* rather than the payload.
//
// `macho_inject` feeds arbitrary section data into a known-good executable.
// This target does the opposite: it hands `Macho` a hostile image and walks
// the whole pipeline, which is where the parsing lives — load commands,
// rebase opcodes, chained fixup chains, the export trie, unwind tables and
// the symbol table are all driven by offsets and counts read out of the file.
// Anything malformed has to come back as an error, never a panic.
//
// Seeding the corpus with `tests/exec_mach64` and `tests/exec_mach64_chained`
// gets the fuzzer past the header and into those walkers.
fuzz_target!(|data: &[u8]| {
    let Ok(macho) = Macho::from(data.to_vec()) else {
        return;
    };
    let Ok(macho) = macho.write_section("__SUI", vec![0u8; 64]) else {
        return;
    };
    let mut out = Vec::new();
    let _ = macho.build(&mut out);
});
