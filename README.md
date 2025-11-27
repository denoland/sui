# `libsui`

[![Crates.io](https://img.shields.io/crates/v/libsui.svg)](https://crates.io/crates/libsui)

_Sui (सुई)_ is a injection tool for executable formats (ELF, PE, Mach-O) that
allows you to embed files into existing binary and extract them at runtime.

It produces valid executables that can be code signed on macOS and Windows.

[Documentation](https://docs.rs/libsui) | [Usage](cli.rs)

## Usage

```
cargo add libsui
```

Embedding data into binaries:

```rust
use libsui::{Macho, PortableExecutable};

let exe = std::fs::read("tests/exec_mach64")?;
let mut out = std::fs::File::create("out")?;

Macho::from(exe)?
    .write_section("__hello", b"Hello, World!".to_vec())?
    .build(&mut out)?;

let exe = std::fs::read("tests/exec_pe64")?;
let mut out = std::fs::File::create("out.exe")?;

PortableExecutable::from(exe)?
    .write_resource("hello.txt", b"Hello, World!".to_vec())?
    .build(&mut out)?;
```

Extracting from self:

```rust
use libsui::find_section;

let data = find_section("hello.txt")?;
```

## Design

### Mach-O

#### ARM64 (Apple Silicon)

Resource is added as section in a new segment, load commands are updated and
offsets are adjusted. `__LINKEDIT` is kept at the end of the file.

It is similar to linker's `-sectcreate,__FOO,__foo,hello.txt` option.

Note that `Macho::build` will invalidate existing code signature. on Apple
sillicon, kernel refuses to run executables with bad signatures.

#### x86_64 (Intel Mac)

For Intel Macs, a simpler approach is used:

1. The existing code signature is stripped using `codesign --remove-signature`
2. Data is appended to the end of the binary with a sentinel marker.
3. The `__LINKEDIT` segment and symbol table sizes are patched to account for
   the appended data.

At runtime, the data is extracted by searching backwards from the end of the
file for the sentinel marker.

#### Code Signing

Use `Macho::build_and_sign` to re-sign the binary with ad-hoc signature. See
[`apple_codesign.rs`](./apple_codesign.rs) for details. This is similar to
`codesign -s - ./out` command.

```rust
Macho::from(exe)?
    .write_section("__sect", data)?
    .build_and_sign(&mut out)?;
```

```
$ codesign -d -vvv ./out

Executable=/Users/divy/gh/sui/out
Identifier=a.out
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=10238 flags=0x20002(adhoc,linker-signed) hashes=317+0 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha256=6b1abb20f2291dd9b0dbcd0659a918cb2d0e6b18
CandidateCDHashFull sha256=6b1abb20f2291dd9b0dbcd0659a918cb2d0e6b1876153efa17f90dc8b3a8f177
Hash choices=sha256
CMSDigest=6b1abb20f2291dd9b0dbcd0659a918cb2d0e6b1876153efa17f90dc8b3a8f177
CMSDigestType=2
CDHash=6b1abb20f2291dd9b0dbcd0659a918cb2d0e6b18
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements=none
```

### PE

Resource is added into a new PE resource directory as `RT_RCDATA` type and
extracted using `FindResource` and `LoadResource` at run-time.

### ELF

Data is simply appended to the end of the file and extracted from
`current_exe()` at run-time.

This is subject to change and may use ELF linker notes (`PT_NOTE`) in the
future.

## Testing

This crate is fuzzed with LLVM's libFuzzer. See [fuzz/](fuzz/).

`exec_*` executables in `tests/` are compiled from `tests/exec.rs`:

```
rustc exec.rs -o exec_elf64 --target x86_64-unknown-linux-gnu
```

## License

MIT
