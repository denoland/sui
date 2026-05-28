# Security Findings for libsui

## Finding 1: Integer Underflow in `patch_macho_executable`

**Severity:** HIGH

**Location:** `intel_mac.rs:209`

**Description:**
The function `patch_macho_executable` reads a command size from untrusted input and performs a subtraction without checking if the value is large enough to subtract from.

```rust
let size = read_u32_le(file, offset) as usize - 8;
```

If a malformed Mach-O file has a `cmdsize` field less than 8 (e.g., 0-7), this subtraction will cause an integer underflow. On release builds, this will wrap around to a very large usize value (e.g., `0 - 8 = 0xFFFFFFFFFFFFFFF8` on 64-bit systems).

**Proof/Exploit:**
A malicious Mach-O file can be crafted with:
1. A valid Mach-O header with `ncmds >= 1`
2. A load command with `cmdsize` set to a value less than 8 (e.g., 0, 1, 2, etc.)

When `patch_macho_executable` processes this:
```rust
let size = read_u32_le(file, offset) as usize - 8;  // underflow!
// size becomes a very large number like 0xFFFFFFFFFFFFFFF8

if offset + size > file.len() {  // This check passes incorrectly due to wrap-around
    return false;
}

let (_, rest) = file.split_at_mut(offset);
let cmd_buf = &mut rest[..size];  // PANIC: slice with invalid length
```

In debug builds this will panic; in release builds it could lead to:
- Buffer over-read attempting to access memory beyond file bounds
- Denial of service through panic/crash

**Fix Suggestion:**
Add bounds checking before the subtraction:
```rust
let cmdsize = read_u32_le(file, offset);
if cmdsize < 8 {
    return false;  // Invalid command size
}
let size = cmdsize as usize - 8;
```

---

## Finding 2: Integer Underflow in Macho::build (rest_size calculation)

**Severity:** MEDIUM

**Location:** `lib.rs:738`

**Description:**
In the `Macho::build` function, there's a subtraction that can underflow:

```rust
let len = self.rest_size as usize - self.seg.cmdsize as usize;
```

The `rest_size` is calculated during `Macho::from()` as:
```rust
let rest_size = linkedit_cmd.fileoff - size_of::<Header64>() as u64 - header.sizeofcmds as u64;
```

And `seg.cmdsize` is set to:
```rust
cmdsize: size_of::<SegmentCommand64>() as u32 + size_of::<Section64>() as u32,
```

If `rest_size` (which depends on file input) is smaller than `seg.cmdsize`, this will underflow.

**Proof/Exploit:**
A crafted Mach-O binary with a `linkedit_cmd.fileoff` very close to the header size would result in a small `rest_size`. When `write_section` is called (increasing `seg.cmdsize`), the subsequent subtraction in `build` could underflow, leading to:
- Panic in debug builds
- Large memory allocation attempt in release builds (potential DoS)

**Fix Suggestion:**
Add a check before subtraction:
```rust
if self.rest_size as usize < self.seg.cmdsize as usize {
    return Err(Error::InvalidObject("rest_size smaller than command size"));
}
let len = self.rest_size as usize - self.seg.cmdsize as usize;
```

---

## Finding 3: Potential Out-of-Bounds Read in patch_command

**Severity:** MEDIUM

**Location:** `intel_mac.rs:56-77`

**Description:**
The `patch_command` function reads from fixed offsets in the buffer without verifying the buffer is large enough:

```rust
fn patch_command(cmd_type: u32, buf: &mut [u8], file_len: usize) {
    // LC_SEGMENT_64
    if cmd_type == 0x19 {
        if let Some(name) = parse_c_str(&buf[..16]) {  // Assumes buf.len() >= 16
            if name == "__LINKEDIT" {
                let fileoff = read_u64_le(buf, 32);  // Assumes buf.len() >= 40
                // ...
                write_u64_le(buf, 24, vmsize_patched);  // Assumes buf.len() >= 32
                write_u64_le(buf, 40, filesize_patched);  // Assumes buf.len() >= 48
            }
        }
    }

    // LC_SYMTAB
    if cmd_type == 0x2 {
        let stroff = read_u32_le(buf, 8);  // Assumes buf.len() >= 12
        write_u32_le(buf, 12, strsize_patched);  // Assumes buf.len() >= 16
    }
}
```

If the command buffer passed to this function is smaller than expected (which can happen due to Finding 1 or malformed input), these reads/writes will panic.

**Proof/Exploit:**
Combined with Finding 1, or with a malformed Mach-O file that has a valid-looking `cmdsize` but still too small for the actual command type:
- A `LC_SEGMENT_64` command needs at least 48 bytes for these operations
- A `LC_SYMTAB` command needs at least 16 bytes

If the `cmdsize` indicates 16 bytes (valid for LC_SYMTAB) but the type is set to LC_SEGMENT_64, the code will attempt to read/write beyond the buffer.

**Fix Suggestion:**
Add explicit length checks:
```rust
fn patch_command(cmd_type: u32, buf: &mut [u8], file_len: usize) {
    if cmd_type == 0x19 && buf.len() >= 48 {  // LC_SEGMENT_64 minimum size
        // ...
    }
    if cmd_type == 0x2 && buf.len() >= 16 {  // LC_SYMTAB minimum size
        // ...
    }
}
```

---

## Finding 4: Memory Leak via Box::leak in find_section

**Severity:** LOW

**Location:** `intel_mac.rs:147, intel_mac.rs:149`

**Description:**
The `find_section` function uses `Box::leak` to return static references:

```rust
return Ok(Some(Box::leak(data.into_boxed_slice())));
```

This intentionally leaks memory. While this may be acceptable for the use case (single extraction at program start), it could be exploited by repeated calls to `find_section` causing memory exhaustion.

**Proof/Exploit:**
If an application calls `find_section` repeatedly in a loop (processing multiple files or recovering from errors), memory will accumulate and never be freed.

**Fix Suggestion:**
Document this behavior or provide a non-leaking alternative API that returns owned data.


---

## Finding 5: Buffer Overflow in write_section (section name)

**Severity:** MEDIUM

**Location:** `lib.rs:554`

**Description:**
In the `Macho::write_section` function, the section name is copied into a fixed-size 16-byte buffer without bounds checking:

```rust
let mut sectname = [0; 16];
sectname[..name.len()].copy_from_slice(name.as_bytes());
```

If the `name` parameter has a length greater than 16 bytes, `copy_from_slice` will panic because the destination slice `sectname[..name.len()]` will be larger than the fixed 16-byte array.

**Proof/Exploit:**
```rust
use libsui::Macho;

fn main() -> Result<(), libsui::Error> {
    let exe = std::fs::read("tests/exec_mach64")?;
    let mut out = std::io::sink();
    
    // This will panic with "range end index 32 out of range for slice of length 16"
    Macho::from(exe)?
        .write_section("THIS_IS_A_VERY_LONG_NAME_OVER_16_CHARS", vec![1, 2, 3])?
        .build(&mut out)?;
    Ok(())
}
```

This is a denial of service vulnerability. An attacker could trigger a panic in any application that allows user-controlled section names.

**Fix Suggestion:**
Add bounds checking before the copy:
```rust
pub fn write_section(mut self, name: &str, sectdata: Vec<u8>) -> Result<Self, Error> {
    if name.len() > 16 {
        return Err(Error::InvalidObject("Section name too long (max 16 bytes)"));
    }
    // ... rest of function
}
```

---

## Finding 6: Integer Underflow in MachoSigner::sign (seg_sz calculation)

**Severity:** MEDIUM

**Location:** `apple_codesign.rs:181`

**Description:**
In the `MachoSigner::sign` function, there's a subtraction that can underflow:

```rust
let seg_sz = self.sig_off + sz - self.linkedit_seg.fileoff as usize;
```

The `linkedit_seg.fileoff` is read directly from untrusted input (the Mach-O file being signed). If a crafted Mach-O file has a `__LINKEDIT` segment with `fileoff` greater than `sig_off + sz`, this subtraction will underflow, resulting in a very large value being written to `linkedit_seg.filesize` and `linkedit_seg.vmsize`.

**Proof/Exploit:**
A malformed Mach-O binary can be crafted with:
1. A `__LINKEDIT` segment with `fileoff` set to a very large value (e.g., 0xFFFFFFFF)
2. A valid `LC_CODE_SIGNATURE` command with a small `dataoff` value

When `MachoSigner::sign` processes this:
```rust
let seg_sz = self.sig_off + sz - self.linkedit_seg.fileoff as usize;
// With sig_off=1000, sz=500, fileoff=0xFFFFFFFF:
// seg_sz = 1000 + 500 - 4294967295 = wraps to very large number

linkedit_seg.filesize = seg_sz as u64;  // Very large value written
linkedit_seg.vmsize = seg_sz as u64;    // Very large value written
```

In debug builds this will panic; in release builds it produces a corrupted binary with invalid segment sizes, which could lead to:
- Denial of service through crash when loading the corrupted binary
- Potential exploitation if the corrupted binary is later processed

**Fix Suggestion:**
Add bounds checking before the subtraction:
```rust
let total_size = self.sig_off + sz;
if self.linkedit_seg.fileoff as usize > total_size {
    return Err(Error::InvalidObject("Invalid LINKEDIT fileoff"));
}
let seg_sz = total_size - self.linkedit_seg.fileoff as usize;
```

---

## Finding 7: Out-of-Bounds Read in experiment::find_section2

**Severity:** HIGH

**Location:** `experiment.rs:80-86`

**Description:**
In the `find_section2` function, there's a bounds check at line 75 that ensures `pos + size_of::<Elf64_Nhdr>()` doesn't exceed `end`. However, immediately after reading the `Elf64_Nhdr`, the code performs a `strncmp` on memory at `pos + size_of::<Elf64_Nhdr>()` without verifying that this memory plus the note name size is within bounds:

```rust
if pos + size_of::<Elf64_Nhdr>() > end {
    break; // invalid
}

let note = pos as *const Elf64_Nhdr;
if (*note).n_namesz != 0
    && (*note).n_descsz != 0
    && strncmp(
        (pos + size_of::<Elf64_Nhdr>()) as *const c_char,  // No bounds check!
        elf_section_name.as_ptr() as *const c_char,
        elf_section_name.len(),
    ) == 0
{
    let size = (*note).n_descsz as usize;
    let data =
        pos + size_of::<Elf64_Nhdr>() + roundup((*note).n_namesz as usize, 4);  // No bounds check!
    return Some(std::slice::from_raw_parts(data as *const u8, size));  // Potential OOB
}
```

The `n_namesz` and `n_descsz` fields are read from untrusted ELF data. If a malformed ELF file has very large values for these fields, the code will:
1. Call `strncmp` on memory beyond the segment bounds
2. Calculate a `data` pointer beyond segment bounds  
3. Return a slice that extends beyond valid memory

**Proof/Exploit:**
A malformed ELF binary with a PT_NOTE segment can be crafted where:
1. The segment has a small `p_memsz` (e.g., 16 bytes)
2. The note header has `n_namesz` = 0xFFFFFFFF and `n_descsz` = 0xFFFFFFFF

When `find_section2` processes this:
- The check `pos + size_of::<Elf64_Nhdr>() > end` passes (12 + 4 = 16 <= 16)
- But `roundup(n_namesz, 4)` = very large number
- `data = pos + 12 + huge_number` = memory far beyond segment
- `std::slice::from_raw_parts(data, n_descsz)` creates a slice pointing to arbitrary memory

This is an out-of-bounds read vulnerability that could:
- Leak sensitive memory contents
- Cause crashes/segfaults
- Potentially be exploited for further attacks

**Fix Suggestion:**
Add comprehensive bounds checking:
```rust
let note = pos as *const Elf64_Nhdr;
let namesz = (*note).n_namesz as usize;
let descsz = (*note).n_descsz as usize;

// Validate that name and data fit within segment
let name_start = pos + size_of::<Elf64_Nhdr>();
let name_padded = roundup(namesz, 4);
let data_start = name_start + name_padded;
let data_padded = roundup(descsz, 4);

if data_start + data_padded > end {
    // Note extends beyond segment bounds
    pos += size_of::<Elf64_Nhdr>() + name_padded + data_padded;
    continue;  // or break
}

// Now safe to access name and data
```
