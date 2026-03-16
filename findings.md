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

## Finding 5: Integer Overflow in find_in_note_segment

**Severity:** MEDIUM

**Location:** `lib.rs:1097, lib.rs:1105-1108`

**Description:**
The `find_in_note_segment` function reads `namesz` and `descsz` from untrusted ELF note data and uses them in bounds checks that can overflow:

```rust
fn find_in_note_segment<'a>(segment: &'a [u8], align: usize, name: &str) -> Option<&'a [u8]> {
    let mut pos = 0usize;
    while pos + 12 <= segment.len() {
        let namesz = u32::from_le_bytes(segment[pos..pos + 4].try_into().ok()?) as usize;
        let descsz = u32::from_le_bytes(segment[pos + 4..pos + 8].try_into().ok()?) as usize;
        // ...
        pos += 12;

        if pos + namesz > segment.len() {  // Can overflow!
            break;
        }
        // ...
        if pos + descsz > segment.len() {  // Can overflow!
            break;
        }
        let desc = &segment[pos..pos + descsz];  // Out-of-bounds access!
```

On 64-bit systems with `usize = u64`, the `namesz` value can be up to 4GB (u32::MAX). If `pos = 12` and `namesz = 0xFFFF_FFF0`, then `pos + namesz = 0x100000002` which wraps to `2` due to integer overflow (though u32 fits in u64 so this requires specific conditions).

On 32-bit systems, if `pos = 12` and `namesz = 0xFFFF_FFF4`, then `pos + namesz` wraps to `0`, bypassing the bounds check and leading to out-of-bounds reads.

**Proof/Exploit:**
Craft a malicious ELF binary with:
1. A PT_NOTE segment
2. Inside that segment, a note entry with:
   - `namesz = 0xFFFF_FFF4` (on 32-bit) or similar large value
   - This causes the bounds check `pos + namesz > segment.len()` to be bypassed via overflow

The subsequent slicing `&segment[pos..pos + namesz]` will then panic or access out-of-bounds memory.

**Fix Suggestion:**
Use checked arithmetic:
```rust
if namesz > segment.len().saturating_sub(pos) {
    break;
}
```
Or use the `checked_add` method:
```rust
if pos.checked_add(namesz).map_or(true, |end| end > segment.len()) {
    break;
}
```

---

## Finding 6: Integer Overflow in align_up Function

**Severity:** MEDIUM

**Location:** `lib.rs:875-881, lib.rs:1105, lib.rs:1109`

**Description:**
The `align_up` function performs unchecked arithmetic that can overflow:

```rust
fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        value
    } else {
        (value + (align - 1)) & !(align - 1)
    }
}
```

If `value` is close to `usize::MAX`, the addition `value + (align - 1)` will overflow, wrapping around to a small value.

This is called from `find_in_note_segment`:
```rust
pos = super::align_up(pos + namesz, align);
// ...
pos = super::align_up(pos + descsz, align);
```

And from the ELF building code:
```rust
section.sh_offset = align_up(max_end as usize, align) as u64;
```

**Proof/Exploit:**
In the ELF parsing/writing path:
1. A malformed ELF file with `sh_offset` and `sh_size` values that sum to near `usize::MAX`
2. When `align_up` is called, it overflows
3. The resulting small offset causes incorrect file layout or memory access

In the note segment parsing path (`find_in_note_segment`):
1. `namesz` or `descsz` values near `usize::MAX - pos`
2. After `align_up`, the `pos` wraps around to a small value
3. The loop continues with an invalid `pos`, potentially reading beyond segment bounds

**Fix Suggestion:**
Use checked or saturating arithmetic:
```rust
fn align_up(value: usize, align: usize) -> Option<usize> {
    if align <= 1 {
        Some(value)
    } else {
        value.checked_add(align - 1).map(|v| v & !(align - 1))
    }
}
```

---

## Finding 7: Integer Overflow in c_dir_sz Calculation (MachoSigner)

**Severity:** MEDIUM

**Location:** `apple_codesign.rs:171`

**Description:**
In the `MachoSigner::sign` function, the calculation of `c_dir_sz` can overflow:

```rust
let n_hashes = self.sig_off.div_ceil(PAGE_SIZE);
let id_off = size_of::<CodeDirectory>();
let hash_off = id_off + id.len();
let c_dir_sz = hash_off + n_hashes * 32;  // Potential overflow!
let sz = size_of::<SuperBlob>() + size_of::<Blob>() + c_dir_sz;
```

If `self.sig_off` is large (close to `usize::MAX`), `n_hashes` will be a large value. The multiplication `n_hashes * 32` can then overflow, wrapping to a small value.

For example, on a 64-bit system:
- `sig_off = 0xFFFF_FFFF_FFFF_F000` (a large valid file offset)
- `n_hashes = sig_off.div_ceil(4096) ≈ 0x000F_FFFF_FFFF_FFFF`  
- `n_hashes * 32 ≈ 0x1FFF_FFFF_FFFF_FFE0` which overflows to a negative-looking value or wraps

This would result in:
- Incorrect `sz` calculation
- Incorrect buffer allocation with `Vec::with_capacity(sz)`
- Potential out-of-bounds writes when filling the buffer

**Proof/Exploit:**
1. Create a Mach-O file with an extremely large (but technically valid) signature offset
2. Pass it to `MachoSigner::new()` followed by `sign()`
3. The integer overflow causes incorrect sizing
4. Buffer operations may panic or access invalid memory

**Fix Suggestion:**
Use checked arithmetic:
```rust
let c_dir_sz = n_hashes
    .checked_mul(32)
    .and_then(|v| v.checked_add(hash_off))
    .ok_or(Error::InvalidObject("Size calculation overflow"))?;
```

---

## Finding 8: Integer Underflow in seg_sz Calculation (MachoSigner)

**Severity:** MEDIUM

**Location:** `apple_codesign.rs:181`

**Description:**
In the `MachoSigner::sign` function, the calculation of `seg_sz` can underflow:

```rust
let seg_sz = self.sig_off + sz - self.linkedit_seg.fileoff as usize;
```

If `self.linkedit_seg.fileoff` is greater than `self.sig_off + sz`, the subtraction will underflow, resulting in an extremely large value.

The `linkedit_seg.fileoff` comes from parsing the Mach-O file, and while a well-formed file should have valid relationships between these values, a malformed or malicious file could violate these invariants.

**Proof/Exploit:**
1. Craft a malicious Mach-O file with:
   - `linkedit_seg.fileoff = 0x8000_0000_0000_0000` (large value)
   - `sig_off + sz = 0x1000` (small value)
2. When `sign()` is called:
   - `seg_sz = 0x1000 - 0x8000_0000_0000_0000` underflows to a huge value
3. `linkedit_seg.filesize = seg_sz as u64;` sets an invalid file size
4. This corrupts the output binary structure

**Fix Suggestion:**
Use checked arithmetic:
```rust
let seg_sz = (self.sig_off + sz)
    .checked_sub(self.linkedit_seg.fileoff as usize)
    .ok_or(Error::InvalidObject("Invalid linkedit segment layout"))?;
```

---

## Finding 9: Integer Overflow in roundup Function (experiment.rs)

**Severity:** MEDIUM

**Location:** `experiment.rs:29-31`

**Description:**
The `roundup` function performs unchecked multiplication and addition that can overflow:

```rust
fn roundup(x: usize, y: usize) -> usize {
    ((x + y - 1) / y) * y
}
```

If `x + y - 1` overflows, it wraps around and the result can be incorrect. Similarly, the final multiplication `(...) * y` can overflow.

This is called with potentially attacker-controlled values from ELF note sections:
```rust
pos += size_of::<Elf64_Nhdr>()
    + roundup((*note).n_namesz as usize, 4)
    + roundup((*note).n_descsz as usize, 4);
```

**Proof/Exploit:**
If a malicious ELF note has `n_namesz = 0xFFFFFFFC` on a 32-bit system:
- `roundup(0xFFFFFFFC, 4) = ((0xFFFFFFFC + 3) / 4) * 4 = ((0xFFFFFFFF) / 4) * 4 = 0x3FFFFFFF * 4 = 0xFFFFFFFC`
- But `0xFFFFFFFC + 4 = 0` (wrap), causing incorrect memory access

Combined with unsafe pointer operations in `find_section2`, this can lead to out-of-bounds reads.

**Fix Suggestion:**
Use checked arithmetic:
```rust
fn roundup_checked(x: usize, y: usize) -> Option<usize> {
    x.checked_add(y.checked_sub(1)?)
        .and_then(|v| v.checked_div(y))
        .and_then(|v| v.checked_mul(y))
}
```

---

## Finding 10: Unsafe Memory Access in find_section2

**Severity:** HIGH

**Location:** `experiment.rs:78-93`

**Description:**
The `find_section2` function performs unsafe memory reads based on untrusted values from ELF note headers without proper bounds checking:

```rust
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
    let data = pos + size_of::<Elf64_Nhdr>() + roundup((*note).n_namesz as usize, 4);
    return Some(std::slice::from_raw_parts(data as *const u8, size));  // OOB read!
}
```

Several issues:
1. `strncmp` reads from `pos + size_of::<Elf64_Nhdr>()` without verifying the name fits within the segment bounds
2. `data` is calculated from `n_namesz` which could be any u32 value, potentially pointing outside valid memory
3. `std::slice::from_raw_parts` creates a slice of `size` bytes (derived from `n_descsz`) which could be arbitrary

**Proof/Exploit:**
A crafted binary with:
- A PT_NOTE segment
- A note with `n_namesz = 0` (passes the `!= 0` check) but actually has no name data
- `n_descsz = 0x10000000` (256MB)

This would cause `std::slice::from_raw_parts` to create a slice potentially reading far beyond allocated memory, leading to information disclosure or crash.

**Fix Suggestion:**
Add bounds checks before all unsafe memory operations:
```rust
let name_end = pos.checked_add(size_of::<Elf64_Nhdr>())
    .and_then(|v| v.checked_add((*note).n_namesz as usize));
let desc_end = name_end
    .and_then(|v| v.checked_add(roundup_checked((*note).n_namesz as usize, 4)?))
    .and_then(|v| v.checked_add((*note).n_descsz as usize));

if desc_end.is_none() || desc_end.unwrap() > end {
    break;  // Invalid note structure
}
```

---

## Finding 11: Out-of-Bounds Read in find_section2 due to Unchecked Arithmetic

**Severity:** HIGH

**Location:** `experiment.rs:69-90`

**Description:**
The `find_section2` function performs multiple arithmetic operations without bounds checking when calculating memory offsets for note sections. Several vulnerabilities exist:

1. The calculation `pos = base + (*phdr).p_vaddr as usize` at line 69 can overflow if a malicious ELF binary has a very large p_vaddr value.

2. The calculation `end = pos + (*phdr).p_memsz as usize` at line 70 can overflow.

3. At line 89, the data offset calculation has no bounds check:
```rust
let data = pos + size_of::<Elf64_Nhdr>() + roundup((*note).n_namesz as usize, 4);
```
This can overflow and result in reading memory from an unintended location.

4. At line 90, `std::slice::from_raw_parts(data as *const u8, size)` is called without validating that `data + size <= end`, leading to potential out-of-bounds memory access.

**Proof/Exploit:**
A crafted ELF binary with a PT_NOTE segment could set:
- `p_vaddr` + `p_memsz` to overflow, making `end < pos`
- `n_namesz` to a value that when added to `pos + size_of::<Elf64_Nhdr>()` overflows, wrapping around to point to arbitrary memory

When the process runs the affected binary and calls `find_section2()`, it will:
1. Create a slice pointing to arbitrary memory locations
2. Return this slice to the caller, potentially leaking sensitive data

**Fix Suggestion:**
Add bounds checking for all arithmetic operations:
```rust
let pos = base.checked_add((*phdr).p_vaddr as usize)?;
let end = pos.checked_add((*phdr).p_memsz as usize)?;
// ...
let name_aligned = roundup((*note).n_namesz as usize, 4);
let data = pos.checked_add(size_of::<Elf64_Nhdr>())?.checked_add(name_aligned)?;
let size = (*note).n_descsz as usize;
if data.checked_add(size)? > end {
    break; // Invalid note
}
return Some(std::slice::from_raw_parts(data as *const u8, size));
```

---

## Finding 5: Integer Overflow in MachoSigner::sign via Large sig_off

**Severity:** MEDIUM

**Location:** `apple_codesign.rs:168-181`

**Description:**
In the `MachoSigner::sign` function, the number of hashes `n_hashes` is calculated based on `sig_off` which comes from untrusted input (a file). If `sig_off` is very large (close to `usize::MAX`), the subsequent multiplication `n_hashes * 32` can overflow on 64-bit platforms.

```rust
let n_hashes = self.sig_off.div_ceil(PAGE_SIZE);  // n_hashes can be huge
let id_off = size_of::<CodeDirectory>();
let hash_off = id_off + id.len();
let c_dir_sz = hash_off + n_hashes * 32;  // OVERFLOW: n_hashes * 32 can wrap
let sz = size_of::<SuperBlob>() + size_of::<Blob>() + c_dir_sz;
```

**Proof/Exploit:**
A malicious Mach-O file can be crafted with:
1. A valid Mach-O structure
2. An `LC_CODE_SIGNATURE` load command with `dataoff` set to a very large value (e.g., `0x7FFFFFFFFFFFFFF8`)

On a 64-bit system:
- `n_hashes = 0x7FFFFFFFFFFFFFF8 / 4096 = 0x1FFFFFFFFFFFFF` (huge number)
- `n_hashes * 32` would overflow, wrapping to a small value
- This leads to an undersized buffer allocation
- Subsequent hash writes would corrupt memory or panic

Additionally, at line 181:
```rust
let seg_sz = self.sig_off + sz - self.linkedit_seg.fileoff as usize;
```
If `self.sig_off + sz` overflows, this calculation produces incorrect results.

**Fix Suggestion:**
Add overflow checks:
```rust
let n_hashes = self.sig_off.div_ceil(PAGE_SIZE);
let c_dir_sz = n_hashes.checked_mul(32)
    .and_then(|v| v.checked_add(hash_off))
    .ok_or(Error::InvalidObject("Code signature size overflow"))?;
```

---

## Finding 6: Potential Memory Corruption via Unchecked Slice Access in find_in_note_segment

**Severity:** MEDIUM

**Location:** `lib.rs:1090-1112`

**Description:**
In `find_in_note_segment`, the function reads `namesz` and `descsz` from untrusted input and uses them to compute positions. While there are bounds checks, the arithmetic `pos + namesz` could overflow before the comparison:

```rust
let namesz = u32::from_le_bytes(segment[pos..pos + 4].try_into().ok()?) as usize;
let descsz = u32::from_le_bytes(segment[pos + 4..pos + 8].try_into().ok()?) as usize;
// ...
pos += 12;

if pos + namesz > segment.len() {  // Could overflow if namesz is huge
    break;
}
```

On 64-bit platforms with a 32-bit `namesz` cast to `usize`, this isn't immediately exploitable. However, the pattern is still concerning for:
1. 32-bit platforms where `usize` is 32 bits
2. Future code changes

Additionally:
```rust
pos = super::align_up(pos + namesz, align);  // Could overflow
if pos + descsz > segment.len() {            // Second overflow potential
    break;
}
```

**Proof/Exploit:**
On a 32-bit system, or with carefully crafted inputs:
- If `namesz = 0xFFFFFFFF` and `pos = 12`, then `pos + namesz = 0x10000000B` which wraps to `0xB` (11)
- The bounds check `pos + namesz > segment.len()` would then pass incorrectly
- Subsequent slice access could read out-of-bounds memory

**Fix Suggestion:**
Use checked arithmetic:
```rust
let next_pos = pos.checked_add(namesz).ok_or_else(|| ...)?;
if next_pos > segment.len() {
    break;
}
```

---

## Finding 7: Integer Underflow in MachoSigner::sign seg_sz Calculation

**Severity:** MEDIUM

**Location:** `apple_codesign.rs:181`

**Description:**
The calculation of `seg_sz` can underflow if `linkedit_seg.fileoff` is greater than `sig_off + sz`:

```rust
let seg_sz = self.sig_off + sz - self.linkedit_seg.fileoff as usize;
```

Since `linkedit_seg.fileoff` comes from parsing the input file without validation that it's less than `sig_off`, this subtraction can underflow.

**Proof/Exploit:**
A malicious Mach-O file with:
- `linkedit_seg.fileoff = 0x10000`
- `sig_off = 0x100`
- `sz = 0x50`

Would result in:
- `seg_sz = 0x150 - 0x10000` = underflow to huge value

This would then be written to:
```rust
linkedit_seg.filesize = seg_sz as u64;
linkedit_seg.vmsize = seg_sz as u64;
```

Creating a malformed binary or causing memory allocation issues.

**Fix Suggestion:**
Validate the relationship before subtraction:
```rust
let total = self.sig_off.checked_add(sz)
    .ok_or(Error::InvalidObject("size overflow"))?;
if total < self.linkedit_seg.fileoff as usize {
    return Err(Error::InvalidObject("Invalid linkedit segment offset"));
}
let seg_sz = total - self.linkedit_seg.fileoff as usize;
```
