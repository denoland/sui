# ELF Notes Design (Technical Overview)

This document describes how `libsui` embeds and extracts data in ELF binaries.

## Goals

- Preserve existing ELF notes (e.g., GNU ABI tag/build-id).
- Keep injected data mapped in memory so runtime lookup works.
- Avoid rewriting the entire ELF layout beyond what is necessary.

## Embedding (`Elf::append`)

### 1) Build the SUI note payload

We encode a single ELF note whose descriptor contains:

- `u16` length of the section name
- section name bytes (UTF-8)
- raw section data bytes

This is wrapped in a standard ELF note header and name:

- note name: `SUI\0`
- note type: `0x5355_4901`

The payload is padded to 4-byte alignment per ELF note requirements.

### 2) Preserve existing notes

If the input ELF already has a `PT_NOTE` segment, we read the raw note segment
data and **prepend** it to the new SUI note payload. The result is a single
note segment that contains all prior notes followed by the new SUI note.

This preserves existing notes without keeping multiple `PT_NOTE` program headers.

### 3) Place `.note.sui` inside a `PT_LOAD`

We add a new section:

- name: `.note.sui`
- type: `SHT_NOTE`
- flags: `SHF_ALLOC`
- alignment: 4
- data: combined note payload (existing notes + SUI note)

To ensure the note is mapped at runtime, the section is placed at the end of
the **last `PT_LOAD` segment**:

- `sh_offset` is set to the end of the file (aligned to the segment alignment)
- `sh_addr` is computed to match the file-to-virtual mapping of that `PT_LOAD`
- the `PT_LOAD` segment’s `p_filesz` and `p_memsz` are extended to cover the new
  section

### 4) Point `PT_NOTE` at `.note.sui`

If a `PT_NOTE` program header exists, it is **repurposed** to point at the new
`.note.sui` range. If none exists, a new `PT_NOTE` header is added.

This means the runtime note scan sees a single `PT_NOTE` segment that contains
the original notes (copied into `.note.sui`) plus the new SUI note.

## Runtime extraction (`find_section`)

At runtime on Unix (non-Apple), `find_section`:

1. Uses `dl_iterate_phdr` to locate `PT_NOTE` segments.
2. Parses note entries in those segments.
3. Matches:
   - note name `SUI`
   - note type `0x5355_4901`
   - the embedded section name in the descriptor
4. Returns the associated section data.

### Linux fallback

On Linux, if the in-memory scan fails, `find_section` falls back to reading
`/proc/self/exe` and scanning the on-disk bytes. This is a safety net for
environments where the note segment might not be mapped or visible in memory.

## Notes and Limits

- Note sizes are stored in 32-bit fields. Payloads >4 GiB will overflow and
  are not supported.
- The section name length is stored as `u16`; extremely long section names are
  rejected.
- Existing `PT_NOTE` **section headers** are not preserved; their contents are
  copied into `.note.sui` instead.

