//! Growing the Mach-O load command region.
//!
//! Load commands have to be contiguous with the Mach-O header, so a new one
//! can only go in the padding the linker left between the end of the commands
//! and the first section. When that padding is too small — a stock `cargo
//! build` binary often has only 48 bytes, against the 152 a `__SUI` segment
//! costs — the padding has to grow, which means pushing the entire image down
//! by a page.
//!
//! That changes the distance from the header to the code, so every value
//! defined *relative to the image base* moves with it: entry point, function
//! starts, unwind info, export addresses, rebased pointers, symbol addresses.
//! This module walks all of them. It is deliberately strict — anything it does
//! not recognise is an error, never a guess, because a missed fixup is exactly
//! the silent corruption this whole path exists to avoid.
//!
//! The approach follows LIEF's `MachO::Binary::shift`, which is what
//! `postject` relies on for the same problem.

use crate::{
    align, Error, Header64, Section64, SegmentCommand64, LC_ATOM_INFO, LC_CODE_SIGNATURE,
    LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO, LC_DYLD_INFO_ONLY,
    LC_DYLIB_CODE_SIGN_DRS, LC_DYSYMTAB, LC_FUNCTION_STARTS, LC_FUNCTION_VARIANTS,
    LC_FUNCTION_VARIANT_FIXUPS, LC_LINKER_OPTIMIZATION_HINT, LC_SEGMENT_64, LC_SYMTAB,
};
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

const LC_MAIN: u32 = 0x8000_0028;
const LC_UUID: u32 = 0x1b;
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;

const SEG_TEXT: &[u8] = b"__TEXT\0";
const SEG_LINKEDIT: &[u8] = b"__LINKEDIT\0";

/// `n_type` bits (`<mach-o/nlist.h>`).
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;

#[repr(C)]
#[derive(Clone, Copy, FromBytes, zerocopy::FromZeroes, AsBytes)]
struct Nlist64 {
    n_strx: u32,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,
}

fn invalid(msg: &'static str) -> Error {
    Error::InvalidObject(msg)
}

/// Borrow `len` bytes at `at`, or fail. Every read in this module goes
/// through here or its callers: a shift runs over attacker-shaped input from
/// `Macho::from`, so a malformed image has to be an error, never a panic.
pub(crate) fn slice(data: &[u8], at: usize, len: usize) -> Result<&[u8], Error> {
    at.checked_add(len)
        .and_then(|end| data.get(at..end))
        .ok_or_else(|| invalid("Truncated Mach-O"))
}

fn read_u16(data: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(slice(data, at, 2)?.try_into().unwrap()))
}

fn read_u32(data: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(slice(data, at, 4)?.try_into().unwrap()))
}

fn write_u32(data: &mut [u8], at: usize, value: u32) -> Result<(), Error> {
    write_at(data, at, &value.to_le_bytes())
}

fn write_at(data: &mut [u8], at: usize, bytes: &[u8]) -> Result<(), Error> {
    at.checked_add(bytes.len())
        .and_then(|end| data.get_mut(at..end))
        .ok_or_else(|| invalid("Truncated Mach-O"))?
        .copy_from_slice(bytes);
    Ok(())
}

fn read_u64(data: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(slice(data, at, 8)?.try_into().unwrap()))
}

fn write_u64(data: &mut [u8], at: usize, value: u64) -> Result<(), Error> {
    write_at(data, at, &value.to_le_bytes())
}

/// Read a ULEB128, returning the value and how many bytes it used.
fn read_uleb(data: &[u8], at: usize) -> Result<(u64, usize), Error> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut len = 0usize;
    loop {
        let byte = *at
            .checked_add(len)
            .and_then(|i| data.get(i))
            .ok_or_else(|| invalid("Truncated ULEB128"))?;
        len += 1;
        if shift < 64 {
            value |= ((byte & 0x7f) as u64) << shift;
        } else if byte & 0x7f != 0 {
            return Err(invalid("ULEB128 overflow"));
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, len));
        }
        if len > 10 {
            return Err(invalid("ULEB128 too long"));
        }
    }
}

/// Encode a ULEB128 into exactly `len` bytes.
///
/// ULEB128 permits non-minimal encodings — extra groups carrying zero bits —
/// and every reader in the toolchain accumulates until the continuation bit
/// clears. Padding lets a value be rewritten in place without disturbing the
/// bytes around it.
fn write_uleb_padded(out: &mut Vec<u8>, mut value: u64, len: usize) {
    for i in 0..len {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if i + 1 < len {
            byte |= 0x80;
        }
        out.push(byte);
    }
}

fn uleb_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn encode_uleb(out: &mut Vec<u8>, value: u64) {
    write_uleb_padded(out, value, uleb_len(value));
}

/// The segment that maps the Mach-O header, and therefore the one the new
/// load command space is carved out of.
fn is_text(seg: &SegmentCommand64) -> bool {
    seg.segname[..SEG_TEXT.len()] == *SEG_TEXT && seg.fileoff == 0
}

/// One `LC_SEGMENT_64` in the image being shifted.
struct Segment {
    /// Offset of the load command inside the file.
    cmd_offset: usize,
    seg: SegmentCommand64,
    /// File offset the segment had *before* the shift.
    old_fileoff: u64,
    /// Virtual address the segment had *before* the shift.
    old_vmaddr: u64,
}

/// A blob living in `__LINKEDIT`, tracked so the region can be relaid out when
/// one of them changes size.
struct LinkeditBlob {
    /// Offset of the `dataoff`/`datasize` pair to patch, and whether the pair
    /// is a plain `linkedit_data_command` or a field inside a bigger command.
    off_field: usize,
    size_field: Option<usize>,
    old_off: u64,
    size: usize,
    /// Replacement contents, when the blob had to be rebuilt.
    replacement: Option<Vec<u8>>,
    /// Blobs the kernel requires to stay last (the code signature).
    is_signature: bool,
}

pub(crate) struct Shifter {
    data: Vec<u8>,
    width: u64,
    /// End of the load commands before the shift; the insertion point.
    lc_end: u64,
    /// Virtual address matching `lc_end`.
    lc_end_va: u64,
    segments: Vec<Segment>,
    /// `(cmd, cmdsize, offset)` for every load command.
    commands: Vec<(u32, u32, usize)>,
    blobs: Vec<LinkeditBlob>,
    linkedit_index: usize,
}

/// Grow the load command region of `obj` by `width` bytes.
///
/// `width` must be a multiple of the segment alignment so that every segment
/// keeps `vmaddr % page == fileoff % page`, which the kernel enforces when it
/// maps the image.
pub(crate) fn shift(obj: Vec<u8>, width: u64) -> Result<Vec<u8>, Error> {
    Shifter::new(obj, width)?.run()
}

impl Shifter {
    fn new(data: Vec<u8>, width: u64) -> Result<Self, Error> {
        let header =
            Header64::read_from_prefix(&data).ok_or_else(|| invalid("Failed to read header"))?;

        // Not `with_capacity(ncmds)`: the count is untrusted, and the loop
        // below rejects a bogus one within a few iterations anyway.
        let mut commands = Vec::new();
        let mut offset = size_of::<Header64>();
        for _ in 0..header.ncmds {
            let cmd = read_u32(&data, offset)?;
            let cmdsize = read_u32(&data, offset + 4)? as usize;
            if cmdsize < 8 || offset + cmdsize > data.len() {
                return Err(invalid("Malformed load command"));
            }
            commands.push((cmd, cmdsize as u32, offset));
            offset += cmdsize;
        }

        // sizeofcmds is untrusted and is used as a splice index below, so it
        // has to be inside the file even if every individual command parsed.
        let lc_end = (size_of::<Header64>() + header.sizeofcmds as usize) as u64;
        if lc_end > data.len() as u64 {
            return Err(invalid("Load commands run past the end of the file"));
        }

        let mut segments = Vec::new();
        let mut text_vmaddr = None;
        for (cmd, _, cmd_offset) in &commands {
            if *cmd != LC_SEGMENT_64 {
                continue;
            }
            let seg = SegmentCommand64::read_from_prefix(&data[*cmd_offset..])
                .ok_or_else(|| invalid("Failed to read segment command"))?;
            if is_text(&seg) {
                text_vmaddr = Some(seg.vmaddr);
            }
            segments.push(Segment {
                cmd_offset: *cmd_offset,
                old_fileoff: seg.fileoff,
                old_vmaddr: seg.vmaddr,
                seg,
            });
        }

        let text_vmaddr =
            text_vmaddr.ok_or_else(|| invalid("No __TEXT segment mapping the Mach-O header"))?;
        let linkedit_index = segments
            .iter()
            .position(|s| s.seg.segname[..SEG_LINKEDIT.len()] == *SEG_LINKEDIT)
            .ok_or_else(|| invalid("Linkedit segment not found"))?;

        // __TEXT's address comes out of the file like everything else.
        let lc_end_va = text_vmaddr
            .checked_add(lc_end)
            .ok_or_else(|| invalid("__TEXT address overflows"))?;

        Ok(Self {
            data,
            width,
            lc_end,
            lc_end_va,
            segments,
            commands,
            blobs: Vec::new(),
            linkedit_index,
        })
    }

    /// Move a file offset, or equivalently an offset from the image base.
    ///
    /// The two coincide because `__TEXT` starts at file offset 0 and covers
    /// the header, so a byte's distance from the start of the file and its
    /// distance from the image base are the same number. Export trie
    /// addresses, unwind info, function starts and chained fixup targets are
    /// all image-base offsets and use this too.
    fn shift_off(&self, value: u64) -> Result<u64, Error> {
        self.moved(value, self.lc_end)
    }

    /// Move a virtual address.
    fn shift_va(&self, value: u64) -> Result<u64, Error> {
        self.moved(value, self.lc_end_va)
    }

    /// Add `width` to anything at or past `floor`.
    ///
    /// A value so large that it overflows is not describing anything real, so
    /// treat it the way the rest of this module treats nonsense.
    fn moved(&self, value: u64, floor: u64) -> Result<u64, Error> {
        if value < floor {
            return Ok(value);
        }
        value
            .checked_add(self.width)
            .ok_or_else(|| invalid("Shifted value overflows"))
    }

    fn run(mut self) -> Result<Vec<u8>, Error> {
        self.reject_unsupported()?;
        self.reject_absolute_eh_frame()?;
        self.collect_linkedit_blobs()?;

        // Patch content that is addressed the old way before anything moves.
        self.patch_rebase_targets()?;
        self.patch_chained_fixups()?;
        self.patch_unwind_info()?;
        self.patch_symbol_table()?;
        self.patch_data_in_code()?;
        self.rebuild_function_starts()?;
        self.rebuild_export_trie()?;

        // Physically open the gap, then move every descriptor across it.
        let gap = self.lc_end as usize;
        self.data.splice(gap..gap, vec![0u8; self.width as usize]);

        self.patch_segments()?;
        self.patch_command_offsets()?;
        self.relayout_linkedit()?;

        self.rewrite_uuid();
        self.verify()?;
        Ok(self.data)
    }

    /// Reject a `linkedit_data_command` that actually carries a payload.
    ///
    /// These blobs are all expressed relative to the image base, so the
    /// relayout would move them without fixing up their contents.
    fn reject_payload(&self, offset: usize, msg: &'static str) -> Result<(), Error> {
        if read_u32(&self.data, offset + 12)? != 0 {
            return Err(invalid(msg));
        }
        Ok(())
    }

    /// Give the image a new `LC_UUID`.
    ///
    /// Every code address moved, so a `.dSYM` built for the original no longer
    /// describes this binary. The UUID is what pairs the two, and leaving it
    /// alone means `lldb` happily loads that companion and reports confidently
    /// wrong functions and line numbers. Changing it makes the pairing fail
    /// instead, and the debugger falls back to the symbol table, which this
    /// module does keep correct.
    ///
    /// Derived from the image content so a given input always yields the same
    /// output.
    fn rewrite_uuid(&mut self) {
        use sha2::{Digest, Sha256};

        let Some(offset) = self.find_command(LC_UUID) else {
            return;
        };
        let Some(field) = self.data.get_mut(offset + 8..offset + 24) else {
            return;
        };
        field.fill(0);

        // The load commands pin down every segment, section and blob location
        // in the image, so hashing them plus the file size distinguishes any
        // two outputs without walking megabytes of code.
        let mut hasher = Sha256::new();
        hasher.update((self.data.len() as u64).to_le_bytes());
        hasher.update(self.width.to_le_bytes());
        hasher.update(&self.data[..(self.lc_end + self.width) as usize]);
        let digest = hasher.finalize();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&digest[..16]);
        // RFC 4122 version 4 / variant 1, so it reads as a normal UUID.
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        self.data[offset + 8..offset + 24].copy_from_slice(&uuid);
    }

    /// Check the properties the kernel relies on when it maps the result.
    ///
    /// These should hold by construction; failing loudly here beats shipping
    /// an image that only misbehaves once it is launched.
    fn verify(&self) -> Result<(), Error> {
        let lc_end = self.lc_end + self.width;
        let mut file_end = 0u64;

        for segment in &self.segments {
            let seg = &segment.seg;
            if seg.filesize == 0 {
                continue;
            }
            let end = seg
                .fileoff
                .checked_add(seg.filesize)
                .ok_or_else(|| invalid("Segment file range overflows"))?;
            if end > self.data.len() as u64 {
                return Err(invalid("Segment runs past the end of the file"));
            }
            // The kernel maps whole pages, so a segment's address and its file
            // offset have to agree modulo the page size for every page size it
            // might use.
            if seg.vmaddr % 0x1000 != seg.fileoff % 0x1000 {
                return Err(invalid("Segment lost page alignment"));
            }
            if is_text(seg) && seg.filesize < lc_end {
                return Err(invalid("__TEXT no longer covers the load commands"));
            }
            file_end = file_end.max(end);
        }

        if file_end != self.data.len() as u64 {
            return Err(invalid("Image has trailing bytes outside every segment"));
        }
        Ok(())
    }

    /// Refuse images carrying something this module cannot faithfully move.
    fn reject_unsupported(&self) -> Result<(), Error> {
        for (cmd, _, offset) in &self.commands {
            match *cmd {
                LC_ENCRYPTION_INFO_64 => {
                    return Err(invalid("Cannot grow the load commands: image is encrypted"))
                }
                LC_SEGMENT_SPLIT_INFO => self.reject_payload(
                    *offset,
                    "Cannot grow the load commands: LC_SEGMENT_SPLIT_INFO has data",
                )?,
                LC_LINKER_OPTIMIZATION_HINT => self.reject_payload(
                    *offset,
                    "Cannot grow the load commands: LC_LINKER_OPTIMIZATION_HINT has data",
                )?,
                LC_ATOM_INFO | LC_DYLIB_CODE_SIGN_DRS => self.reject_payload(
                    *offset,
                    "Cannot grow the load commands: unsupported __LINKEDIT payload",
                )?,
                LC_FUNCTION_VARIANTS | LC_FUNCTION_VARIANT_FIXUPS => self.reject_payload(
                    *offset,
                    "Cannot grow the load commands: LC_FUNCTION_VARIANTS has data",
                )?,
                LC_DYSYMTAB => {
                    // Linked images leave these empty. Anything else would
                    // need its own relayout, so bail out rather than guess.
                    // tocoff, modtaboff, extrefsymoff, extreloff, locreloff.
                    for at in [32usize, 40, 48, 64, 72] {
                        if read_u32(&self.data, offset + at)? != 0 {
                            return Err(invalid(
                                "Cannot grow the load commands: LC_DYSYMTAB has relocation tables",
                            ));
                        }
                    }
                }
                _ => {}
            }
        }

        // Section relocations point into a table this module does not relay
        // out. Linked images have none.
        for seg in &self.segments {
            let mut sect_offset = seg.cmd_offset + size_of::<SegmentCommand64>();
            for _ in 0..seg.seg.nsects {
                let sect = Section64::read_from_prefix(slice(
                    &self.data,
                    sect_offset,
                    size_of::<Section64>(),
                )?)
                .ok_or_else(|| invalid("Failed to read section"))?;
                if sect.nreloc != 0 {
                    return Err(invalid(
                        "Cannot grow the load commands: sections carry relocations",
                    ));
                }
                sect_offset += size_of::<Section64>();
            }
        }
        Ok(())
    }

    /// `__eh_frame` FDEs reach their function through a pointer whose encoding
    /// the governing CIE declares.
    ///
    /// clang and rustc emit PC-relative encodings, which move with the section
    /// and need no patching at all — the section comes out byte-identical yet
    /// every FDE still points at the right code. An absolute encoding would be
    /// left stale instead, and nothing downstream would notice until something
    /// tried to unwind, so refuse those rather than guess.
    fn reject_absolute_eh_frame(&self) -> Result<(), Error> {
        let Some((sect_off, sect_size)) = self.find_section(b"__eh_frame")? else {
            return Ok(());
        };
        let base = sect_off as usize;
        let end = base + sect_size as usize;

        let mut at = base;
        while at + 4 <= end {
            let length = read_u32(&self.data, at)? as usize;
            if length == 0 {
                break; // terminator
            }
            if length == 0xffff_ffff {
                return Err(invalid(
                    "Cannot grow the load commands: 64-bit DWARF __eh_frame",
                ));
            }
            let entry_end = at + 4 + length;
            if entry_end > end {
                return Err(invalid("Malformed __eh_frame"));
            }
            // A zero CIE pointer marks a CIE; anything else is an FDE, which
            // inherits its encoding from the CIE it names.
            if read_u32(&self.data, at + 4)? == 0 {
                self.check_cie_encodings(at + 8, entry_end)?;
            }
            at = entry_end;
        }
        Ok(())
    }

    fn check_cie_encodings(&self, mut at: usize, end: usize) -> Result<(), Error> {
        const DW_EH_PE_OMIT: u8 = 0xff;
        const DW_EH_PE_PCREL: u8 = 0x10;

        let unsupported = || invalid("Cannot grow the load commands: absolute __eh_frame pointers");

        let version = *self.data.get(at).ok_or_else(|| invalid("Malformed CIE"))?;
        at += 1;
        if version != 1 && version != 3 {
            return Err(invalid(
                "Cannot grow the load commands: unknown CIE version",
            ));
        }

        let aug_start = at;
        while at < end && self.data[at] != 0 {
            at += 1;
        }
        let augmentation = slice(&self.data, aug_start, at - aug_start)?.to_vec();
        at += 1;

        // Without a 'z' augmentation the FDE pointer encoding is absolute.
        if augmentation.first() != Some(&b'z') {
            return Err(unsupported());
        }

        at += read_uleb(&self.data, at)?.1; // code alignment factor
        while at < end && self.data[at] & 0x80 != 0 {
            at += 1; // data alignment factor (SLEB128)
        }
        at += 1;
        at += read_uleb(&self.data, at)?.1; // return address register
        at += read_uleb(&self.data, at)?.1; // augmentation data length

        let mut saw_fde_encoding = false;
        for kind in &augmentation[1..] {
            match kind {
                b'L' | b'R' => {
                    let encoding = *self.data.get(at).ok_or_else(|| invalid("Malformed CIE"))?;
                    at += 1;
                    if encoding != DW_EH_PE_OMIT && encoding & 0x70 != DW_EH_PE_PCREL {
                        return Err(unsupported());
                    }
                    if *kind == b'R' {
                        saw_fde_encoding = true;
                    }
                }
                b'P' => {
                    let encoding = *self.data.get(at).ok_or_else(|| invalid("Malformed CIE"))?;
                    at += 1;
                    if encoding != DW_EH_PE_OMIT && encoding & 0x70 != DW_EH_PE_PCREL {
                        return Err(unsupported());
                    }
                    at += match encoding & 0x0f {
                        0x00 | 0x04 | 0x0c => 8,
                        0x02 | 0x0a => 2,
                        0x03 | 0x0b => 4,
                        0x01 | 0x09 => read_uleb(&self.data, at)?.1,
                        _ => return Err(invalid("Unknown __eh_frame pointer encoding")),
                    };
                }
                b'S' | b'B' | b'G' => {}
                _ => return Err(invalid("Unknown __eh_frame augmentation")),
            }
        }

        if !saw_fde_encoding {
            return Err(unsupported());
        }
        Ok(())
    }

    // ---------------------------------------------------------------- layout

    fn patch_segments(&mut self) -> Result<(), Error> {
        for index in 0..self.segments.len() {
            let cmd_offset = self.segments[index].cmd_offset;
            let mut seg = self.segments[index].seg.clone();
            let grows = is_text(&seg);

            seg.fileoff = self.shift_off(self.segments[index].old_fileoff)?;
            seg.vmaddr = self.shift_va(self.segments[index].old_vmaddr)?;
            if grows {
                // __TEXT swallows the new gap: it starts at file offset 0 and
                // covers the header, so it is the segment that got bigger.
                seg.filesize = self.moved(seg.filesize, 0)?;
                seg.vmsize = self.moved(seg.vmsize, 0)?;
            }

            let nsects = seg.nsects as usize;
            write_at(&mut self.data, cmd_offset, seg.as_bytes())?;
            self.segments[index].seg = seg;

            let mut sect_offset = cmd_offset + size_of::<SegmentCommand64>();
            for _ in 0..nsects {
                let mut sect = Section64::read_from_prefix(slice(
                    &self.data,
                    sect_offset,
                    size_of::<Section64>(),
                )?)
                .ok_or_else(|| invalid("Failed to read section"))?;
                // A zero file offset marks a zerofill section; it owns no file
                // bytes but its address still moves with the rest.
                if sect.offset as u64 >= self.lc_end {
                    sect.offset = u32::try_from(self.moved(sect.offset as u64, 0)?)
                        .map_err(|_| invalid("Mach-O file would exceed 4 GiB"))?;
                }
                sect.addr = self.shift_va(sect.addr)?;
                write_at(&mut self.data, sect_offset, sect.as_bytes())?;
                sect_offset += size_of::<Section64>();
            }
        }
        Ok(())
    }

    /// Move the entry point.
    ///
    /// `__LINKEDIT` blob offsets are handled by [`Self::relayout_linkedit`],
    /// which may also have to close gaps left by a rebuilt blob.
    fn patch_command_offsets(&mut self) -> Result<(), Error> {
        let Some(offset) = self.find_command(LC_MAIN) else {
            return Ok(());
        };
        // entryoff is measured from the header, so it tracks the code rather
        // than the file layout.
        let entryoff = read_u64(&self.data, offset + 8)?;
        let shifted = self.shift_off(entryoff)?;
        write_u64(&mut self.data, offset + 8, shifted)
    }

    // -------------------------------------------------------------- linkedit

    fn collect_linkedit_blobs(&mut self) -> Result<(), Error> {
        let mut blobs = Vec::new();
        for (cmd, _, offset) in &self.commands {
            let offset = *offset;
            match *cmd {
                LC_FUNCTION_STARTS
                | LC_DATA_IN_CODE
                | LC_CODE_SIGNATURE
                | LC_DYLD_EXPORTS_TRIE
                | LC_DYLD_CHAINED_FIXUPS
                | LC_DYLIB_CODE_SIGN_DRS
                | LC_ATOM_INFO
                | LC_LINKER_OPTIMIZATION_HINT
                | LC_FUNCTION_VARIANTS
                | LC_FUNCTION_VARIANT_FIXUPS => {
                    let dataoff = read_u32(&self.data, offset + 8)? as u64;
                    let datasize = read_u32(&self.data, offset + 12)? as usize;
                    if datasize == 0 {
                        continue;
                    }
                    blobs.push(LinkeditBlob {
                        off_field: offset + 8,
                        size_field: Some(offset + 12),
                        old_off: dataoff,
                        size: datasize,
                        replacement: None,
                        is_signature: *cmd == LC_CODE_SIGNATURE,
                    });
                }
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    // rebase, bind, weak bind, lazy bind, export
                    for pair in 0..5 {
                        let at = offset + 8 + pair * 8;
                        let dataoff = read_u32(&self.data, at)? as u64;
                        let datasize = read_u32(&self.data, at + 4)? as usize;
                        if datasize == 0 {
                            continue;
                        }
                        blobs.push(LinkeditBlob {
                            off_field: at,
                            size_field: Some(at + 4),
                            old_off: dataoff,
                            size: datasize,
                            replacement: None,
                            is_signature: false,
                        });
                    }
                }
                LC_SYMTAB => {
                    let symoff = read_u32(&self.data, offset + 8)? as u64;
                    let nsyms = read_u32(&self.data, offset + 12)? as usize;
                    let stroff = read_u32(&self.data, offset + 16)? as u64;
                    let strsize = read_u32(&self.data, offset + 20)? as usize;
                    if nsyms != 0 {
                        blobs.push(LinkeditBlob {
                            off_field: offset + 8,
                            size_field: None,
                            old_off: symoff,
                            size: nsyms * size_of::<Nlist64>(),
                            replacement: None,
                            is_signature: false,
                        });
                    }
                    if strsize != 0 {
                        blobs.push(LinkeditBlob {
                            off_field: offset + 16,
                            size_field: None,
                            old_off: stroff,
                            size: strsize,
                            replacement: None,
                            is_signature: false,
                        });
                    }
                }
                LC_DYSYMTAB => {
                    // Only the indirect symbol table carries content that a
                    // relayout has to keep contiguous; the rest are unused in
                    // linked images and are shifted in patch_command_offsets.
                    let indirectsymoff = read_u32(&self.data, offset + 56)? as u64;
                    let nindirectsyms = read_u32(&self.data, offset + 60)? as usize;
                    if nindirectsyms != 0 {
                        blobs.push(LinkeditBlob {
                            off_field: offset + 56,
                            size_field: None,
                            old_off: indirectsymoff,
                            size: nindirectsyms * 4,
                            replacement: None,
                            is_signature: false,
                        });
                    }
                }
                _ => {}
            }
        }

        for blob in &blobs {
            slice(&self.data, blob.old_off as usize, blob.size)?;
        }
        blobs.sort_by_key(|b| b.old_off);

        // The relayout rewrites __LINKEDIT from the blobs alone, so anything
        // in there that no load command describes would be dropped. The gaps
        // between blobs are alignment padding, so require them to be exactly
        // that: shorter than the widest alignment in play, and all zero. That
        // is proof there is nothing to lose, rather than a tolerance.
        const MAX_ALIGN: u64 = 16;
        let seg = &self.segments[self.linkedit_index].seg;
        let linkedit_end = seg
            .fileoff
            .checked_add(seg.filesize)
            .ok_or_else(|| invalid("__LINKEDIT range overflows"))?;
        let mut cursor = seg.fileoff;

        let unaccounted = || {
            invalid(
                "Cannot grow the load commands: __LINKEDIT holds data no load command describes",
            )
        };

        for blob in blobs.iter().chain(std::iter::once(&LinkeditBlob {
            off_field: 0,
            size_field: None,
            old_off: linkedit_end,
            size: 0,
            replacement: None,
            is_signature: false,
        })) {
            if blob.old_off < cursor {
                return Err(invalid(
                    "Cannot grow the load commands: __LINKEDIT blobs overlap",
                ));
            }
            let gap = blob.old_off - cursor;
            if gap >= MAX_ALIGN {
                return Err(unaccounted());
            }
            if !slice(&self.data, cursor as usize, gap as usize)?
                .iter()
                .all(|byte| *byte == 0)
            {
                return Err(unaccounted());
            }
            cursor = blob
                .old_off
                .checked_add(blob.size as u64)
                .ok_or_else(|| invalid("__LINKEDIT blob range overflows"))?;
        }

        self.blobs = blobs;
        Ok(())
    }

    /// Write `__LINKEDIT` back out, packing the blobs in their original order.
    ///
    /// Everything simply slides by `width` unless a blob was rebuilt at a
    /// different size, in which case the ones after it close up behind it.
    fn relayout_linkedit(&mut self) -> Result<(), Error> {
        let linkedit_start = self.segments[self.linkedit_index].seg.fileoff;

        let mut contents: Vec<u8> = Vec::new();
        let mut new_offsets: Vec<(usize, Option<usize>, u64, usize)> = Vec::new();

        for blob in &self.blobs {
            // Blobs are 8-byte aligned by the linker; the code signature has
            // to land on 16 so the kernel accepts it.
            let alignment = if blob.is_signature { 16 } else { 8 };
            let pad = align(contents.len() as u64, alignment) as usize - contents.len();
            contents.resize(contents.len() + pad, 0);

            let new_off = linkedit_start + contents.len() as u64;
            let bytes: &[u8] = match &blob.replacement {
                Some(replacement) => replacement,
                None => {
                    // The gap was opened before __LINKEDIT, so the original
                    // bytes now start `width` further into the buffer.
                    let start = (blob.old_off + self.width) as usize;
                    self.data
                        .get(start..start + blob.size)
                        .ok_or_else(|| invalid("Truncated __LINKEDIT"))?
                }
            };
            new_offsets.push((blob.off_field, blob.size_field, new_off, bytes.len()));
            contents.extend_from_slice(bytes);
        }

        let linkedit_size = contents.len() as u64;
        self.data.truncate(linkedit_start as usize);
        self.data.extend_from_slice(&contents);

        for (off_field, size_field, new_off, size) in new_offsets {
            let value =
                u32::try_from(new_off).map_err(|_| invalid("Mach-O file would exceed 4 GiB"))?;
            write_u32(&mut self.data, off_field, value)?;
            if let Some(size_field) = size_field {
                write_u32(&mut self.data, size_field, size as u32)?;
            }
        }

        let cmd_offset = self.segments[self.linkedit_index].cmd_offset;
        let mut seg = self.segments[self.linkedit_index].seg.clone();
        seg.filesize = linkedit_size;
        seg.vmsize = align(linkedit_size, 0x4000);
        write_at(&mut self.data, cmd_offset, seg.as_bytes())?;
        self.segments[self.linkedit_index].seg = seg;

        Ok(())
    }

    fn find_command(&self, want: u32) -> Option<usize> {
        self.commands
            .iter()
            .find(|(cmd, _, _)| *cmd == want)
            .map(|(_, _, offset)| *offset)
    }

    fn blob_mut(&mut self, off_field: usize) -> Option<&mut LinkeditBlob> {
        self.blobs.iter_mut().find(|b| b.off_field == off_field)
    }

    // --------------------------------------------------------------- symbols

    /// Symbol addresses are absolute virtual addresses, so they move with the
    /// code they name.
    fn patch_symbol_table(&mut self) -> Result<(), Error> {
        let Some(offset) = self.find_command(LC_SYMTAB) else {
            return Ok(());
        };
        let symoff = read_u32(&self.data, offset + 8)? as usize;
        let nsyms = read_u32(&self.data, offset + 12)? as usize;

        for index in 0..nsyms {
            let at = symoff + index * size_of::<Nlist64>();
            let mut sym = Nlist64::read_from_prefix(slice(&self.data, at, size_of::<Nlist64>())?)
                .ok_or_else(|| invalid("Truncated symbol table"))?;

            let carries_address = if sym.n_type & N_STAB != 0 {
                // Debug map entries reuse n_value for other things: N_OSO
                // stores a timestamp, and the closing N_FUN of a pair stores
                // the function's length. Both have n_sect == 0, which is the
                // only thing separating them from a real address — in a dylib
                // the image base is 0, so the range check below rules nothing
                // out. Do not drop this test.
                sym.n_sect != 0
            } else {
                // N_TYPE is the mask, N_SECT the value; they happen to share
                // the bit pattern 0x0e.
                sym.n_type & N_TYPE == N_SECT
            };

            if carries_address && sym.n_value >= self.lc_end_va {
                sym.n_value = self.moved(sym.n_value, 0)?;
                write_at(&mut self.data, at, sym.as_bytes())?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ data links

    fn patch_data_in_code(&mut self) -> Result<(), Error> {
        let Some(offset) = self.find_command(LC_DATA_IN_CODE) else {
            return Ok(());
        };
        let dataoff = read_u32(&self.data, offset + 8)? as usize;
        let datasize = read_u32(&self.data, offset + 12)? as usize;

        // struct data_in_code_entry { uint32_t offset; uint16_t length; uint16_t kind; }
        for at in (dataoff..dataoff + datasize).step_by(8) {
            let value = read_u32(&self.data, at)? as u64;
            let shifted = u32::try_from(self.shift_off(value)?)
                .map_err(|_| invalid("Mach-O file would exceed 4 GiB"))?;
            write_u32(&mut self.data, at, shifted)?;
        }
        Ok(())
    }

    /// `LC_FUNCTION_STARTS` is a ULEB128 delta list; only the first entry is
    /// anchored to the image base.
    fn rebuild_function_starts(&mut self) -> Result<(), Error> {
        let Some(offset) = self.find_command(LC_FUNCTION_STARTS) else {
            return Ok(());
        };
        let dataoff = read_u32(&self.data, offset + 8)? as usize;
        let datasize = read_u32(&self.data, offset + 12)? as usize;
        if datasize == 0 {
            return Ok(());
        }

        let (first, first_len) = read_uleb(&self.data, dataoff)?;
        if first == 0 {
            return Ok(());
        }
        let shifted = self.shift_off(first)?;

        let mut rebuilt = Vec::with_capacity(datasize);
        // Keep the encoding the same width when the value still fits, so the
        // blob keeps its size and nothing behind it has to move.
        let new_len = uleb_len(shifted).max(first_len);
        write_uleb_padded(&mut rebuilt, shifted, new_len);
        let tail_len = datasize
            .checked_sub(first_len)
            .ok_or_else(|| invalid("Malformed LC_FUNCTION_STARTS"))?;
        rebuilt.extend_from_slice(slice(&self.data, dataoff + first_len, tail_len)?);

        // The linker pads the blob to an 8-byte boundary; spend that padding
        // before growing the blob.
        let grew = new_len - first_len;
        if grew > 0 && rebuilt[datasize..].iter().all(|b| *b == 0) {
            rebuilt.truncate(datasize);
        }

        self.blob_mut(offset + 8)
            .ok_or_else(|| invalid("Missing LC_FUNCTION_STARTS blob"))?
            .replacement = Some(rebuilt);
        Ok(())
    }

    // ----------------------------------------------------------- unwind info

    /// `__unwind_info` indexes functions by their offset from the image base.
    fn patch_unwind_info(&mut self) -> Result<(), Error> {
        let Some((sect_off, sect_size)) = self.find_section(b"__unwind_info")? else {
            return Ok(());
        };
        let base = sect_off as usize;

        let version = read_u32(&self.data, base)?;
        if version != 1 {
            return Err(invalid("Unsupported __unwind_info version"));
        }
        let personality_off = read_u32(&self.data, base + 12)? as usize;
        let personality_count = read_u32(&self.data, base + 16)? as usize;
        let index_off = read_u32(&self.data, base + 20)? as usize;
        let index_count = read_u32(&self.data, base + 24)? as usize;

        let sect_size = sect_size as usize;
        let within = |at: usize, len: usize| -> Result<(), Error> {
            match at.checked_add(len) {
                Some(end) if end <= sect_size => Ok(()),
                _ => Err(invalid("Malformed __unwind_info")),
            }
        };
        within(index_off, index_count.saturating_mul(12))?;
        within(personality_off, personality_count.saturating_mul(4))?;

        // Personality entries point at the GOT slot holding the routine.
        for i in 0..personality_count {
            self.shift_u32_off(base + personality_off + i * 4)?;
        }

        let mut pages = Vec::with_capacity(index_count);
        for i in 0..index_count {
            let entry = base + index_off + i * 12;
            let second_level = read_u32(&self.data, entry + 4)? as usize;
            let lsda_start = read_u32(&self.data, entry + 8)? as usize;
            pages.push((second_level, lsda_start));
            // functionOffset — the sentinel entry has one too.
            self.shift_u32_off(entry)?;
        }

        // The LSDA array spans from the first index entry's start to the last.
        for window in pages.windows(2) {
            let (_, start) = window[0];
            let (_, end) = window[1];
            if end < start || end > sect_size {
                return Err(invalid("Malformed __unwind_info LSDA index"));
            }
            for at in (base + start..base + end).step_by(8) {
                self.shift_u32_off(at)?; // functionOffset
                self.shift_u32_off(at + 4)?; // lsdaOffset
            }
        }

        for (second_level, _) in &pages {
            if *second_level == 0 {
                continue; // sentinel entry
            }
            within(*second_level, 8)?;
            let page = base + second_level;
            let kind = read_u32(&self.data, page)?;
            match kind {
                2 => {
                    // Regular page: absolute function offsets.
                    let entry_off = read_u16(&self.data, page + 4)? as usize;
                    let entry_count = read_u16(&self.data, page + 6)? as usize;
                    within(second_level + entry_off, entry_count.saturating_mul(8))?;
                    for i in 0..entry_count {
                        self.shift_u32_off(page + entry_off + i * 8)?;
                    }
                }
                // Compressed pages store 24-bit offsets relative to the index
                // entry's functionOffset, which has already been moved.
                3 => {}
                _ => return Err(invalid("Unsupported __unwind_info page kind")),
            }
        }

        Ok(())
    }

    fn shift_u32_off(&mut self, at: usize) -> Result<(), Error> {
        let value = read_u32(&self.data, at)? as u64;
        if value == 0 {
            return Ok(());
        }
        let shifted = u32::try_from(self.shift_off(value)?)
            .map_err(|_| invalid("Mach-O file would exceed 4 GiB"))?;
        write_u32(&mut self.data, at, shifted)
    }

    // ---------------------------------------------------------- classic dyld

    /// Patch the pointers that `LC_DYLD_INFO` rebase opcodes point at.
    ///
    /// The opcode stream itself is expressed as (segment, offset) pairs and so
    /// survives the shift untouched, but each slot it names holds a link-time
    /// absolute address that has to move with its target.
    fn patch_rebase_targets(&mut self) -> Result<(), Error> {
        let Some(offset) = self
            .find_command(LC_DYLD_INFO_ONLY)
            .or_else(|| self.find_command(LC_DYLD_INFO))
        else {
            return Ok(());
        };

        let rebase_off = read_u32(&self.data, offset + 8)? as usize;
        let rebase_size = read_u32(&self.data, offset + 12)? as usize;
        if rebase_size == 0 {
            return Ok(());
        }

        const DONE: u8 = 0x00;
        const SET_TYPE_IMM: u8 = 0x10;
        const SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
        const ADD_ADDR_ULEB: u8 = 0x30;
        const ADD_ADDR_IMM_SCALED: u8 = 0x40;
        const DO_REBASE_IMM_TIMES: u8 = 0x50;
        const DO_REBASE_ULEB_TIMES: u8 = 0x60;
        const DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
        const DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;
        const REBASE_TYPE_POINTER: u64 = 1;

        let mut slots: Vec<u64> = Vec::new();
        let mut seg_index = usize::MAX;
        let mut seg_offset = 0u64;
        let mut kind = REBASE_TYPE_POINTER;
        let mut at = rebase_off;
        let end = rebase_off + rebase_size;

        // Validating each slot here bounds `slots`: a bogus repeat count runs
        // off the end of the file within a few iterations instead of pushing
        // billions of entries.
        let push = |slots: &mut Vec<u64>, seg_index: usize, seg_offset: u64| -> Result<(), Error> {
            let seg = self
                .segments
                .get(seg_index)
                .ok_or_else(|| invalid("Rebase opcode names an unknown segment"))?;
            let slot = seg
                .old_fileoff
                .checked_add(seg_offset)
                .ok_or_else(|| invalid("Rebase offset overflows"))?;
            slice(&self.data, slot as usize, 8)?;
            slots.push(slot);
            Ok(())
        };

        // Every advance of the cursor comes from the file, so none of them can
        // be trusted not to wrap.
        fn advance(offset: u64, by: u64) -> Result<u64, Error> {
            offset
                .checked_add(by)
                .ok_or_else(|| invalid("Rebase offset overflows"))
        }

        while at < end {
            let byte = *self
                .data
                .get(at)
                .ok_or_else(|| invalid("Truncated rebase opcodes"))?;
            at += 1;
            let opcode = byte & 0xf0;
            let imm = (byte & 0x0f) as u64;
            match opcode {
                DONE => break,
                SET_TYPE_IMM => kind = imm,
                SET_SEGMENT_AND_OFFSET_ULEB => {
                    let (value, len) = read_uleb(&self.data, at)?;
                    at += len;
                    seg_index = imm as usize;
                    seg_offset = value;
                }
                ADD_ADDR_ULEB => {
                    let (value, len) = read_uleb(&self.data, at)?;
                    at += len;
                    seg_offset = advance(seg_offset, value)?;
                }
                ADD_ADDR_IMM_SCALED => seg_offset = advance(seg_offset, imm * 8)?,
                DO_REBASE_IMM_TIMES | DO_REBASE_ULEB_TIMES => {
                    let count = if opcode == DO_REBASE_IMM_TIMES {
                        imm
                    } else {
                        let (value, len) = read_uleb(&self.data, at)?;
                        at += len;
                        value
                    };
                    if kind != REBASE_TYPE_POINTER {
                        return Err(invalid("Unsupported rebase type"));
                    }
                    for _ in 0..count {
                        push(&mut slots, seg_index, seg_offset)?;
                        seg_offset = advance(seg_offset, 8)?;
                    }
                }
                DO_REBASE_ADD_ADDR_ULEB => {
                    let (value, len) = read_uleb(&self.data, at)?;
                    at += len;
                    if kind != REBASE_TYPE_POINTER {
                        return Err(invalid("Unsupported rebase type"));
                    }
                    push(&mut slots, seg_index, seg_offset)?;
                    seg_offset = advance(seg_offset, advance(8, value)?)?;
                }
                DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                    let (count, len) = read_uleb(&self.data, at)?;
                    at += len;
                    let (skip, len) = read_uleb(&self.data, at)?;
                    at += len;
                    if kind != REBASE_TYPE_POINTER {
                        return Err(invalid("Unsupported rebase type"));
                    }
                    let stride = advance(8, skip)?;
                    for _ in 0..count {
                        push(&mut slots, seg_index, seg_offset)?;
                        seg_offset = advance(seg_offset, stride)?;
                    }
                }
                _ => return Err(invalid("Unknown rebase opcode")),
            }
        }

        for slot in slots {
            let value = read_u64(&self.data, slot as usize)?;
            if value >= self.lc_end_va {
                let moved = self.moved(value, 0)?;
                write_u64(&mut self.data, slot as usize, moved)?;
            }
        }
        Ok(())
    }

    // -------------------------------------------------------- chained fixups

    /// Patch `LC_DYLD_CHAINED_FIXUPS`: the per-segment anchors and the rebase
    /// target packed into every pointer in the chains.
    fn patch_chained_fixups(&mut self) -> Result<(), Error> {
        let Some(offset) = self.find_command(LC_DYLD_CHAINED_FIXUPS) else {
            return Ok(());
        };
        let dataoff = read_u32(&self.data, offset + 8)? as usize;
        let datasize = read_u32(&self.data, offset + 12)? as usize;
        if datasize == 0 {
            return Ok(());
        }

        const DYLD_CHAINED_PTR_64: u16 = 2;
        const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
        const START_NONE: u16 = 0xffff;
        const START_MULTI: u16 = 0x8000;

        let fixups_version = read_u32(&self.data, dataoff)?;
        if fixups_version != 0 {
            return Err(invalid("Unsupported chained fixups version"));
        }
        let starts_offset = read_u32(&self.data, dataoff + 4)? as usize;
        let starts = dataoff + starts_offset;
        let seg_count = read_u32(&self.data, starts)? as usize;

        for index in 0..seg_count {
            let info_offset = read_u32(&self.data, starts + 4 + index * 4)? as usize;
            if info_offset == 0 {
                continue; // segment carries no fixups
            }
            let info = starts + info_offset;

            let page_size = read_u16(&self.data, info + 4)?;
            let pointer_format = read_u16(&self.data, info + 6)?;
            // struct dyld_chained_starts_in_segment {
            //   u32 size; u16 page_size; u16 pointer_format; u64 segment_offset;
            //   u32 max_valid_pointer; u16 page_count; u16 page_start[];
            // }
            let segment_offset = read_u64(&self.data, info + 8)?;
            let page_count = read_u16(&self.data, info + 20)? as usize;

            if pointer_format != DYLD_CHAINED_PTR_64 && pointer_format != DYLD_CHAINED_PTR_64_OFFSET
            {
                return Err(invalid("Unsupported chained pointer format"));
            }

            let seg = self
                .segments
                .get(index)
                .ok_or_else(|| invalid("Chained fixups name an unknown segment"))?;
            let seg_fileoff = seg.old_fileoff;

            // segment_offset is measured from the image base.
            let shifted_segment_offset = self.shift_off(segment_offset)?;
            write_u64(&mut self.data, info + 8, shifted_segment_offset)?;

            for page in 0..page_count {
                let at = info + 22 + page * 2;
                let start = read_u16(&self.data, at)?;
                if start == START_NONE {
                    continue;
                }
                if start & START_MULTI != 0 {
                    return Err(invalid("Unsupported chained fixups page layout"));
                }

                let mut chain = (seg_fileoff as usize)
                    .checked_add(page * page_size as usize)
                    .and_then(|c| c.checked_add(start as usize))
                    .ok_or_else(|| invalid("Chained fixup page out of range"))?;
                loop {
                    let value = read_u64(&self.data, chain)?;
                    let is_bind = value >> 63 & 1 == 1;
                    let next = (value >> 51 & 0xfff) as usize;

                    if !is_bind {
                        let target = value & 0xf_ffff_ffff;
                        let shifted = if pointer_format == DYLD_CHAINED_PTR_64_OFFSET {
                            self.shift_off(target)?
                        } else {
                            self.shift_va(target)?
                        };
                        if shifted != target {
                            let rest = value & !0xf_ffff_ffff;
                            write_u64(&mut self.data, chain, rest | shifted)?;
                        }
                    }

                    if next == 0 {
                        break;
                    }
                    chain = chain
                        .checked_add(next * 4)
                        .ok_or_else(|| invalid("Chained fixup runs off the image"))?;
                }
            }
        }
        Ok(())
    }

    // ----------------------------------------------------------- export trie

    /// Rebuild the export trie with image-base-relative addresses moved.
    ///
    /// The addresses are ULEB128, so widening one shifts every byte behind it
    /// and invalidates the node offsets threaded through the trie. The tree is
    /// therefore parsed, patched and re-emitted, keeping its original shape.
    fn rebuild_export_trie(&mut self) -> Result<(), Error> {
        let (off_field, dataoff, datasize) =
            if let Some(offset) = self.find_command(LC_DYLD_EXPORTS_TRIE) {
                (
                    offset + 8,
                    read_u32(&self.data, offset + 8)? as usize,
                    read_u32(&self.data, offset + 12)? as usize,
                )
            } else if let Some(offset) = self
                .find_command(LC_DYLD_INFO_ONLY)
                .or_else(|| self.find_command(LC_DYLD_INFO))
            {
                (
                    offset + 40,
                    read_u32(&self.data, offset + 40)? as usize,
                    read_u32(&self.data, offset + 44)? as usize,
                )
            } else {
                return Ok(());
            };

        if datasize == 0 {
            return Ok(());
        }

        let trie = slice(&self.data, dataoff, datasize)?;
        let mut nodes = parse_trie(trie)?;

        for node in &mut nodes {
            if let Some(payload) = node.terminal.take() {
                node.terminal = Some(self.patch_export_payload(&payload)?);
            }
        }

        let rebuilt = emit_trie(&nodes)?;
        self.blob_mut(off_field)
            .ok_or_else(|| invalid("Missing export trie blob"))?
            .replacement = Some(rebuilt);
        Ok(())
    }

    /// Move the addresses inside one export trie terminal payload.
    fn patch_export_payload(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        const KIND_MASK: u64 = 0x03;
        const KIND_ABSOLUTE: u64 = 0x02;
        const REEXPORT: u64 = 0x08;
        const STUB_AND_RESOLVER: u64 = 0x10;

        let (flags, flags_len) = read_uleb(payload, 0)?;
        let mut out = Vec::with_capacity(payload.len() + 2);
        encode_uleb(&mut out, flags);
        let mut at = flags_len;

        if flags & REEXPORT != 0 {
            // Ordinal plus an optional renamed symbol — no addresses at all.
            out.extend_from_slice(payload.get(at..).unwrap_or_default());
            return Ok(out);
        }

        let (address, len) = read_uleb(payload, at)?;
        at += len;
        // An absolute export names a fixed address rather than a place in the
        // image, so it stays where it is.
        let moved = if flags & KIND_MASK == KIND_ABSOLUTE {
            address
        } else {
            self.shift_off(address)?
        };
        encode_uleb(&mut out, moved);

        if flags & STUB_AND_RESOLVER != 0 {
            let (resolver, len) = read_uleb(payload, at)?;
            at += len;
            encode_uleb(&mut out, self.shift_off(resolver)?);
        }

        out.extend_from_slice(payload.get(at..).unwrap_or_default());
        Ok(out)
    }

    /// Locate a section by name across all segments, returning its file offset
    /// and size.
    fn find_section(&self, name: &[u8]) -> Result<Option<(u64, u64)>, Error> {
        for seg in &self.segments {
            let mut sect_offset = seg.cmd_offset + size_of::<SegmentCommand64>();
            for _ in 0..seg.seg.nsects {
                let sect = Section64::read_from_prefix(slice(
                    &self.data,
                    sect_offset,
                    size_of::<Section64>(),
                )?)
                .ok_or_else(|| invalid("Failed to read section"))?;
                let sect_name = &sect.sectname[..name.len()];
                let terminated = sect.sectname.get(name.len()).is_none_or(|b| *b == 0);
                if sect_name == name && terminated && sect.offset != 0 {
                    // Validate here so every caller can walk the section
                    // without re-checking each step against the file.
                    slice(&self.data, sect.offset as usize, sect.size as usize)?;
                    return Ok(Some((sect.offset as u64, sect.size)));
                }
                sect_offset += size_of::<Section64>();
            }
        }
        Ok(None)
    }
}

/// One node of an export trie, kept in the shape the original had.
#[derive(Default)]
struct TrieNode {
    /// Terminal payload, already patched. `None` for a non-terminal node.
    terminal: Option<Vec<u8>>,
    /// `(edge string, index into the node list)`.
    children: Vec<(Vec<u8>, usize)>,
}

/// Parse an export trie into a flat node list, root first.
fn parse_trie(trie: &[u8]) -> Result<Vec<TrieNode>, Error> {
    use std::collections::HashMap;

    let mut nodes: Vec<TrieNode> = vec![TrieNode::default()];
    let mut index_of: HashMap<usize, usize> = HashMap::new();
    index_of.insert(0, 0);
    let mut queue = vec![0usize];

    while let Some(node_off) = queue.pop() {
        let index = index_of[&node_off];

        let (terminal_size, len) = read_uleb(trie, node_off)?;
        let mut at = node_off + len;

        let terminal = if terminal_size > 0 {
            let end = at
                .checked_add(terminal_size as usize)
                .ok_or_else(|| invalid("Malformed export trie"))?;
            let payload = trie
                .get(at..end)
                .ok_or_else(|| invalid("Malformed export trie"))?
                .to_vec();
            at = end;
            Some(payload)
        } else {
            None
        };

        let child_count = *trie
            .get(at)
            .ok_or_else(|| invalid("Malformed export trie"))?;
        at += 1;

        let mut children = Vec::with_capacity(child_count as usize);
        for _ in 0..child_count {
            let start = at;
            while *trie
                .get(at)
                .ok_or_else(|| invalid("Malformed export trie"))?
                != 0
            {
                at += 1;
            }
            let edge = trie[start..at].to_vec();
            at += 1;

            let (child_off, len) = read_uleb(trie, at)?;
            at += len;
            let child_off = child_off as usize;
            if child_off >= trie.len() {
                return Err(invalid("Export trie child out of range"));
            }

            let child_index = match index_of.get(&child_off) {
                Some(index) => *index,
                None => {
                    let index = nodes.len();
                    nodes.push(TrieNode::default());
                    index_of.insert(child_off, index);
                    queue.push(child_off);
                    index
                }
            };
            children.push((edge, child_index));
        }

        nodes[index].terminal = terminal;
        nodes[index].children = children;
    }

    Ok(nodes)
}

fn trie_node_size(node: &TrieNode, offsets: &[usize]) -> usize {
    let terminal_size = node.terminal.as_ref().map_or(0, |t| t.len());
    let mut size = uleb_len(terminal_size as u64) + terminal_size + 1;
    for (edge, child) in &node.children {
        size += edge.len() + 1 + uleb_len(offsets[*child] as u64);
    }
    size
}

/// Re-emit a parsed trie.
///
/// Node offsets are ULEB128 and point forward into the blob, so a node's size
/// depends on where the nodes after it land. Sizes only ever grow as offsets
/// grow, so iterating to a fixed point converges.
fn emit_trie(nodes: &[TrieNode]) -> Result<Vec<u8>, Error> {
    let mut offsets = vec![0usize; nodes.len()];
    let mut sizes: Vec<usize> = nodes.iter().map(|n| trie_node_size(n, &offsets)).collect();

    for _ in 0..32 {
        let mut cursor = 0;
        for index in 0..nodes.len() {
            offsets[index] = cursor;
            cursor += sizes[index];
        }

        let mut changed = false;
        for index in 0..nodes.len() {
            let size = trie_node_size(&nodes[index], &offsets);
            if size != sizes[index] {
                sizes[index] = size;
                changed = true;
            }
        }

        if !changed {
            let mut out = Vec::with_capacity(cursor);
            for node in nodes {
                let terminal_size = node.terminal.as_ref().map_or(0, |t| t.len());
                encode_uleb(&mut out, terminal_size as u64);
                if let Some(payload) = &node.terminal {
                    out.extend_from_slice(payload);
                }
                out.push(node.children.len() as u8);
                for (edge, child) in &node.children {
                    out.extend_from_slice(edge);
                    out.push(0);
                    encode_uleb(&mut out, offsets[*child] as u64);
                }
            }
            return Ok(out);
        }
    }

    Err(invalid("Export trie layout did not converge"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `LC_DYLD_INFO` rebase opcodes and an export trie inside dyld info.
    const CLASSIC: &[u8] = include_bytes!("tests/exec_mach64");
    /// `LC_DYLD_CHAINED_FIXUPS` and a standalone `LC_DYLD_EXPORTS_TRIE`.
    const CHAINED: &[u8] = include_bytes!("tests/exec_mach64_chained");

    /// Corrupted input must come back as an error, never a panic or a hang.
    ///
    /// `shift` walks rebase opcodes, chained fixup chains, an export trie,
    /// unwind tables and a symbol table, all driven by offsets and counts read
    /// straight out of the file. Every one of those is a place a bad image
    /// could walk off the end, so sweep byte flips across the header and load
    /// commands and require a clean result each time.
    #[test]
    fn corrupted_images_error_rather_than_panic() {
        for original in [CLASSIC, CHAINED] {
            // xorshift64, so the sweep is identical on every run.
            let mut state = 0x2545_f491_4f6c_dd1du64;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };

            // Retyping a command now and then steers the sweep into walkers
            // the fixture would not otherwise reach.
            const RETYPE: [u32; 4] = [
                LC_DYLD_CHAINED_FIXUPS,
                LC_DYLD_EXPORTS_TRIE,
                LC_FUNCTION_STARTS,
                LC_DATA_IN_CODE,
            ];

            let mut errors = 0;
            for round in 0..2000 {
                let mut obj = original.to_vec();

                if round % 4 == 0 {
                    // Land on a load command boundary so the retype means
                    // something.
                    let mut at = size_of::<Header64>();
                    for _ in 0..next() % 12 {
                        let cmdsize = read_u32(&obj, at + 4).unwrap_or(8).max(8) as usize;
                        match at.checked_add(cmdsize) {
                            Some(n) if n + 8 <= obj.len() => at = n,
                            _ => break,
                        }
                    }
                    let cmd = RETYPE[(next() % RETYPE.len() as u64) as usize];
                    obj[at..at + 4].copy_from_slice(&cmd.to_le_bytes());
                }

                for _ in 0..1 + next() % 8 {
                    // Bias at the header and load commands, where the walkers
                    // pick up every offset they trust.
                    let at = (next() as usize) % obj.len().min(4096);
                    obj[at] = next() as u8;
                }
                if shift(obj, 0x4000).is_err() {
                    errors += 1;
                }
            }

            // The sweep is only meaningful if it reached failure paths.
            assert!(errors > 0, "no corruption was detected at all");
        }
    }

    /// The same images untouched must still shift cleanly, so the sweep above
    /// cannot pass by rejecting everything.
    ///
    /// `shift` runs [`Shifter::verify`] before returning, so success already
    /// asserts the segments stayed inside the file, kept their page alignment,
    /// left no bytes outside any segment, and that `__TEXT` still covers the
    /// grown load command region.
    #[test]
    fn intact_images_shift() {
        for original in [CLASSIC, CHAINED] {
            let shifted = shift(original.to_vec(), 0x4000).expect("a well-formed image must shift");

            let header = Header64::read_from_prefix(&shifted[..]).unwrap();
            let lc_end = size_of::<Header64>() + header.sizeofcmds as usize;
            assert!(
                shifted[lc_end..lc_end + 0x4000].iter().all(|b| *b == 0),
                "the freed header padding should be zeroed"
            );
        }
    }

    /// A shifted image must not keep claiming the `.dSYM` built for the
    /// original, whose addresses no longer describe it.
    #[test]
    fn shifting_retires_the_uuid() {
        let uuid = |obj: &[u8]| -> Option<[u8; 16]> {
            let header = Header64::read_from_prefix(obj)?;
            let mut offset = size_of::<Header64>();
            for _ in 0..header.ncmds {
                let cmd = read_u32(obj, offset).ok()?;
                let cmdsize = read_u32(obj, offset + 4).ok()? as usize;
                if cmd == LC_UUID {
                    return obj[offset + 8..offset + 24].try_into().ok();
                }
                offset += cmdsize;
            }
            None
        };

        for original in [CLASSIC, CHAINED] {
            let before = uuid(original).expect("fixture should carry an LC_UUID");
            let shifted = shift(original.to_vec(), 0x4000).unwrap();
            let after = uuid(&shifted).unwrap();
            assert_ne!(before, after, "a shifted image kept its original UUID");
            // Same input, same output: builds stay reproducible.
            let again = shift(original.to_vec(), 0x4000).unwrap();
            assert_eq!(shifted, again, "shifting is not deterministic");
        }
    }
}
