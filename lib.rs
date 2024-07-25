/*
 * "Sui: embed and extract auxillary data from binaries"
 *
 * Copyright (c) 2024 Divy Srivastava
 * Copyright (c) 2024 the Deno authors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

//! Sui is a library for embedding and extracting auxillary data from binary files.
//!
//! # Examples
//!
//! Embedding data in a Mach-O binary:
//! ```rust
//! use libsui::Macho;
//! use std::fs::File;
//!
//! # fn main() -> Result<(), libsui::Error> {
//! let data = b"Hello, world!";
//! let exe = std::fs::read("tests/exec_mach64")?;
//! let mut out = File::create("tests/out")?;
//!
//! Macho::from(exe)?
//!     .write_section("__SECTION", data.to_vec())?
//!     .build(&mut out)?;
//! #     Ok(())
//! # }
//! ```

use core::mem::size_of;
use editpe::{
    constants::{LANGUAGE_ID_EN_US, RT_RCDATA},
    ResourceEntry, ResourceEntryName, ResourceTable,
};
use std::io::Write;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub mod apple_codesign;

#[cfg(target_os = "linux")]
pub use elf::find_section;
#[cfg(target_os = "macos")]
pub use macho::find_section;
#[cfg(target_os = "windows")]
pub use pe::find_section;

#[derive(Debug)]
pub enum Error {
    InvalidObject(&'static str),
    InternalError,
    IoError(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidObject(msg) => write!(f, "Invalid object: {}", msg),
            Error::InternalError => write!(f, "Internal error"),
            Error::IoError(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}

impl std::error::Error for Error {}

/// A portable executable (PE)
///
/// Build a new PE from existing PE and write auxillary data as
/// a resource in the .rsrc section.
pub struct PortableExecutable<'a> {
    image: editpe::Image<'a>,
}

impl<'a> PortableExecutable<'a> {
    /// Parse from a PE file
    pub fn from(data: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            image: editpe::Image::parse(data)
                .map_err(|_| Error::InvalidObject("Failed to parse PE"))?,
        })
    }

    /// Write a resource to the PE file
    pub fn write_resource(mut self, name: &str, sectdata: Vec<u8>) -> Result<Self, Error> {
        let mut resources = editpe::ResourceDirectory::default();
        let root = resources.root_mut();
        if root.get(ResourceEntryName::ID(RT_RCDATA as u32)).is_none() {
            root.insert(
                ResourceEntryName::ID(RT_RCDATA as u32),
                ResourceEntry::Table(ResourceTable::default()),
            );
        }
        let rc_table = match root
            .get_mut(ResourceEntryName::ID(RT_RCDATA as u32))
            .unwrap()
        {
            ResourceEntry::Table(table) => table,
            ResourceEntry::Data(_) => {
                return Err(Error::InvalidObject("RCDATA is not a table"));
            }
        };
        let name = name.to_uppercase();
        rc_table.insert(
            editpe::ResourceEntryName::from_string(name.clone()),
            ResourceEntry::Table(ResourceTable::default()),
        );

        let rc_table = match rc_table
            .get_mut(editpe::ResourceEntryName::from_string(name))
            .unwrap()
        {
            ResourceEntry::Table(table) => table,
            ResourceEntry::Data(_) => {
                return Err(Error::InvalidObject("Resource entry is not a table"));
            }
        };
        let mut entry = editpe::ResourceData::default();
        entry.set_data(sectdata);

        rc_table.insert(
            ResourceEntryName::ID(LANGUAGE_ID_EN_US as u32),
            ResourceEntry::Data(entry),
        );

        self.image
            .set_resource_directory(resources)
            .map_err(|_| Error::InternalError)?;
        Ok(self)
    }

    /// Build and write the modified PE file
    pub fn build<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        let data = self.image.data();
        writer.write_all(data)?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod pe {
    use std::ffi::CString;
    use windows_sys::Win32::System::LibraryLoader::{
        FindResourceA, LoadResource, LockResource, SizeofResource,
    };

    pub fn find_section(section_name: &str) -> Option<&[u8]> {
        let Ok(section_name) = CString::new(section_name) else {
            return None;
        };

        unsafe {
            let resource_handle = FindResourceA(0, section_name.as_ptr() as _, 10 as *const _);
            if resource_handle == 0 {
                return None;
            }

            let resource_data = LoadResource(0, resource_handle);
            if resource_data == 0 {
                return None;
            }

            let resource_size = SizeofResource(0, resource_handle);
            if resource_size == 0 {
                return None;
            }

            let resource_ptr = LockResource(resource_data);
            Some(std::slice::from_raw_parts(
                resource_ptr as *const u8,
                resource_size as usize,
            ))
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, FromBytes, FromZeroes, AsBytes)]
pub(crate) struct SegmentCommand64 {
    cmd: u32,
    cmdsize: u32,
    segname: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    nsects: u32,
    flags: u32,
}

#[derive(FromBytes, FromZeroes, AsBytes)]
#[repr(C)]
pub(crate) struct Header64 {
    magic: u32,
    cputype: i32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, FromBytes, FromZeroes, AsBytes)]
pub(crate) struct Section64 {
    sectname: [u8; 16],
    segname: [u8; 16],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

const SEG_LINKEDIT: &[u8] = b"__LINKEDIT";

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
pub(crate) const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2d;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000001e;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x80000034;

const CPU_TYPE_ARM_64: i32 = 0x0100000c;

fn align(size: u64, base: u64) -> u64 {
    let over = size % base;
    if over == 0 {
        size
    } else {
        size + (base - over)
    }
}

fn align_vmsize(size: u64, page_size: u64) -> u64 {
    align(if size > 0x4000 { size } else { 0x4000 }, page_size)
}

fn shift(value: u64, amount: u64, range_min: u64, range_max: u64) -> u64 {
    if value < range_min || value > (range_max + range_min) {
        return value;
    }
    value + amount
}

pub struct Macho {
    header: Header64,
    commands: Vec<(u32, u32, usize)>,
    linkedit_cmd: SegmentCommand64,
    rest_size: u64,
    data: Vec<u8>,
    seg: SegmentCommand64,
    sec: Section64,
    sectdata: Option<Vec<u8>>,
}

pub(crate) const SEGNAME: [u8; 16] = *b"__SUI\0\0\0\0\0\0\0\0\0\0\0";

impl Macho {
    pub fn from(obj: Vec<u8>) -> Result<Self, Error> {
        let header = Header64::read_from_prefix(&obj)
            .ok_or(Error::InvalidObject("Failed to read header"))?;
        let mut commands: Vec<(u32, u32, usize)> = Vec::with_capacity(header.ncmds as usize);

        let mut offset = size_of::<Header64>();
        let mut linkedit_cmd = None;

        for _ in 0..header.ncmds as usize {
            let cmd = u32::from_le_bytes(
                obj[offset..offset + 4]
                    .try_into()
                    .map_err(|_| Error::InvalidObject("Failed to read command"))?,
            );
            let cmdsize = u32::from_le_bytes(
                obj[offset + 4..offset + 8]
                    .try_into()
                    .map_err(|_| Error::InvalidObject("Failed to read command size"))?,
            );

            if cmd == LC_SEGMENT_64 {
                let segcmd = SegmentCommand64::read_from_prefix(&obj[offset..])
                    .ok_or(Error::InvalidObject("Failed to read segment command"))?;
                if segcmd.segname[..SEG_LINKEDIT.len()] == *SEG_LINKEDIT {
                    linkedit_cmd = Some(segcmd);
                }
            }

            commands.push((cmd, cmdsize, offset));
            offset += cmdsize as usize;
        }

        let Some(linkedit_cmd) = linkedit_cmd else {
            return Err(Error::InvalidObject("Linkedit segment not found"));
        };
        let rest_size =
            linkedit_cmd.fileoff - size_of::<Header64>() as u64 - header.sizeofcmds as u64;
        Ok(Self {
            header,
            commands,
            linkedit_cmd,
            data: obj,
            rest_size,
            seg: SegmentCommand64::new_zeroed(),
            sec: Section64::new_zeroed(),
            sectdata: None,
        })
    }

    pub fn write_section(mut self, name: &str, sectdata: Vec<u8>) -> Result<Self, Error> {
        let page_size = if self.header.cputype == CPU_TYPE_ARM_64 {
            0x10000
        } else {
            0x1000
        };

        self.seg = SegmentCommand64 {
            cmd: LC_SEGMENT_64,
            cmdsize: size_of::<SegmentCommand64>() as u32 + size_of::<Section64>() as u32,
            segname: SEGNAME,
            vmaddr: self.linkedit_cmd.vmaddr,
            vmsize: align_vmsize(sectdata.len() as u64, page_size),
            filesize: align_vmsize(sectdata.len() as u64, page_size),
            fileoff: self.linkedit_cmd.fileoff,
            maxprot: 0x01,
            initprot: 0x01,
            nsects: 1,
            flags: 0,
        };

        let mut sectname = [0; 16];
        sectname[..name.len()].copy_from_slice(name.as_bytes());

        self.sec = Section64 {
            addr: self.seg.vmaddr,
            size: sectdata.len() as u64,
            offset: self.linkedit_cmd.fileoff as u32,
            align: if sectdata.len() < 16 { 0 } else { 4 },
            segname: SEGNAME,
            sectname,
            ..self.sec
        };

        self.linkedit_cmd.vmaddr += self.seg.vmsize;
        let linkedit_fileoff = self.linkedit_cmd.fileoff;
        self.linkedit_cmd.fileoff += self.seg.filesize;

        macro_rules! shift_cmd {
            ($cmd:expr) => {
                $cmd = shift(
                    $cmd as _,
                    self.seg.filesize,
                    linkedit_fileoff,
                    self.linkedit_cmd.filesize,
                ) as _;
            };
        }

        for (cmd, _, offset) in self.commands.iter_mut() {
            match *cmd {
                LC_SYMTAB => {
                    #[derive(FromBytes, FromZeroes, AsBytes)]
                    #[repr(C)]
                    pub struct SymtabCommand {
                        pub cmd: u32,
                        pub cmdsize: u32,
                        pub symoff: u32,
                        pub nsyms: u32,
                        pub stroff: u32,
                        pub strsize: u32,
                    }

                    let cmd = SymtabCommand::mut_from_prefix(&mut self.data[*offset..])
                        .ok_or(Error::InvalidObject("Failed to read symtab command"))?;
                    shift_cmd!(cmd.symoff);
                    shift_cmd!(cmd.stroff);
                }
                LC_DYSYMTAB => {
                    #[derive(FromBytes, FromZeroes, AsBytes)]
                    #[repr(C)]
                    pub struct DysymtabCommand {
                        pub cmd: u32,
                        pub cmdsize: u32,
                        pub ilocalsym: u32,
                        pub nlocalsym: u32,
                        pub iextdefsym: u32,
                        pub nextdefsym: u32,
                        pub iundefsym: u32,
                        pub nundefsym: u32,
                        pub tocoff: u32,
                        pub ntoc: u32,
                        pub modtaboff: u32,
                        pub nmodtab: u32,
                        pub extrefsymoff: u32,
                        pub nextrefsyms: u32,
                        pub indirectsymoff: u32,
                        pub nindirectsyms: u32,
                        pub extreloff: u32,
                        pub nextrel: u32,
                        pub locreloff: u32,
                        pub nlocrel: u32,
                    }

                    let cmd = DysymtabCommand::mut_from_prefix(&mut self.data[*offset..])
                        .ok_or(Error::InvalidObject("Failed to read dysymtab command"))?;
                    shift_cmd!(cmd.tocoff);
                    shift_cmd!(cmd.modtaboff);
                    shift_cmd!(cmd.extrefsymoff);
                    shift_cmd!(cmd.indirectsymoff);
                    shift_cmd!(cmd.extreloff);
                    shift_cmd!(cmd.locreloff);
                }

                LC_CODE_SIGNATURE
                | LC_FUNCTION_STARTS
                | LC_DATA_IN_CODE
                | LC_DYLIB_CODE_SIGN_DRS
                | LC_LINKER_OPTIMIZATION_HINT
                | LC_DYLD_EXPORTS_TRIE
                | LC_DYLD_CHAINED_FIXUPS => {
                    #[derive(FromBytes, FromZeroes, AsBytes)]
                    #[repr(C)]
                    struct LinkeditDataCommand {
                        cmd: u32,
                        cmdsize: u32,
                        dataoff: u32,
                        datasize: u32,
                    }
                    let cmd = LinkeditDataCommand::mut_from_prefix(&mut self.data[*offset..])
                        .ok_or(Error::InvalidObject("Failed to read linkedit data command"))?;
                    shift_cmd!(cmd.dataoff);
                }

                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    #[derive(FromBytes, FromZeroes, AsBytes)]
                    #[repr(C)]
                    pub struct DyldInfoCommand {
                        pub cmd: u32,
                        pub cmdsize: u32,
                        pub rebase_off: u32,
                        pub rebase_size: u32,
                        pub bind_off: u32,
                        pub bind_size: u32,
                        pub weak_bind_off: u32,
                        pub weak_bind_size: u32,
                        pub lazy_bind_off: u32,
                        pub lazy_bind_size: u32,
                        pub export_off: u32,
                        pub export_size: u32,
                    }
                    let dyld_info = DyldInfoCommand::mut_from_prefix(&mut self.data[*offset..])
                        .ok_or(Error::InvalidObject("Failed to read dyld info command"))?;
                    shift_cmd!(dyld_info.rebase_off);
                    shift_cmd!(dyld_info.bind_off);
                    shift_cmd!(dyld_info.weak_bind_off);
                    shift_cmd!(dyld_info.lazy_bind_off);
                    shift_cmd!(dyld_info.export_off);
                }

                _ => {}
            }
        }

        self.header.ncmds += 1;
        self.header.sizeofcmds += self.seg.cmdsize;

        self.sectdata = Some(sectdata);
        Ok(self)
    }

    /// Build and write the modified Mach-O file
    pub fn build<W: Write>(mut self, writer: &mut W) -> Result<(), Error> {
        writer.write_all(self.header.as_bytes())?;

        for (cmd, cmdsize, offset) in self.commands.iter_mut() {
            if *cmd == LC_SEGMENT_64 {
                let segcmd = SegmentCommand64::read_from_prefix(&self.data[*offset..])
                    .ok_or(Error::InvalidObject("Failed to read segment command"))?;
                if segcmd.segname[..SEG_LINKEDIT.len()] == *SEG_LINKEDIT {
                    writer.write_all(self.seg.as_bytes())?;
                    writer.write_all(self.sec.as_bytes())?;
                    writer.write_all(self.linkedit_cmd.as_bytes())?;
                    continue;
                }
            }
            writer.write_all(&self.data[*offset..*offset + *cmdsize as usize])?;
        }

        let mut off = self.header.sizeofcmds as usize + size_of::<Header64>();

        let len = self.rest_size as usize - self.seg.cmdsize as usize;
        writer.write_all(&self.data[off..off + len])?;

        off += len;

        if let Some(sectdata) = self.sectdata {
            writer.write_all(&sectdata)?;
            if self.seg.filesize > sectdata.len() as u64 {
                let padding = vec![0; (self.seg.filesize - sectdata.len() as u64) as usize];
                writer.write_all(&padding)?;
            }
        }

        writer.write_all(&self.data[off..off + self.linkedit_cmd.filesize as usize])?;

        Ok(())
    }

    pub fn build_and_sign<W: Write>(self, mut writer: W) -> Result<(), Error> {
        if self.header.cputype == CPU_TYPE_ARM_64 {
            let mut data = Vec::new();
            self.build(&mut data)?;
            let codesign = apple_codesign::MachoSigner::new(data)?;
            codesign.sign(writer)
        } else {
            self.build(&mut writer)
        }
    }
}

#[cfg(target_os = "macos")]
mod macho {
    use super::SEGNAME;
    use std::ffi::CString;
    use std::os::raw::c_char;

    extern "C" {
        pub fn getsectdata(
            segname: *const c_char,
            sectname: *const c_char,
            size: *mut usize,
        ) -> *mut c_char;

        pub fn _dyld_get_image_vmaddr_slide(image_index: usize) -> usize;
    }

    pub fn find_section(section_name: &str) -> Option<&[u8]> {
        let mut section_size: usize = 0;
        let section_name = CString::new(section_name).ok()?;

        unsafe {
            let mut ptr = getsectdata(
                SEGNAME.as_ptr() as *const c_char,
                section_name.as_ptr() as *const c_char,
                &mut section_size as *mut usize,
            );

            if ptr.is_null() {
                return None;
            }

            // Add the "virtual memory address slide" amount to ensure a valid pointer
            // in cases where the virtual memory address have been adjusted by the OS.
            ptr = ptr.wrapping_add(_dyld_get_image_vmaddr_slide(0));
            Some(std::slice::from_raw_parts(ptr as *const u8, section_size))
        }
    }
}

pub struct Elf<'a> {
    data: &'a [u8],
}

impl<'a> Elf<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn append<W: Write>(&self, sectdata: &[u8], writer: &mut W) -> Result<(), Error> {
        let mut elf = self.data.to_vec();
        elf.extend_from_slice(sectdata);
        const MAGIC: u32 = 0x501e;

        elf.extend_from_slice(&MAGIC.to_le_bytes());
        elf.extend_from_slice(&(sectdata.len() as u32 + 8).to_le_bytes());

        writer.write_all(&elf)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod elf {
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;

    pub fn find_section(_: &str) -> Option<&[u8]> {
        let exe = std::env::current_exe().unwrap();

        let mut file = std::fs::File::open(exe).unwrap();
        file.seek(SeekFrom::End(-8)).unwrap();
        let mut buf = [0; 8];
        file.read_exact(&mut buf).unwrap();
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != 0x501e {
            return None;
        }

        let offset = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;

        file.seek(SeekFrom::End(-(offset as i64))).unwrap();

        // Read section data
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let data = buf[..buf.len() - 8].to_vec();

        Some(Box::leak(data.into_boxed_slice()))
    }
}

/// Utilities for detecting binary formats
pub mod utils {
    /// Check if the given data is an ELF64 binary
    pub fn is_elf(data: &[u8]) -> bool {
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        magic == 0x7f454c46
    }

    /// Check if the given data is a 64-bit Mach-O binary
    pub fn is_macho(data: &[u8]) -> bool {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        magic == 0xfeedfacf
    }

    /// Check if the given data is a PE32+ binary
    pub fn is_pe(data: &[u8]) -> bool {
        let magic = u16::from_le_bytes([data[0], data[1]]);
        magic == 0x5a4d
    }
}
