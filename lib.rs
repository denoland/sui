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
    constants::{CODE_PAGE_ID_EN_US, RT_GROUP_ICON, RT_ICON, RT_RCDATA},
    types::{IconDirectory, IconDirectoryEntry},
    ResourceData, ResourceEntry, ResourceEntryName, ResourceTable,
};
use image::{imageops::FilterType::Lanczos3, ImageFormat, ImageReader};
use object::endian::Endianness;
use object::read::elf::{FileHeader, ProgramHeader};
use std::io::Cursor;
use std::io::Write;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub mod apple_codesign;
pub mod intel_mac;

#[cfg(all(unix, not(target_vendor = "apple")))]
pub use elf::find_section;
#[cfg(target_vendor = "apple")]
pub use macho::find_section;
#[cfg(windows)]
pub use pe::find_section;

#[derive(Debug)]
pub enum Error {
    InvalidObject(&'static str),
    ImageError(image::ImageError),
    InternalError,
    IoError(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidObject(msg) => write!(f, "Invalid object: {}", msg),
            Error::InternalError => write!(f, "Internal error"),
            Error::ImageError(err) => write!(f, "Image error: {}", err),
            Error::IoError(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl From<image::ImageError> for Error {
    fn from(err: image::ImageError) -> Self {
        Error::ImageError(err)
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
    resource_dir: editpe::ResourceDirectory,
    icons: Vec<IconDirectoryEntry>,
}

impl<'a> PortableExecutable<'a> {
    /// Parse from a PE file
    pub fn from(data: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            image: editpe::Image::parse(data)
                .map_err(|_| Error::InvalidObject("Failed to parse PE"))?,
            resource_dir: editpe::ResourceDirectory::default(),
            icons: Vec::new(),
        })
    }

    /// Write a resource to the PE file
    pub fn write_resource(mut self, name: &str, sectdata: Vec<u8>) -> Result<Self, Error> {
        let root = self.resource_dir.root_mut();
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

        rc_table.insert(ResourceEntryName::ID(0), ResourceEntry::Data(entry));

        Ok(self)
    }

    /// Set the icon of the executable.
    pub fn set_icon<T: AsRef<[u8]>>(mut self, icon: T) -> Result<Self, Error> {
        let root = self.resource_dir.root_mut();
        let icon = icon.as_ref();
        let icon = ImageReader::new(Cursor::new(icon))
            .with_guessed_format()?
            .decode()?;

        // find the main icon table
        if root.get(ResourceEntryName::ID(RT_ICON as u32)).is_none() {
            root.insert(
                ResourceEntryName::ID(RT_ICON as u32),
                ResourceEntry::Table(ResourceTable::default()),
            );
        }
        let icon_table = match root.get_mut(ResourceEntryName::ID(RT_ICON as u32)).unwrap() {
            ResourceEntry::Table(table) => table,
            ResourceEntry::Data(_) => {
                return Err(Error::InvalidObject("icon table is not a table"));
            }
        };

        // find the first free icon id
        let first_free_icon_id = icon_table
            .entries()
            .into_iter()
            .filter_map(|k| match k {
                ResourceEntryName::ID(id) => Some(id),
                _ => None,
            })
            .max()
            .unwrap_or(&0)
            + 1;

        // add the icon to the icon table
        let mut icon_directory_entries = Vec::new();
        let resolutions = [256, 128, 48, 32, 24, 16];
        for (i, &size) in resolutions.iter().enumerate() {
            let id = first_free_icon_id + i as u32;
            let mut inner_table = ResourceTable::default();
            let data = {
                let mut data = Vec::new();
                icon.resize_exact(size, size, Lanczos3)
                    .to_rgba8()
                    .write_to(&mut Cursor::new(&mut data), ImageFormat::Ico)?;

                let mut entry = IconDirectoryEntry::read_from_prefix(&data[6..20]).unwrap();
                entry.id = id as u16;
                icon_directory_entries.push(entry);
                data[22..].to_owned()
            };

            let mut resource_data = ResourceData::default();
            resource_data.set_codepage(CODE_PAGE_ID_EN_US as u32);
            resource_data.set_data(data);

            inner_table.insert(ResourceEntryName::ID(0), ResourceEntry::Data(resource_data));
            icon_table.insert(ResourceEntryName::ID(id), ResourceEntry::Table(inner_table));
        }
        self.icons = icon_directory_entries;

        Ok(self)
    }

    /// Build and write the modified PE file
    pub fn build<W: std::io::Write>(mut self, writer: &mut W) -> Result<(), Error> {
        // TODO: the order of the table entries matters. this works for now.
        if !self.icons.is_empty() {
            let root = self.resource_dir.root_mut();

            // find the group icon table
            if root
                .get(ResourceEntryName::ID(RT_GROUP_ICON as u32))
                .is_none()
            {
                root.insert(
                    ResourceEntryName::ID(RT_GROUP_ICON as u32),
                    ResourceEntry::Table(ResourceTable::default()),
                );
            }
            let group_table = match root
                .get_mut(ResourceEntryName::ID(RT_GROUP_ICON as u32))
                .unwrap()
            {
                ResourceEntry::Table(table) => table,
                ResourceEntry::Data(_) => {
                    return Err(Error::InvalidObject("group icon table is not a table"));
                }
            };

            let data = {
                let mut data = Vec::new();
                let icon_directory = IconDirectory {
                    reserved: 0,
                    type_: 1,
                    count: self.icons.len() as u16,
                };
                data.extend(icon_directory.as_bytes());
                for entry in self.icons {
                    data.extend(&entry.as_bytes()[..14]);
                }
                data
            };
            let mut resource_data = ResourceData::default();
            resource_data.set_codepage(CODE_PAGE_ID_EN_US as u32);
            resource_data.set_data(data);
            // insert the main icon directory table
            let mut inner_table = ResourceTable::default();
            inner_table.insert(ResourceEntryName::ID(0), ResourceEntry::Data(resource_data));
            group_table.insert_at(
                ResourceEntryName::from_string("MAINICON"),
                ResourceEntry::Table(inner_table),
                0,
            );
        }

        self.image
            .set_resource_directory(self.resource_dir)
            .map_err(|_| Error::InternalError)?;

        let data = self.image.data();
        writer.write_all(data)?;
        Ok(())
    }
}

#[cfg(windows)]
mod pe {
    use std::ffi::CString;
    use windows_sys::Win32::System::LibraryLoader::{
        FindResourceA, LoadResource, LockResource, SizeofResource,
    };

    pub fn find_section(section_name: &str) -> std::io::Result<Option<&[u8]>> {
        let section_name = section_name.to_uppercase();
        let section_name = CString::new(section_name)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

        unsafe {
            let current_process_hmod = 0;
            let resource_handle = FindResourceA(
                current_process_hmod,
                section_name.as_ptr() as _,
                10 as *const _,
            );
            if resource_handle == 0 {
                return Ok(None);
            }

            let resource_data = LoadResource(current_process_hmod, resource_handle);
            if resource_data == 0 {
                return Err(std::io::Error::last_os_error());
            }

            let resource_size = SizeofResource(current_process_hmod, resource_handle);
            if resource_size == 0 {
                return Ok(Some(&[]));
            }

            let resource_ptr = LockResource(resource_data);
            Ok(Some(std::slice::from_raw_parts(
                resource_ptr as *const u8,
                resource_size as usize,
            )))
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
const LC_ATOM_INFO: u32 = 0x36;
const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2d;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x80000033;
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

        // Atomically strip code signature first for intel binaries.
        #[cfg(target_vendor = "apple")]
        let obj = if header.cputype != CPU_TYPE_ARM_64 {
            use std::io::Write;

            let tmp_dir = std::env::temp_dir();
            std::fs::create_dir_all(&tmp_dir)?;
            let tmp_path = tmp_dir.join(format!("sui_tmp_{}", std::process::id()));

            let mut tmp_file = std::fs::File::create(&tmp_path)?;
            tmp_file.write_all(&obj)?;
            drop(tmp_file);

            match std::process::Command::new("codesign")
                .arg("--remove-signature")
                .arg(&tmp_path)
                .output()
            {
                Ok(output) => {
                    if !output.status.success() {
                        // If codesign fails, just use the original binary
                        eprintln!(
                            "Warning: Failed to remove code signature: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        std::fs::remove_file(&tmp_path).ok();
                        obj
                    } else {
                        // Read the stripped binary
                        let stripped = std::fs::read(&tmp_path)?;
                        std::fs::remove_file(&tmp_path).ok();
                        stripped
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // codesign not found, skip it
                    std::fs::remove_file(&tmp_path).ok();
                    obj
                }
                Err(e) => {
                    std::fs::remove_file(&tmp_path).ok();
                    return Err(e.into());
                }
            }
        } else {
            obj
        };

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
        /* x86_64 */
        if self.header.cputype != CPU_TYPE_ARM_64 {
            self.sectdata = Some(sectdata);
            return Ok(self);
        }

        /* arm64 */
        let page_size = 0x10000;

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
                | LC_ATOM_INFO
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
        if self.header.cputype != CPU_TYPE_ARM_64 {
            let mut data = self.data;

            if let Some(sectdata) = self.sectdata {
                // Construct sentinel from reversed string to prevent it from existing as contiguous
                // bytes in the binary. Use black_box to prevent compiler from const-evaluating.
                let mut sentinel = Vec::with_capacity(16);
                let reversed = std::hint::black_box(b">~atad-ius~<"); // "<~sui-data~>" reversed
                for &byte in reversed.iter().rev() {
                    sentinel.push(byte);
                }
                // Add magic bytes in reverse order with black_box
                let magic = std::hint::black_box([0xEF, 0xBE, 0xAD, 0xDE]);
                sentinel.extend_from_slice(&magic);
                data.extend_from_slice(&sentinel);
                data.extend_from_slice(&(sectdata.len() as u64).to_le_bytes());
                data.extend_from_slice(&sectdata);
            }

            intel_mac::patch_macho_executable(&mut data);
            writer.write_all(&data)?;
            return Ok(());
        };

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
            // For Intel binaries, build to a temporary file and run adhoc codesign
            #[cfg(target_vendor = "apple")]
            {
                let tmp_dir = std::env::temp_dir();
                std::fs::create_dir_all(&tmp_dir)?;
                let tmp_path = tmp_dir.join(format!("sui_sign_{}", std::process::id()));

                {
                    let mut tmp_file = std::fs::File::create(&tmp_path)?;
                    self.build(&mut tmp_file)?;
                }

                // Run adhoc codesign
                match std::process::Command::new("codesign")
                    .arg("-s")
                    .arg("-")
                    .arg(&tmp_path)
                    .output()
                {
                    Ok(output) => {
                        if !output.status.success() {
                            eprintln!(
                                "Warning: Failed to adhoc codesign binary: {}",
                                String::from_utf8_lossy(&output.stderr)
                            );
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // codesign not found, skip it
                    }
                    Err(e) => {
                        std::fs::remove_file(&tmp_path).ok();
                        return Err(e.into());
                    }
                }

                // Read the (possibly signed) binary and write to output
                let signed_data = std::fs::read(&tmp_path)?;
                writer.write_all(&signed_data)?;
                std::fs::remove_file(&tmp_path).ok();

                Ok(())
            }

            #[cfg(not(target_vendor = "apple"))]
            {
                // On non-macOS, just build directly without codesign
                self.build(&mut writer)?;
                Ok(())
            }
        }
    }
}

#[cfg(target_vendor = "apple")]
mod macho {
    pub fn find_section(_section_name: &str) -> std::io::Result<Option<&[u8]>> {
        #[cfg(target_arch = "x86_64")]
        {
            super::intel_mac::find_section()
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
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

            let mut section_size: usize = 0;
            let section_name = CString::new(_section_name)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

            unsafe {
                let mut ptr = getsectdata(
                    SEGNAME.as_ptr() as *const c_char,
                    section_name.as_ptr() as *const c_char,
                    &mut section_size as *mut usize,
                );

                if ptr.is_null() {
                    return Ok(None);
                }

                // Add the "virtual memory address slide" amount to ensure a valid pointer
                // in cases where the virtual memory address have been adjusted by the OS.
                ptr = ptr.wrapping_add(_dyld_get_image_vmaddr_slide(0));
                Ok(Some(std::slice::from_raw_parts(
                    ptr as *const u8,
                    section_size,
                )))
            }
        }
    }
}

pub struct Elf<'a> {
    data: &'a [u8],
}

const ELF_NOTE_NAME: &[u8] = b"SUI\0";
const ELF_NOTE_TYPE_SECTION_DATA: u32 = 0x5355_4901;

fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        value
    } else {
        (value + (align - 1)) & !(align - 1)
    }
}

// ELF note payload
fn build_elf_note_payload(section_name: &str, section_data: &[u8]) -> Vec<u8> {
    let name_len = section_name.len();
    let name_len_u16 = u16::try_from(name_len).expect("section name too long");

    let mut desc = Vec::with_capacity(2 + name_len + section_data.len());
    desc.extend_from_slice(&name_len_u16.to_le_bytes());
    desc.extend_from_slice(section_name.as_bytes());
    desc.extend_from_slice(section_data);

    let mut note =
        Vec::with_capacity(12 + align_up(ELF_NOTE_NAME.len(), 4) + align_up(desc.len(), 4));
    note.extend_from_slice(&(ELF_NOTE_NAME.len() as u32).to_le_bytes());
    note.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    note.extend_from_slice(&ELF_NOTE_TYPE_SECTION_DATA.to_le_bytes());
    note.extend_from_slice(ELF_NOTE_NAME);
    note.resize(align_up(note.len(), 4), 0);
    note.extend_from_slice(&desc);
    note.resize(align_up(note.len(), 4), 0);
    note
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn parse_elf_note_desc<'a>(desc: &'a [u8], name: &str) -> Option<&'a [u8]> {
    if desc.len() < 2 {
        return None;
    }
    let name_len = u16::from_le_bytes(desc[0..2].try_into().ok()?) as usize;
    if desc.len() < 2 + name_len {
        return None;
    }
    if desc.get(2..2 + name_len)? != name.as_bytes() {
        return None;
    }
    Some(&desc[2 + name_len..])
}

impl<'a> Elf<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn append<W: Write>(
        &self,
        name: &str,
        sectdata: &[u8],
        writer: &mut W,
    ) -> Result<(), Error> {
        use object::build::elf as e;
        let note_data = build_elf_note_payload(name, sectdata);

        // Existing PT_NOTE section headers are not preserved; their contents are copied into
        // `.note.sui` instead
        let combined_note_data = {
            let existing = object::read::elf::ElfFile64::<Endianness, _>::parse(self.data)
                .ok()
                .and_then(|elf_file| {
                    let endian = elf_file.endian();
                    let header = elf_file.elf_header();
                    let segments = header.program_headers(endian, self.data).ok()?;
                    for segment in segments {
                        if segment.p_type(endian) != object::elf::PT_NOTE {
                            continue;
                        }
                        let data = segment.data(endian, self.data).ok()?;
                        if !data.is_empty() {
                            return Some(data);
                        }
                    }
                    None
                });
            if let Some(existing) = existing {
                let mut combined = Vec::with_capacity(existing.len() + note_data.len());
                combined.extend_from_slice(existing);
                combined.extend_from_slice(&note_data);
                combined
            } else {
                note_data.clone()
            }
        };

        let mut builder =
            e::Builder::read(self.data).map_err(|_| Error::InvalidObject("Failed to parse ELF"))?;

        let section = builder.sections.add();
        section.name = ".note.sui".into();
        section.sh_type = object::elf::SHT_NOTE;
        section.sh_flags = object::elf::SHF_ALLOC as u64;
        section.sh_addralign = 4;
        section.data = e::SectionData::Note(combined_note_data.into());
        let section_id = section.id();

        builder.set_section_sizes();

        let mut max_end = 0u64;
        for existing in builder.sections.iter() {
            if existing.delete {
                continue;
            }
            let filesz = if existing.sh_type == object::elf::SHT_NOBITS {
                0
            } else {
                existing.sh_size
            };
            let end = existing.sh_offset + filesz;
            if end > max_end {
                max_end = end;
            }
        }
        let load_segment_id = builder
            .segments
            .iter()
            .filter(|segment| segment.is_load())
            .max_by_key(|segment| segment.p_offset + segment.p_filesz)
            .map(|segment| segment.id());

        {
            let section = builder.sections.get_mut(section_id);
            let align = if let Some(load_segment_id) = load_segment_id {
                let seg = builder.segments.get(load_segment_id);
                (seg.p_align as usize)
                    .max(section.sh_addralign as usize)
                    .max(1)
            } else {
                (section.sh_addralign as usize).max(1)
            };
            section.sh_offset = align_up(max_end as usize, align) as u64;
            section.sh_addr = if let Some(load_segment_id) = load_segment_id {
                let seg = builder.segments.get(load_segment_id);
                seg.p_vaddr + (section.sh_offset - seg.p_offset)
            } else {
                0
            };
        }

        if let Some(load_segment_id) = load_segment_id {
            let section = builder.sections.get_mut(section_id);
            let seg = builder.segments.get_mut(load_segment_id);
            let section_end = section.sh_offset + section.sh_size;
            let mem_end = section.sh_addr + section.sh_size;
            if section_end > seg.p_offset + seg.p_filesz {
                seg.p_filesz = section_end - seg.p_offset;
            }
            if mem_end > seg.p_vaddr + seg.p_memsz {
                seg.p_memsz = mem_end - seg.p_vaddr;
            }
            if !seg.sections.contains(&section_id) {
                seg.sections.push(section_id);
            }
        }

        let note_segment_id = builder
            .segments
            .iter()
            .find(|segment| segment.p_type == object::elf::PT_NOTE)
            .map(|segment| segment.id());

        if let Some(note_segment_id) = note_segment_id {
            let section = builder.sections.get_mut(section_id);
            let segment = builder.segments.get_mut(note_segment_id);
            segment.sections.clear();
            segment.sections.push(section_id);
            segment.p_type = object::elf::PT_NOTE;
            segment.p_flags = object::elf::PF_R;
            segment.p_align = 4;
            segment.p_offset = section.sh_offset;
            segment.p_vaddr = section.sh_addr;
            segment.p_paddr = section.sh_addr;
            segment.p_filesz = section.sh_size;
            segment.p_memsz = section.sh_size;
        } else {
            let section = builder.sections.get_mut(section_id);
            let segment = builder.segments.add();
            segment.p_type = object::elf::PT_NOTE;
            segment.p_flags = object::elf::PF_R;
            segment.p_align = 4;
            segment.p_offset = section.sh_offset;
            segment.p_vaddr = section.sh_addr;
            segment.p_paddr = section.sh_addr;
            segment.p_filesz = section.sh_size;
            segment.p_memsz = section.sh_size;
            segment.sections.push(section_id);
        }

        let mut out = Vec::new();
        builder
            .write(&mut out)
            .map_err(|err| Error::IoError(std::io::Error::other(err)))?;
        writer.write_all(&out)?;
        Ok(())
    }
}

#[cfg(all(unix, not(target_vendor = "apple")))]
mod elf {
    use libc::{dl_iterate_phdr, dl_phdr_info, Elf64_Phdr, PT_NOTE};
    use std::os::raw::{c_int, c_void};

    unsafe extern "C" fn sui_dl_iterate_phdr_callback(
        info: *mut dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> c_int {
        *(data as *mut dl_phdr_info) = *info;
        1
    }

    fn find_in_note_segment<'a>(segment: &'a [u8], align: usize, name: &str) -> Option<&'a [u8]> {
        let mut pos = 0usize;
        while pos + 12 <= segment.len() {
            let namesz = u32::from_le_bytes(segment[pos..pos + 4].try_into().ok()?) as usize;
            let descsz = u32::from_le_bytes(segment[pos + 4..pos + 8].try_into().ok()?) as usize;
            let note_type = u32::from_le_bytes(segment[pos + 8..pos + 12].try_into().ok()?);
            pos += 12;

            if pos + namesz > segment.len() {
                break;
            }
            let mut note_name = &segment[pos..pos + namesz];
            while let [rest @ .., 0] = note_name {
                note_name = rest;
            }
            pos = super::align_up(pos + namesz, align);

            if pos + descsz > segment.len() {
                break;
            }
            let desc = &segment[pos..pos + descsz];
            pos = super::align_up(pos + descsz, align);

            if note_name == &super::ELF_NOTE_NAME[..super::ELF_NOTE_NAME.len() - 1]
                && note_type == super::ELF_NOTE_TYPE_SECTION_DATA
            {
                if let Some(section_data) = super::parse_elf_note_desc(desc, name) {
                    return Some(section_data);
                }
            }
        }
        None
    }

    pub fn find_section(name: &str) -> std::io::Result<Option<&[u8]>> {
        let mut main_program_info: dl_phdr_info = unsafe { std::mem::zeroed() };
        unsafe {
            dl_iterate_phdr(
                Some(sui_dl_iterate_phdr_callback),
                &mut main_program_info as *mut dl_phdr_info as *mut c_void,
            );
        }

        let mut p = main_program_info.dlpi_phdr as *const u8;
        let mut n = main_program_info.dlpi_phnum as usize;
        let base = main_program_info.dlpi_addr as usize;

        while n > 0 {
            let phdr = unsafe { &*(p as *const Elf64_Phdr) };
            if phdr.p_type == PT_NOTE {
                let pos = base + phdr.p_vaddr as usize;
                let len = phdr.p_memsz as usize;
                if len > 0 {
                    let segment = unsafe { std::slice::from_raw_parts(pos as *const u8, len) };
                    let align = (phdr.p_align as usize).max(4);
                    if let Some(section_data) = find_in_note_segment(segment, align, name) {
                        // SAFETY: `segment` points into a mapped PT_LOAD range of the main
                        // executable. That mapping stays valid for the process lifetime,
                        // so it is safe to extend the slice's lifetime to 'static here.
                        let data: &'static [u8] = unsafe { std::mem::transmute(section_data) };
                        return Ok(Some(data));
                    }
                }
            }

            n -= 1;
            p = unsafe { p.add(core::mem::size_of::<Elf64_Phdr>()) };
        }

        Ok(None)
    }
}

/// Utilities for detecting binary formats
pub mod utils {
    /// Check if the given data is an ELF64 binary
    pub fn is_elf(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        magic == 0x7f454c46
    }

    /// Check if the given data is a 64-bit Mach-O binary
    pub fn is_macho(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        magic == 0xfeedfacf
    }

    /// Check if the given data is a PE32+ binary
    pub fn is_pe(data: &[u8]) -> bool {
        if data.len() < 2 {
            return false;
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        magic == 0x5a4d
    }
}
