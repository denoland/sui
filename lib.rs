/*
 * "Sui: embed and extract auxillary data from binaries"
 *
 * Copyright (c) 2024 Divy Srivastaa
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

use editpe::{
    constants::{LANGUAGE_ID_EN_US, RT_RCDATA},
    ResourceEntry, ResourceEntryName, ResourceTable,
};

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
        let mut resources = self.image.resource_directory().cloned().unwrap_or_default();
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
        rc_table.insert(
            editpe::ResourceEntryName::from_string(name),
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
        let Ok(section_name) = CString::new(section_name.to_uppercase()) else {
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

// mach-o
#[cfg(target_os = "macos")]
mod macho {
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
        let segment_name = "__SUI\0";
        let section_name = if section_name.starts_with("__") {
            section_name.to_string()
        } else {
            format!("__{}", section_name)
        };
        let section_name = CString::new(section_name).unwrap();

        unsafe {
            let mut ptr = getsectdata(
                segment_name.as_ptr() as *const c_char,
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

use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[repr(C)]
#[derive(Debug, Clone, FromBytes, FromZeroes, AsBytes)]
pub struct SegmentCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
}

#[derive(FromBytes, FromZeroes, AsBytes)]
#[repr(C)]
pub struct Header64 {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, FromBytes, FromZeroes, AsBytes)]
pub struct Section64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

const SEG_LINKEDIT: &[u8] = b"__LINKEDIT";
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2d;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000001e;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x80000034;

fn align(size: u64, base: u64) -> u64 {
    let over = size % base;
    if over == 0 {
        size
    } else {
        size + (base - over)
    }
}

fn align_vmsize(size: u64) -> u64 {
    align(if size > 0x4000 { size } else { 0x4000 }, 0x1000)
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

impl Macho {
    pub fn from(obj: Vec<u8>) -> Self {
        let header = Header64::read_from_prefix(&obj).unwrap();
        let mut commands: Vec<(u32, u32, usize)> = Vec::new();

        let mut offset = std::mem::size_of::<Header64>() as usize;
        let mut linkedit_cmd = None;

        for _ in 0..header.ncmds as usize {
            let cmd = u32::from_le_bytes(obj[offset..offset + 4].try_into().unwrap());
            let cmdsize = u32::from_le_bytes(obj[offset + 4..offset + 8].try_into().unwrap());

            if cmd == LC_SEGMENT_64 {
                let segcmd = SegmentCommand64::read_from_prefix(&obj[offset..]).unwrap();
                if segcmd.segname == SEG_LINKEDIT {
                    linkedit_cmd = Some(segcmd);
                }
            }

            commands.push((cmd, cmdsize, offset));
            offset += cmdsize as usize;
        }

        let Some(linkedit_cmd) = linkedit_cmd else {
            panic!("Failed to find __LINKEDIT segment");
        };
        let rest_size = linkedit_cmd.fileoff - offset as u64 - header.sizeofcmds as u64;
        Self {
            header,
            commands,
            linkedit_cmd,
            data: obj,
            rest_size,
            seg: SegmentCommand64::new_zeroed(),
            sec: Section64::new_zeroed(),
            sectdata: None,
        }
    }

    pub fn write_section(mut self, name: &str, sectdata: Vec<u8>) -> Result<Self, Error> {
        self.seg.cmd = LC_SEGMENT_64;
        self.seg.cmdsize = std::mem::size_of::<SegmentCommand64>() as u32
            + std::mem::size_of::<Section64>() as u32;

        // Copy segment name
        let segname = name.as_bytes();
        for i in 0..segname.len() {
            self.seg.segname[i] = segname[i] as u8;
        }

        self.seg.vmaddr = self.linkedit_cmd.vmaddr;
        self.seg.vmsize = align_vmsize(sectdata.len() as u64);
        self.seg.fileoff = self.linkedit_cmd.fileoff;
        self.seg.filesize = self.seg.vmsize;
        self.seg.maxprot = 0x01;
        self.seg.initprot = self.seg.maxprot;
        self.seg.nsects = 1;

        // Copy section name
        let sectname = name.as_bytes();
        for i in 0..sectname.len() {
            self.sec.sectname[i] = sectname[i] as u8;
        }
        self.sec.segname = *b"__SUI\0\0\0\0\0\0\0\0\0\0\0";

        self.sec.addr = self.seg.vmaddr;
        self.sec.size = sectdata.len() as u64;
        self.sec.offset = self.seg.fileoff as u32;
        self.sec.align = if self.sec.size < 15 { 0 } else { 4 };

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

                    let cmd = SymtabCommand::mut_from_prefix(&mut self.data[*offset..]).unwrap();
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

                    let cmd = DysymtabCommand::mut_from_prefix(&mut self.data[*offset..]).unwrap();
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
                    let cmd =
                        LinkeditDataCommand::mut_from_prefix(&mut self.data[*offset..]).unwrap();
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
                    let dyld_info =
                        DyldInfoCommand::mut_from_prefix(&mut self.data[*offset..]).unwrap();
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
    pub fn build<W: std::io::Write + std::io::Seek>(mut self, writer: &mut W) -> Result<(), Error> {
        writer.write(self.header.as_bytes())?;

        let mut off = std::mem::size_of::<Header64>();
        for (cmd, cmdsize, offset) in self.commands.iter_mut() {
            if *cmd == LC_SEGMENT_64 {
                let segcmd = SegmentCommand64::read_from_prefix(&self.data[*offset..]).unwrap();
                if segcmd.segname == SEG_LINKEDIT {
                    writer.write(self.seg.as_bytes())?;
                    writer.write(self.sec.as_bytes())?;
                }
            }
            writer.write_all(&self.data[*offset..*offset + *cmdsize as usize])?;
            off += *cmdsize as usize;
        }

        // Write rest of the data
        let len = self.rest_size as usize - self.seg.cmdsize as usize;
        writer.write(&self.data[off..off + len])?;

        // Write custom data
        if let Some(sectdata) = self.sectdata {
            writer.write(&sectdata)?;
            if self.seg.filesize > sectdata.len() as u64 {
                let padding = vec![0; (self.seg.filesize - sectdata.len() as u64) as usize];
                writer.write(&padding)?;
            }
        }

        // Write __LINKEDIT data
        writer.write(&self.data[off + len..off + len + self.linkedit_cmd.filesize as usize])?;

        println!(
            "Total size: {}",
            off + len + self.linkedit_cmd.filesize as usize
        );

        Ok(())
    }
}

pub fn inject_macho(
    macho: &[u8],
    name: &str,
    sectname: &str,
    sectdata: &[u8],
    outfile: &str,
) -> Result<(), String> {
    let header = unsafe { &mut *(macho.as_ptr() as *mut Header64) };

    let mut linkedit_cmd = None;

    let mut segment = unsafe { macho.as_ptr().add(std::mem::size_of::<Header64>()) };

    let mut commands = Vec::new();
    for _ in 0..header.ncmds {
        let cmd = unsafe { &mut *(segment as *mut SegmentCommand64) };
        if cmd.cmd == LC_SEGMENT_64 {
            let segname = unsafe { std::ffi::CStr::from_ptr(cmd.segname.as_ptr() as *const i8) };
            if segname.to_bytes() == SEG_LINKEDIT {
                linkedit_cmd = Some(unsafe { &mut *(cmd as *mut SegmentCommand64) });
            }
        }

        segment = unsafe { segment.add(cmd.cmdsize as usize) };
        commands.push(cmd);
    }
    println!("commands: {:?}", commands.len());

    let Some(linkedit_cmd) = linkedit_cmd else {
        return Err("Failed to find __LINKEDIT segment".to_string());
    };

    println!("linkedit_cmd: {:?}", linkedit_cmd);
    let rest_datasize =
        linkedit_cmd.fileoff - std::mem::size_of::<Header64>() as u64 - header.sizeofcmds as u64;

    let mut seg = unsafe { std::mem::zeroed::<SegmentCommand64>() };
    let mut sec = unsafe { std::mem::zeroed::<Section64>() };

    seg.cmd = LC_SEGMENT_64;
    seg.cmdsize =
        std::mem::size_of::<SegmentCommand64>() as u32 + std::mem::size_of::<Section64>() as u32;

    // Copy segment name
    let segname = name.as_bytes();
    for i in 0..segname.len() {
        seg.segname[i] = segname[i] as u8;
    }

    seg.vmaddr = linkedit_cmd.vmaddr;
    seg.vmsize = align_vmsize(sectdata.len() as u64);
    seg.fileoff = linkedit_cmd.fileoff;
    seg.filesize = seg.vmsize;
    seg.maxprot = 0x01;
    seg.initprot = seg.maxprot;
    seg.nsects = 1;

    // Copy section name
    let sectname = sectname.as_bytes();
    for i in 0..sectname.len() {
        sec.sectname[i] = sectname[i] as u8;
    }
    // Copy segment name
    for i in 0..segname.len() {
        sec.segname[i] = segname[i] as u8;
    }

    sec.addr = seg.vmaddr;
    sec.size = sectdata.len() as u64;
    sec.offset = seg.fileoff as u32;
    sec.align = if sec.size < 16 { 0 } else { 4 };

    linkedit_cmd.vmaddr += seg.vmsize;
    let linkedit_fileoff = linkedit_cmd.fileoff;
    linkedit_cmd.fileoff += seg.filesize;

    fn shift(value: u64, amount: u64, range_min: u64, range_max: u64) -> u64 {
        if value < range_min || value > (range_max + range_min) {
            return value;
        }
        value + amount
    }

    macro_rules! shift_cmd {
        ($cmd:expr) => {
            $cmd = shift(
                $cmd as _,
                seg.filesize,
                linkedit_fileoff,
                linkedit_cmd.filesize,
            ) as _;
        };
    }

    const LC_SYMTAB: u32 = 0x2;
    const LC_DYSYMTAB: u32 = 0xb;
    const LC_CODE_SIGNATURE: u32 = 0x1d;
    const LC_FUNCTION_STARTS: u32 = 0x26;
    const LC_DATA_IN_CODE: u32 = 0x29;
    const LC_DYLD_INFO: u32 = 0x22;
    const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
    const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
    const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2d;
    const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000001e;
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x80000034;

    for cmd in commands.iter_mut() {
        match cmd.cmd {
            LC_SYMTAB => {
                #[repr(C)]
                pub struct SymtabCommand {
                    pub cmd: u32,
                    pub cmdsize: u32,
                    pub symoff: u32,
                    pub nsyms: u32,
                    pub stroff: u32,
                    pub strsize: u32,
                }

                let cmd = unsafe { &mut *(*cmd as *mut _ as *mut SymtabCommand) };
                shift_cmd!(cmd.symoff);
                shift_cmd!(cmd.stroff);
            }
            LC_DYSYMTAB => {
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

                let cmd = unsafe { &mut *(*cmd as *mut _ as *mut DysymtabCommand) };
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
                #[repr(C)]
                struct LinkeditDataCommand {
                    cmd: u32,
                    cmdsize: u32,
                    dataoff: u32,
                    datasize: u32,
                }
                let cmd = unsafe { &mut *(*cmd as *mut _ as *mut LinkeditDataCommand) };
                shift_cmd!(cmd.dataoff);
            }

            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
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
                let dyld_info = unsafe { &mut *(*cmd as *mut _ as *mut DyldInfoCommand) };
                shift_cmd!(dyld_info.rebase_off);
                shift_cmd!(dyld_info.bind_off);
                shift_cmd!(dyld_info.weak_bind_off);
                shift_cmd!(dyld_info.lazy_bind_off);
                shift_cmd!(dyld_info.export_off);
            }

            _ => {}
        }
    }

    header.ncmds += 1;
    header.sizeofcmds += seg.cmdsize;

    println!("seg: {:?}", seg);

    let fout = unsafe { libc::fopen(outfile.as_ptr() as *const _, "wb".as_ptr() as *const _) };

    use libc::fwrite;
    let mut finoff = macho.as_ptr() as *const _;
    // Write header
    unsafe {
        fwrite(finoff, 1, std::mem::size_of::<Header64>(), fout);
        finoff = finoff.add(std::mem::size_of::<Header64>());
    }

    // Write commands
    for cmd in commands.iter() {
        if *cmd as *const _ == linkedit_cmd as *const _ {
            unsafe {
                fwrite(
                    &seg as *const _ as *const _,
                    1,
                    std::mem::size_of::<SegmentCommand64>(),
                    fout,
                );
                fwrite(
                    &sec as *const _ as *const _,
                    1,
                    std::mem::size_of::<Section64>(),
                    fout,
                );
            }
        }
        unsafe {
            fwrite(*cmd as *const _ as _, 1, (*cmd).cmdsize as usize, fout);
        }
    }

    unsafe {
        finoff = finoff.add(header.sizeofcmds as usize);
    }

    // Write rest of the data
    unsafe {
        fwrite(
            finoff,
            1,
            rest_datasize as usize - seg.cmdsize as usize,
            fout,
        );
        finoff = finoff.add(rest_datasize as usize - seg.cmdsize as usize);
    }

    // Write custom data
    unsafe {
        fwrite(sectdata.as_ptr() as *const _, 1, sectdata.len(), fout);
        if seg.filesize > sectdata.len() as u64 {
            let padding = vec![0; (seg.filesize - sectdata.len() as u64) as usize];
            fwrite(padding.as_ptr() as *const _, 1, padding.len(), fout);
        }
    }

    // Write __LINKEDIT data
    unsafe {
        fwrite(finoff, 1, linkedit_cmd.filesize as usize, fout);
        finoff = finoff.add(linkedit_cmd.filesize as usize);
    }

    println!("Total size: {}", finoff as usize - macho.as_ptr() as usize);

    Ok(())
}

// elf
pub fn inject_elf(elf: &[u8], _name: &str, sectdata: &[u8], outfile: &str) -> Result<(), String> {
    let mut elf = elf.to_vec();
    elf.extend_from_slice(sectdata);
    const MAGIC: u32 = 0x501e;

    elf.extend_from_slice(&MAGIC.to_le_bytes());
    elf.extend_from_slice(&(sectdata.len() as u32 + 8).to_le_bytes());

    std::fs::write(outfile, elf).unwrap();

    Ok(())
}

#[cfg(target_os = "linux")]
mod elf {
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;

    pub fn find_section(_: &str) -> Option<Vec<u8>> {
        let exe = std::env::current_exe().unwrap();

        // Check magic and offset
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

        buf = buf[..buf.len() - 9].to_vec();

        return Some(buf);
    }
}
