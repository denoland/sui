#[cfg(target_os = "linux")]
mod elf;
#[cfg(target_os = "macos")]
mod macho;
#[cfg(target_os = "windows")]
mod pe;

#[cfg(target_os = "linux")]
pub use elf::find_section;
#[cfg(target_os = "macos")]
pub use macho::find_section;
#[cfg(target_os = "windows")]
pub use pe::find_section;

use std::fs::File;

// pe

use editpe::constants::RT_RCDATA;
use editpe::constants::{CODE_PAGE_ID_EN_US, LANGUAGE_ID_EN_US};
use editpe::types::{ResourceDirectoryTable, VersionU16};
use editpe::Image;
use editpe::ResourceEntry;
use editpe::ResourceEntryName;
use editpe::ResourceTable;

pub fn inject_pe(pe: &[u8], name: &str, sectdata: &[u8], outfile: &str) -> Result<(), String> {
    let mut image = Image::parse(pe).unwrap();

    let mut resources = image.resource_directory().cloned().unwrap_or_default();
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
            return Err("icon table is not a table".to_string());
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
            return Err("icon table is not a table".to_string());
        }
    };
    let mut entry = editpe::ResourceData::default();
    entry.set_data(sectdata.to_vec());

    rc_table.insert(
        ResourceEntryName::ID(LANGUAGE_ID_EN_US as u32),
        ResourceEntry::Data(entry),
    );

    image.set_resource_directory(resources).unwrap();

    let target = image.data();
    std::fs::write(outfile, target).unwrap();

    Ok(())
}

// mach-o

#[repr(C)]
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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

    let Some(mut linkedit_cmd) = linkedit_cmd else {
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

    let old_ncmds = header.ncmds;
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
