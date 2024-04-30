use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_uchar};

#[cfg(target_os = "windows")]
mod pe {
    use std::ffi::CString;

    pub fn find_section(section_name: &str) -> Option<&[u8]> {
        let section_name = CString::new(section_name.to_uppercase()).unwrap();

        unsafe {
            let resource_handle = FindResourceA(std::ptr::null_mut(), section_name.as_ptr(), 10);
            if resource_handle.is_null() {
                return None;
            }

            let resource_data = LoadResource(std::ptr::null_mut(), resource_handle);
            if resource_data.is_null() {
                return None;
            }

            let resource_size = SizeofResource(std::ptr::null_mut(), resource_handle);
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

#[cfg(target_os = "linux")]
pub use elf::find_section;

#[cfg(target_os = "macos")]
pub use macho::find_section;

#[cfg(target_os = "windows")]
pub use pe::find_section;

#[cfg(target_os = "linux")]
mod elf {
    fn roundup(x: usize, y: usize) -> usize {
        ((x + y - 1) / y) * y
    }

    use libc::{dl_iterate_phdr, dl_phdr_info, strncmp, Elf64_Phdr, PT_NOTE};
    use std::mem::size_of;
    use std::os::raw::{c_char, c_int, c_void};

    unsafe extern "C" fn sui__dl_iterate_phdr_callback(
        info: *mut dl_phdr_info,
        size: usize,
        data: *mut c_void,
    ) -> c_int {
        // Snag the dl_phdr_info struct then stop iterating.
        *(data as *mut dl_phdr_info) = *info;
        1
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct Elf64_Nhdr {
        pub n_namesz: u32,
        pub n_descsz: u32,
        pub n_type: u32,
    }

    pub fn find_section(elf_section_name: &str) -> Option<&[u8]> {
        unsafe {
            let mut main_program_info: dl_phdr_info = std::mem::zeroed();
            dl_iterate_phdr(
                Some(sui__dl_iterate_phdr_callback),
                &mut main_program_info as *mut dl_phdr_info as *mut c_void,
            );

            let mut p = main_program_info.dlpi_phdr as *const u8;
            let mut n = main_program_info.dlpi_phnum as usize;
            let base = main_program_info.dlpi_addr as usize;

            let mut size = 0;
            loop {
                if n <= 0 {
                    break;
                }
                let phdr = p as *const Elf64_Phdr;
                if (*phdr).p_type == PT_NOTE {
                    let mut pos = base + (*phdr).p_vaddr as usize;
                    let end = pos + (*phdr).p_memsz as usize;

                    while pos < end {
                        if pos + size_of::<Elf64_Nhdr>() > end {
                            break; // invalid
                        }

                        let note = pos as *const Elf64_Nhdr;
                        if (*note).n_namesz != 0
                            && (*note).n_descsz != 0
                            && strncmp(
                                (pos + size_of::<Elf64_Nhdr>()) as *const c_char,
                                elf_section_name.as_ptr() as *const c_char,
                                elf_section_name.len(),
                            ) == 0
                        {
                            size = (*note).n_descsz as usize;

                            let data = pos
                                + size_of::<Elf64_Nhdr>()
                                + roundup((*note).n_namesz as usize, 4);
                            return Some(std::slice::from_raw_parts(data as *const u8, size));
                        }

                        pos += size_of::<Elf64_Nhdr>()
                            + roundup((*note).n_namesz as usize, 4)
                            + roundup((*note).n_descsz as usize, 4);
                    }
                }

                n -= 1;
                p = p.add(size_of::<Elf64_Phdr>());
            }

            None
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum ExecutableFormat {
    ELF,
    MachO,
    PE,
    Unknown,
}

type Write = extern "C" fn(*const u8, usize, *const c_void) -> c_int;

extern "C" {
    #[link_name = "get_executable_format"]
    fn c_get_executable_format(start: *const u8, len: usize) -> ExecutableFormat;

    #[link_name = "inject_into_elf"]
    fn c_inject_into_elf(
        executable_ptr: *const c_uchar,
        executable_size: usize,
        note_name_ptr: *const c_char,
        note_name_size: usize,
        data_ptr: *const c_uchar,
        data_size: usize,
        overwrite: bool,
        user_data: *const c_void,
        write: Write,
    ) -> c_int;

    #[link_name = "inject_into_macho"]
    fn c_inject_into_macho(
        executable_ptr: *const c_uchar,
        executable_size: usize,
        segment_name_ptr: *const c_char,
        segment_name_size: usize,
        section_name_ptr: *const c_char,
        section_name_size: usize,
        data_ptr: *const c_uchar,
        data_size: usize,
        overwrite: bool,
        user_data: *const c_void,
        write: Write,
    ) -> c_int;

    #[link_name = "inject_into_pe"]
    fn c_inject_into_pe(
        executable_ptr: *const c_uchar,
        executable_size: usize,
        resource_name_ptr: *const c_char,
        resource_name_size: usize,
        data_ptr: *const c_uchar,
        data_size: usize,
        overwrite: bool,
        user_data: *const c_void,
        write: Write,
    ) -> c_int;
}

pub fn get_executable_format(data: &[u8]) -> ExecutableFormat {
    unsafe { c_get_executable_format(data.as_ptr(), data.len()) }
}

type RustWrite = Box<dyn Fn(&[u8]) -> Result<(), c_int>>;

extern "C" fn cwrite(data: *const u8, len: usize, user_data: *const c_void) -> c_int {
    let data = unsafe { std::slice::from_raw_parts(data as *const u8, len) };

    let write = unsafe { Box::from_raw(user_data as *mut RustWrite) };
    write(data).map(|_| 0).unwrap_or_else(|e| e)
}

pub fn inject_into_elf(
    executable: &[u8],
    note_name: &str,
    data: &[u8],
    overwrite: bool,
    write: RustWrite,
) -> c_int {
    unsafe {
        c_inject_into_elf(
            executable.as_ptr(),
            executable.len(),
            note_name.as_ptr() as *const c_char,
            note_name.len(),
            data.as_ptr(),
            data.len(),
            overwrite,
            Box::into_raw(Box::new(write)) as *const c_void,
            cwrite,
        )
    }
}

pub fn inject_into_macho(
    executable: &[u8],
    segment_name: &str,
    section_name: &str,
    data: &[u8],
    overwrite: bool,
    write: RustWrite,
) -> c_int {
    unsafe {
        c_inject_into_macho(
            executable.as_ptr(),
            executable.len(),
            segment_name.as_ptr() as *const c_char,
            segment_name.len(),
            section_name.as_ptr() as *const c_char,
            section_name.len(),
            data.as_ptr(),
            data.len(),
            overwrite,
            Box::into_raw(Box::new(write)) as *const c_void,
            cwrite,
        )
    }
}

pub fn inject_into_pe(
    executable: &[u8],
    resource_name: &str,
    data: &[u8],
    overwrite: bool,
    write: RustWrite,
) -> c_int {
    unsafe {
        c_inject_into_pe(
            executable.as_ptr(),
            executable.len(),
            resource_name.as_ptr() as *const c_char,
            resource_name.len(),
            data.as_ptr(),
            data.len(),
            overwrite,
            Box::into_raw(Box::new(write)) as *const c_void,
            cwrite,
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_executable_format() {
        let unknown = b"unknown";

        assert_eq!(
            super::get_executable_format(unknown),
            super::ExecutableFormat::Unknown
        );
    }
}
