use std::os::raw::{c_int, c_char, c_uchar};
use std::ffi::c_void;

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
    fn c_inject_into_elf(executable_ptr: *const c_uchar,
                       executable_size: usize,
                       note_name_ptr: *const c_char,
                       note_name_size: usize,
                       data_ptr: *const c_uchar,
                       data_size: usize,
                       overwrite: bool,
                       user_data: *const c_void,
                       write: Write) -> c_int;

    #[link_name = "inject_into_macho"]
    fn c_inject_into_macho(executable_ptr: *const c_uchar,
                         executable_size: usize,
                         segment_name_ptr: *const c_char,
                         segment_name_size: usize,
                         section_name_ptr: *const c_char,
                         section_name_size: usize,
                         data_ptr: *const c_uchar,
                         data_size: usize,
                         overwrite: bool,
                         user_data: *const c_void,
                         write: Write) -> c_int;

    #[link_name = "inject_into_pe"]
    fn c_inject_into_pe(executable_ptr: *const c_uchar,
                      executable_size: usize,
                      resource_name_ptr: *const c_char,
                      resource_name_size: usize,
                      data_ptr: *const c_uchar,
                      data_size: usize,
                      overwrite: bool,
                      user_data: *const c_void,
                      write: Write) -> c_int;
}

pub fn get_executable_format(data: &[u8]) -> ExecutableFormat {
    unsafe {
        c_get_executable_format(data.as_ptr(), data.len())
    }
}

type RustWrite = Box<dyn Fn(&[u8]) -> Result<(), c_int>>;

extern "C" fn cwrite(data: *const u8, len: usize, user_data: *const c_void) -> c_int {
    let data = unsafe {
        std::slice::from_raw_parts(data as *const u8, len)
    };

    let write = unsafe {
        Box::from_raw(user_data as *mut RustWrite)
    };
    write(data).map(|_| 0).unwrap_or_else(|e| e)
}

pub fn inject_into_elf(executable: &[u8],
                       note_name: &str,
                       data: &[u8],
                       overwrite: bool,
                       write: RustWrite) -> c_int {
    unsafe {
        c_inject_into_elf(executable.as_ptr(),
                        executable.len(),
                        note_name.as_ptr() as *const c_char,
                        note_name.len(),
                        data.as_ptr(),
                        data.len(),
                        overwrite,
                        Box::into_raw(Box::new(write)) as *const c_void,
                        cwrite)
    }
}

pub fn inject_into_macho(executable: &[u8],
                         segment_name: &str,
                         section_name: &str,
                         data: &[u8],
                         overwrite: bool,
                         write: RustWrite) -> c_int {
    unsafe {
        c_inject_into_macho(executable.as_ptr(),
                          executable.len(),
                          segment_name.as_ptr() as *const c_char,
                          segment_name.len(),
                          section_name.as_ptr() as *const c_char,
                          section_name.len(),
                          data.as_ptr(),
                          data.len(),
                          overwrite,
                          Box::into_raw(Box::new(write)) as *const c_void,
                          cwrite)
    }
}

pub fn inject_into_pe(executable: &[u8],
                      resource_name: &str,
                      data: &[u8],
                      overwrite: bool,
                      write: RustWrite) -> c_int {
    unsafe {
        c_inject_into_pe(executable.as_ptr(),
                       executable.len(),
                       resource_name.as_ptr() as *const c_char,
                       resource_name.len(),
                       data.as_ptr(),
                       data.len(),
                       overwrite,
                       Box::into_raw(Box::new(write)) as *const c_void,
                       cwrite)
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
