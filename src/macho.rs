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
