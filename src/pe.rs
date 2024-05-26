use std::ffi::CString;

pub fn find_section(section_name: &str) -> Option<&[u8]> {
    None
    // let section_name = CString::new(section_name.to_uppercase()).unwrap();

    // unsafe {
    //     let resource_handle = FindResourceA(std::ptr::null_mut(), section_name.as_ptr(), 10);
    //     if resource_handle.is_null() {
    //         return None;
    //     }

    //     let resource_data = LoadResource(std::ptr::null_mut(), resource_handle);
    //     if resource_data.is_null() {
    //         return None;
    //     }

    //     let resource_size = SizeofResource(std::ptr::null_mut(), resource_handle);
    //     if resource_size == 0 {
    //         return None;
    //     }

    //     let resource_ptr = LockResource(resource_data);
    //     Some(std::slice::from_raw_parts(
    //         resource_ptr as *const u8,
    //         resource_size as usize,
    //     ))
    // }
}
