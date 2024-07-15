use std::ffi::CString;

use windows_sys::Win32::System::LibraryLoader::FindResourceA;
use windows_sys::Win32::System::LibraryLoader::LoadResource;
use windows_sys::Win32::System::LibraryLoader::LockResource;
use windows_sys::Win32::System::LibraryLoader::SizeofResource;

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
