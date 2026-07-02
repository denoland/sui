//! Exports a single C entry point that reads an embedded sui section from the
//! dylib it is loaded into, exercising `find_section_in_current_image`.

/// Writes the embedded section for `name` into `out`/`out_len` and returns
/// `true` when found. `name` is a NUL-terminated C string.
///
/// # Safety
/// `name` must be a valid NUL-terminated pointer; `out`/`out_len` must be valid
/// writable pointers.
#[no_mangle]
pub unsafe extern "C" fn sui_probe_section(
    name: *const std::os::raw::c_char,
    out: *mut *const u8,
    out_len: *mut usize,
) -> bool {
    let name = std::ffi::CStr::from_ptr(name).to_str().unwrap_or("");
    match libsui::find_section_in_current_image(name) {
        Ok(Some(data)) => {
            *out = data.as_ptr();
            *out_len = data.len();
            true
        }
        _ => {
            *out = std::ptr::null();
            *out_len = 0;
            false
        }
    }
}
