mod sui;

pub use sui::inject_into_elf;
pub use sui::inject_into_macho;
pub use sui::inject_into_pe;

pub use sui::get_executable_format;
pub use sui::ExecutableFormat;

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
