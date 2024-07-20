use libc::{dl_iterate_phdr, dl_phdr_info, strncmp, Elf64_Phdr, PT_NOTE};
use std::mem::size_of;
use std::os::raw::{c_char, c_int, c_void};

fn roundup(x: usize, y: usize) -> usize {
    ((x + y - 1) / y) * y
}

unsafe extern "C" fn sui_dl_iterate_phdr_callback(
    info: *mut dl_phdr_info,
    _size: usize,
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

pub fn find_section2(elf_section_name: &str) -> Option<&[u8]> {
    unsafe {
        let mut main_program_info: dl_phdr_info = std::mem::zeroed();
        dl_iterate_phdr(
            Some(sui_dl_iterate_phdr_callback),
            &mut main_program_info as *mut dl_phdr_info as *mut c_void,
        );

        let mut p = main_program_info.dlpi_phdr as *const u8;
        let mut n = main_program_info.dlpi_phnum as usize;
        let base = main_program_info.dlpi_addr as usize;

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
                        let size = (*note).n_descsz as usize;

                        let data =
                            pos + size_of::<Elf64_Nhdr>() + roundup((*note).n_namesz as usize, 4);
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
use std::io::SeekFrom;
use std::io::Read;
use std::io::Seek;
pub fn find_section(elf_section_name: &str) -> Option<Vec<u8>> {
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

