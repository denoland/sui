use sui::ExecutableFormat;
use sui::find_section;

const HELP: &str = r#"
Usage: sui <exe> <segment> <data_file> <output>
"#;

fn main() {
  let args: Vec<String> = std::env::args().collect();
  if args.len() != 5 {
    let section = find_section("_SUI").unwrap();
    eprintln!("{}", HELP);
    std::process::exit(1);
  }
  
  let exe = std::fs::read(&args[1]).unwrap();
  let data = std::fs::read(&args[3]).unwrap();

  let out = args[4].clone();
  let writer = move |data: &[u8]| {
    std::fs::write(&out, data).unwrap();
    Ok(())
  };

  match sui::get_executable_format(&exe) {
      ExecutableFormat::ELF => {
          sui::inject_into_elf(&exe, &args[2], &data, true, Box::new(writer));
      },
      ExecutableFormat::MachO => {
          sui::inject_into_macho(&exe, &args[2], &args[2], &data, true, Box::new(writer));
      },
      ExecutableFormat::PE => {
          sui::inject_into_pe(&exe, &args[2], &data, true, Box::new(writer));
      },
      _ => {
          eprintln!("Unknown executable format");
          std::process::exit(1);
      }
  }
}
