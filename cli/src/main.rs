use libsui::find_section;
use libsui::ExecutableFormat;

const HELP: &str = r#"Usage: sui <exe> <segment> <data_file> <output>"#;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        if let Some(section) = find_section("__SUI") {
            println!("Found section: {:?}", section);
        }
        eprintln!("{}", HELP);
        std::process::exit(1);
    }

    let exe = std::fs::read(&args[1]).unwrap();
    let data = std::fs::read(&args[3]).unwrap();

    let out = args[4].clone();
    let writer = move |data: &[u8]| {
        println!("Writing to {}", out);
        std::fs::write(&out, data).unwrap();
        Ok(())
    };

    match libsui::get_executable_format(&exe) {
        ExecutableFormat::ELF => {
            libsui::inject_into_elf(&exe, &args[2], &data, true, Box::new(writer));
        }
        ExecutableFormat::MachO => {
            libsui::inject_into_macho(&exe, &args[2], &args[2], &data, true, Box::new(writer));
        }
        ExecutableFormat::PE => {
            libsui::inject_into_pe(&exe, &args[2], &data, true, Box::new(writer));
        }
        _ => {
            eprintln!("Unknown executable format");
            std::process::exit(1);
        }
    }
}
