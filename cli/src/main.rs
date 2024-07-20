use libsui::find_section;

const HELP: &str = r#"Usage: sui <exe> <segment> <data_file> <output>"#;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        if let Some(section) = find_section("__SUI") {
            println!("Found section: {:?}", std::str::from_utf8(&section));
        }
        eprintln!("{}", HELP);
        std::process::exit(1);
    }

    let exe = std::fs::read(&args[1]).unwrap();
    let data = std::fs::read(&args[3]).unwrap();

    // libsui::inject_macho(&exe, &args[2], &args[2], &data, &args[4]);
    // libsui::inject_pe(&exe, &args[2], &data, &args[4]).unwrap();

    libsui::inject_elf(&exe, &args[2], &data, &args[4]).unwrap();
}
