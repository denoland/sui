use libsui::find_section;
use libsui::Macho;
use libsui::PortableExecutable;

const HELP: &str = r#"Usage: sui <exe> <data_file> <output>"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        if let Some(section) = find_section("__SUI") {
            println!("Found section: {:?}", std::str::from_utf8(&section));
        }
        eprintln!("{}", HELP);
        std::process::exit(1);
    }

    let exe = std::fs::read(&args[1])?;
    let data = std::fs::read(&args[3])?;

    let mut out = std::fs::File::create(&args[4])?;
    // libsui::inject_macho(&exe, &args[2], &args[2], &data, &args[4]);
    // libsui::inject_pe(&exe, &args[2], &data, &args[4]).unwrap();

    // PortableExecutable::from(&exe)?
    //    .write_resource("_SUI", data)?
    //    .build(&mut out)?;

    Macho::from(exe)
        .write_section("__SUI", data)?
        .build(&mut out)?;

    //    Elf::new(&exe)
    //        .append(&data);
    Ok(())
}
