use libsui::find_section;
use libsui::Elf;
use libsui::Macho;
use libsui::PortableExecutable;

use libsui::utils;

const HELP: &str = r#"Usage: sui <exe> <data_file> <output>"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(section) = find_section("__SUI") {
        println!("Found section");
        println!("{}", std::str::from_utf8(section)?);
        return Ok(());
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("{}", HELP);
        std::process::exit(1);
    }

    let exe = std::fs::read(&args[1])?;
    let data = std::fs::read(&args[2])?;

    let mut out = std::fs::File::create(&args[3])?;

    if utils::is_pe(&exe) {
        PortableExecutable::from(&exe)?
            .write_resource("_SUI", data)?
            .build(&mut out)?;
    } else if utils::is_macho(&exe) {
        let mut settings = apple_codesign::SigningSettings::default();
        settings.set_binary_identifier(apple_codesign::SettingsScope::Main, "sui");

        Macho::from(exe)?
            .write_section("__SUI", data)?
            //.build_and_sign(&settings, &mut out)?;
            .build(&mut out)?;
    } else if utils::is_elf(&exe) {
        Elf::new(&exe).append(&data, &mut out)?;
    } else {
        eprintln!("Unsupported file format");
        std::process::exit(1);
    }

    Ok(())
}
