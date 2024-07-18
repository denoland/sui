use std::env;
use std::path::PathBuf;

fn main() {
    let from_source = env::var("SUI_FROM_SOURCE").is_ok();
    if cfg!(target_os = "windows") && !from_source {
        download_prebuilt();
    } else {
        let mut config = cmake::Config::new(".");
        config
            .define("BUILD_SHARED_LIBS", "OFF")
            .define("LIEF_USE_CRT_RELEASE", "MTd")
            .static_crt(true)
            .build();
        let dst = config.build();

        println!(
            "cargo:rustc-link-search=native={}",
            dst.join("build").display()
        );
        println!(
            "cargo:rustc-link-search=native={}",
            dst.join("lib").display()
        );

        let lib_path = dst.join("build").join("lib");
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        // On windows, a new folder is created for the static lib
        let lib_path = dst.join("build").join("Release");
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        let lib_path = dst.join("build").join("Debug");
        println!("cargo:rustc-link-search=native={}", lib_path.display());

        let lief_lib_path = dst.join("build").join("LIEF").join("lib");
        println!("cargo:rustc-link-search=native={}", lief_lib_path.to_str().unwrap());
    }

    println!("cargo:rustc-link-lib=static=LIEF");
    println!("cargo:rustc-link-lib=static=sui");

    #[cfg(target_os = "linux")]
    {
      println!("cargo:rustc-link-lib=dylib=stdc++");
      println!("cargo:rustc-link-lib=dylib=c_nonshared");
    }
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=dylib=c++");
}

fn download_prebuilt() {
    let (url, lief_url) = static_lib_url();
    println!("Downloading prebuilt lib from {}", url);

    let out_dir = static_lib_dir();
    std::fs::create_dir_all(&out_dir).unwrap();
    println!("cargo:rustc-link-search={}", out_dir.display());

    match std::fs::read_to_string(static_checksum_path()) {
        Ok(c) if c.trim() == url => {
            println!("Using cached prebuilt lib");
            return;
        }
        _ => {}
    };

    let sui_lib = std::process::Command::new("curl")
        .arg("-L")
        .arg("-o")
        .arg(out_dir.join("sui.lib"))
        .arg(url.clone())
        .status()
        .expect("Failed to download prebuilt lib");
    assert!(sui_lib.success());
    let lief_lib = std::process::Command::new("curl")
        .arg("-L")
        .arg("-o")
        .arg(out_dir.join("LIEF.lib"))
        .arg(lief_url)
        .status()
        .expect("Failed to download prebuilt lib");
    assert!(lief_lib.success());

    std::fs::write(static_checksum_path(), url).unwrap();
}

fn static_lib_name() -> &'static str {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "windows" {
        "sui.lib"
    } else {
        "libsui.a"
    }
}

fn static_lib_path() -> PathBuf {
    static_lib_dir().join(static_lib_name())
}

fn static_lib_dir() -> PathBuf {
    build_dir().join("out")
}

fn static_checksum_path() -> PathBuf {
    let mut t = static_lib_path();
    t.set_extension("sum");
    t
}

fn build_dir() -> PathBuf {
    let root = env::current_dir().unwrap();

    let out_dir = env::var_os("OUT_DIR").expect(
        "The 'OUT_DIR' environment is not set (it should be something like \
     'target/debug/sui-{hash}').",
    );
    let out_dir_abs = root.join(out_dir);

    // This would be target/debug or target/release
    out_dir_abs
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn static_lib_url() -> (String, String) {
    let default_base = "https://github.com/littledivy/sui/releases/download";
    let base = env::var("SUI_MIRROR").unwrap_or_else(|_| default_base.into());
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    // Note: we always use the release build on windows.
    if target_os == "windows" {
        return (
            format!("{}/{}/sui.lib", base, version),
            format!("{}/{}/LIEF.lib", base, version),
        );
    }

    unimplemented!()
}
