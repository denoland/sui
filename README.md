Sui (सुई)

Heavily modified fork of Postject. Available as a CLI tool and a Rust library.

### CLI

```
cargo install sui-cli
```

```shell
$ cp $(command -v deno) .
$ echo "Hello, World!" > hello.txt

$ sui ./deno _SUI hello.txt ./deno_new
$ readelf -n ./deno_new

Displaying notes found in:
  Owner                Data size 	Description
  _SUI                 0x0000000a	Unknown note type: (0x00000000)
   description data: 73 6f 6d 65 20 74 65 78 74 0a
```

### API

Inject into existing Mach-O binary:
```rust
use sui::inject_into_macho;

let executable = fs::read("executable")?;
inject_into_macho(&executable, "__CUSTOM", "__custom", "Hello, World!", |data| {
  fs::write("executable", data);
  Ok(())
})?;
```

Extract from itself:
```rust
use sui::find_section;

let data = find_section("_CUSTOM")
            .expect("Section not found");
```
