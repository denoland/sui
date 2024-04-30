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

### Design

**Windows**

For PE executables, the resources are added into the `.rsrc` section,
with the `RT_RCDATA` (raw data) type.

The build-time equivalent is adding the binary data as a resource in
the usual manner, such as the Resource Compiler, and marking it as
`RT_RCDATA`.

The run-time lookup uses the `FindResource` and `LoadResource` APIs.

**macOS**

For Mach-O executables, the resources are added as sections inside a
new segment.

The build-time equivalent of embedding binary data with this approach
uses a linker flag: `-sectcreate,__FOO,__foo,content.txt`

**Linux**

For ELF executables, the resources are added as notes.

The build-time equivalent is to use a linker script.
