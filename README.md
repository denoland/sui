Sui (सुई)

Heavily modified fork of Postject. Available as a CLI tool and a Rust library.

```
cargo install sui-cli
```

```shell
cp $(command -v deno) .
echo "Hello, World!" > hello.txt

sui ./deno __CUSTOM_NOTE hello.txt ./deno_new
readelf -n ./deno_new
```

```rust
use sui::inject_into_macho;

let executable = fs::read("executable")?;
inject_into_macho(&executable, "__CUSTOM", "__custom", "Hello, World!", |data| {
  fs::write("executable", data);
  Ok(())
})?;
```
