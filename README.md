Sui (सुई)

Heavily modified fork of Postject.

```rust
use sui::inject_into_macho;

let executable = fs::read("executable")?;
inject_into_macho(&executable, "__CUSTOM", "__custom", "Hello, World!", |data| {
  fs::write("executable", data);
  Ok(())
})?;
```
