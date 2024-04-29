Sui (सुई)

Heavily modified fork of Postject.

```rust
use sui::Inject;

let mut file = std::fs::File::open("executable")?;

Inject::new(&mut file)
    .inject("__CUSTOM", "Hello, World!")?;
```

```rust
use sui::inject_macho;

let executable = fs::read("executable")?;
inject_macho(&executable, "__CUSTOM", "__custom", "Hello, World!")?;
```
