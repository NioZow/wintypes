# wintypes

> A rust library that exports windows functions as types

# Usage

Once this library is downloaded you can just use a function as a type by DLL:

```rust
use wintypes::user32::FnMessageBoxA;
```

# Build

## Get DLLs exported functions

The first step is to get the exported functions of the DLLs:

```sh
$ scripts/parse_dll_exports.py ~/SharedFolder/dlls/advapi32.dll ~/SharedFolder/dlls/crypt32.dll ~/SharedFolder/dlls/kernel32.dll ~/SharedFolder/dlls/kernelbase.dll ~/SharedFolder/dlls/winhttp.dll ~/SharedFolder/dlls/ntdll.dll | jq . > exports.json
```

## Generate the types

```sh
$ ./scripts/parse_doc_crates.py exports.json
```

# Credits

- `ntapi` and `winapi` for implementing windows functions as functions. This project scrapes prototypes from those crates.
