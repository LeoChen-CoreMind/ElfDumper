# ElfDumper

An IDA Pro plugin for dumping ELF binaries from memory. Useful for extracting unpacked/decrypted ELF files during dynamic debugging sessions.

Supports both **32-bit** and **64-bit** ELF formats.

## Features

- Dump ELF segments (PT_LOAD / PT_DYNAMIC) directly from IDA Pro's memory
- Reconstruct ELF files based on Program Header Table
- Support for x86 (32-bit) and x64 (64-bit) ELF binaries
- Lightweight, zero-dependency (only requires IDA Pro's `idc` module)

## Requirements

- IDA Pro 9.0+ (with IDAPython)

## Installation

Copy `DumpELF_x64.py` and `DumpELF_x86.py` to your IDA Pro plugins or scripts directory:

```
%IDADIR%/plugins/
```

Or simply load them via **File → Script file...** in IDA Pro.

## Usage

In IDA Pro's Python console or script:

### Dump a 64-bit ELF

```python
import DumpELF_x64

# addr: the base address of the ELF in memory
# output_path: (optional) output file path, defaults to "ELF.dump"
DumpELF_x64.main(0x400000)

# or specify output path
DumpELF_x64.main(0x400000, "dumped_binary.so")
```

### Dump a 32-bit ELF

```python
import DumpELF_x86

DumpELF_x86.main(0x8048000)

# or specify output path
DumpELF_x86.main(0x8048000, "dumped_binary.so")
```

## How It Works

1. Reads the ELF header at the given base address to locate the Program Header Table
2. Iterates through program headers, filtering for `PT_LOAD` (type 1) and `PT_DYNAMIC` (type 2) segments
3. Dumps each segment's memory content to the output file at the correct file offset
4. Produces a reconstructed ELF file that can be further analyzed with static tools

## Use Cases

- Dumping packed/encrypted ELF binaries after they are unpacked in memory
- Extracting decrypted shared libraries (`.so`) from Android native layers
- Capturing runtime-modified ELF binaries during dynamic analysis

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**LeoChen**
