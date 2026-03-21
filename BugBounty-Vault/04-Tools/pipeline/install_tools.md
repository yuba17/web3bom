# Tool Installation Guide

## Already Installed
- [x] Foundry (forge v1.5.1) — `C:\Users\Yuba\.foundry\bin\`
- [x] Slither — `pip install slither-analyzer`
- [x] Python 3.13

## To Install Manually

### Medusa (coverage-guided fuzzer)
Option A (recommended): Install Go first, then:
```bash
go install github.com/crytic/medusa@latest
```

Option B: Download prebuilt binary from https://github.com/crytic/medusa/releases
- Look for `medusa_v1.5.1_windows_amd64.zip` or similar
- Extract `medusa.exe` to `C:\Users\Yuba\.foundry\bin\`

### Echidna (grammar-based fuzzer)
Download from https://github.com/crytic/echidna/releases
- Look for `echidna-Windows.zip` or `echidna-x86_64-pc-windows-msvc.zip`
- Extract `echidna.exe` to `C:\Users\Yuba\.foundry\bin\`

### Halmos (symbolic testing)
Requires C++ Build Tools for safe-pysha3:
1. Install Visual C++ Build Tools: https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Then: `pip install halmos`

### Chimera Framework
```bash
forge install Recon-Fuzz/chimera
```
Or add to existing project manually.

## Verification
```bash
forge --version
medusa --version
echidna --version
halmos --version
slither --version
```
