<div align="center">

# Amsi-Go

**AMSI Bypass Patcher Written in Go**

[![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

*In-memory AMSI patch implemented in Go for red team operations*

</div>

---

## Overview

**Amsi-Go** patches the Windows Antimalware Scan Interface (AMSI) directly in memory using Go. The binary compiles with no console window (`-H=windowsgui`), making it suitable for use in offensive engagements where stealth is required.

## Features

- **In-Memory Patching** — Modifies `AmsiScanBuffer` at runtime without touching disk
- **No Console Window** — Compiles as a GUI application for stealth
- **Stripped Binary** — Debug symbols removed for smaller footprint
- **Go Native** — No CGO dependencies, single static binary

## Build

```bash
go build -ldflags "-H=windowsgui -s -w" .\main.go
```

| Flag | Purpose |
|------|---------|
| `-H=windowsgui` | No console window on execution |
| `-s` | Strip symbol table |
| `-w` | Strip DWARF debug info |

## Screenshots

**Before Patch — AMSI Active:**

[![test1.png](https://i.postimg.cc/mkgw7kc5/test1.png)](https://postimg.cc/YGTYHpz6)

**After Patch — AMSI Bypassed:**

[![test2.png](https://i.postimg.cc/DyDgb27x/test2.png)](https://postimg.cc/6yrRkx2Z)

## Legal Disclaimer

> **This tool is intended for authorized penetration testing and security research only.** Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse of this software.

## Author

**[@3xploit666](https://github.com/3xploit666)**

---

<div align="center">

*For educational and authorized security testing purposes only.*

</div>
