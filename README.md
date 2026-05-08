<div align="center">

```
███████╗██╗   ██╗██╗██╗     ██╗ █████╗
██╔════╝██║   ██║██║██║     ██║██╔══██╗
███████╗██║   ██║██║██║     ██║███████║
╚════██║╚██╗ ██╔╝██║██║     ██║██╔══██║
███████║ ╚████╔╝ ██║███████╗██║██║  ██║
╚══════╝  ╚═══╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝
```

**Intelligent File Analysis Tool**

*Metadata · Image Intelligence · Context Resolver*

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)]()
[![stdlib](https://img.shields.io/badge/stdlib%20only-no%20pip%20required-success?style=flat-square)]()

</div>

---

## What is Svilia?

**Svilia** is a zero-dependency Python CLI tool that extracts deep intelligence from any file. It combines three powerful analysis modules into a single script — no virtual environments, no `pip install`, just Python 3 and a file.

```bash
python3 svilia.py all photo.jpg
```

```
╔═══════════════════════════════════════════════════════════╗
║                      S V I L I A  v1.0                    ║
║         Metadata · Image Intelligence · Context           ║
╚═══════════════════════════════════════════════════════════╝

──────────────── METADATA ANALYZER ─────────────────
  File                      photo.jpg
  Size                      4.2 MB  (4,412,819 bytes)
  MIME Type                 image/jpeg
  Detected                  JPEG Image
  MD5                       d41d8cd98f00b204e9800998ecf8427e
  SHA-256                   e3b0c44298fc1c149afb...
  ...

──────────── IMAGE INTELLIGENCE EXTRACTOR ────────────
  Format                    JPEG
  Width                     4032
  Height                    3024
  Camera Make               Apple
  Camera Model              iPhone 14 Pro
  ISO                       64
  Iso Context               Good light conditions
  Datetime Original         2024:07:15 14:32:01
  ...

────────────────── CONTEXT RESOLVER ──────────────────
  Capture Datetime          2024:07:15 14:32:01
  Capture Day Of Week       Monday
  Photo Age                 9 months
  Geo City                  Istanbul
  Geo Country               Turkey
  Device                    Apple iPhone 14 Pro
  ...
```

---

## Modules

### 🔵 Metadata Analyzer
Extracts deep file metadata from any file type.

| Feature | Details |
|---|---|
| File info | Name, size, MIME type, permissions, timestamps |
| Magic bytes | Real format detection via binary signatures (20+ formats) |
| Hashing | MD5, SHA-1, SHA-256, CRC32 |
| Type detection | JPEG, PNG, PDF, ZIP, EXE, MP3, MP4, TIFF, PSD and more |
| Text stats | Line count, word count, character count, encoding detection |

### 🟣 Image Intelligence Extractor
Deep analysis of image files — no external libraries needed.

| Format | Extracted Data |
|---|---|
| **JPEG** | Width/height/bit-depth from SOF markers, full EXIF parser (40+ tags) |
| **PNG** | IHDR chunk, color type, gamma, sRGB intent, tEXt/iTXt metadata |
| **GIF** | Version, Global Color Table size, pixel aspect ratio |
| **BMP** | DIB header version, compression mode, bit depth |

EXIF tags include: camera make/model, lens, ISO, aperture (f-number), focal length, flash status, GPS coordinates, capture datetime, software, artist, copyright and more.

Supported formats: `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.webp` `.tiff` `.tif`

### 🟢 Context Resolver
Connects file data to the real world via live APIs and system context.

| Category | What it resolves |
|---|---|
| **Temporal** | File age (human-readable), local timezone, EXIF capture date/day/month, photo age |
| **Geolocation** | GPS EXIF → OpenStreetMap reverse geocode (city, state, country, postcode) |
| **IP Geolocation** | If no GPS: analysis location via ipapi.co (city, country, ISP, timezone) |
| **Device** | Camera make/model, lens, ISO interpretation ("Low light", "Night"), flash |
| **Network** | Hostname, local IP address |
| **Provenance** | Analysis timestamp, Python version, edit detection (ctime vs mtime) |

---

## Installation

### Requirements

- Python 3.6+
- No external packages — uses stdlib only

### Ubuntu / Debian

```bash
# Check Python version (3.6+ required)
python3 --version

# Download svilia.py and move to home directory
mv ~/Downloads/svilia.py ~/svilia.py

# Make executable
chmod +x ~/svilia.py

# Run
python3 ~/svilia.py all photo.jpg
```

### Global install (run from anywhere)

```bash
sudo cp ~/svilia.py /usr/local/bin/svilia
sudo chmod +x /usr/local/bin/svilia

# Now works from any directory
svilia all photo.jpg
```

### macOS

```bash
# Python 3 via Homebrew (if not installed)
brew install python3

chmod +x svilia.py
python3 svilia.py all photo.jpg
```

### Windows

```powershell
python svilia.py all photo.jpg
```

---

## Usage

```
python3 svilia.py <command> <file>
```

| Command | Description |
|---|---|
| `all` | Run all three modules |
| `metadata` | Metadata Analyzer only |
| `image` | Image Intelligence Extractor only |
| `context` | Context Resolver only |

### Examples

```bash
# Full analysis on a photo
python3 svilia.py all vacation.jpg

# Extract metadata from any file
python3 svilia.py metadata document.pdf
python3 svilia.py metadata archive.zip
python3 svilia.py metadata script.py

# Image intelligence
python3 svilia.py image photo.png
python3 svilia.py image scan.tiff

# Real-world context
python3 svilia.py context photo.jpg
```

---

## Supported File Formats

Svilia works on **any file** for metadata analysis. Image Intelligence is available for:

```
JPEG  PNG  GIF  BMP  WEBP  TIFF
```

Magic byte detection recognizes:

```
JPEG  PNG  GIF  PDF  ZIP  GZIP  BZIP2  ELF  EXE/PE
MP3 (ID3)  MP4/MOV  PSD  TIFF  MS Office  RIFF (WAV/AVI/WEBP)
UTF-8 BOM  UTF-16 LE/BE  DOCX/XLSX (ZIP-based)
```

---

## Output Example — Full Analysis

<details>
<summary>Click to expand full output</summary>

```
╔═══════════════════════════════════════════════════════════╗
║                      S V I L I A  v1.0                    ║
║         Metadata · Image Intelligence · Context           ║
╚═══════════════════════════════════════════════════════════╝

──────────────────── METADATA ANALYZER ─────────────────────
  File                      sunset.jpg
  Size                      3.1 MB  (3,248,192 bytes)
  MIME Type                 image/jpeg
  Detected                  JPEG Image
  Encoding                  —
  Magic Bytes               FF D8 FF E1 18 4A 45 78 69 66 00 00 49 49
  Permissions               0644
  Is Symlink                False
  Created                   2024-07-15T14:32:01.000000
  Modified                  2024-07-15T14:32:01.000000
  Accessed                  2024-07-16T09:00:00.000000
  MD5                       d41d8cd98f00b204e9800998ecf8427e
  SHA-1                     da39a3ee5e6b4b0d3255bfef95601890afd80709
  SHA-256                   e3b0c44298fc1c149afbf4c8996fb92427ae41e4
  CRC32                     00000000

──────────────── IMAGE INTELLIGENCE EXTRACTOR ───────────────
  Format                    JPEG
  Width                     4032
  Height                    3024
  Bit Depth                 8
  Color Mode                YCbCr/RGB
  Progressive               No
  Exif Byte Order           Little-endian (Intel)
  Camera Make               Apple
  Camera Model              iPhone 14 Pro
  Datetime Original         2024:07:15 14:32:01
  Iso Speed                 64
  F Number                  9/5
  Focal Length              77/20
  Flash                     16
  Software                  16.5.1
  Pixel X Dimension         4032
  Pixel Y Dimension         3024
  Lens Model                iPhone 14 Pro back triple camera 6.86mm f/1.78

──────────────────── CONTEXT RESOLVER ───────────────────────
  File Age                  9 months
  Local Timezone            UTC+3
  Capture Datetime          2024:07:15 14:32:01
  Capture Day Of Week       Monday
  Capture Year              2024
  Capture Month             July
  Photo Age                 9 months
  Geo City                  Istanbul
  Geo State                 Istanbul
  Geo Country               Turkey
  Geo Postcode              34000
  Geo Country Code          TR
  Device                    Apple iPhone 14 Pro
  Iso                       64
  Iso Context               Good light conditions
  Flash Fired               False
  Lens                      iPhone 14 Pro back triple camera 6.86mm f/1.78
  Analysis Host             mypc
  Local Ip                  192.168.1.100
  Analyzed At               2025-05-09T00:06:00.000000
  Tool                      Svilia v1.0
  Python Version            3.12.3
  File Likely Edited        Probably not (ctime ≈ mtime)

──────────────────────────────────────────────────────────────
  ✓  Svilia analysis complete — sunset.jpg
```

</details>

---

## Project Structure

```
svilia/
└── svilia.py          # Single-file tool — everything in one place
```

Svilia is intentionally a single file. No setup.py, no requirements.txt, no virtual environment. Clone or download and run.

---

## Architecture

```
svilia.py
├── MetadataAnalyzer        # File system + hashing + magic bytes + text stats
├── ImageIntelligenceExtractor
│   ├── JPEG parser         # SOF markers + EXIF (40+ tags, pure Python)
│   ├── PNG parser          # IHDR + tEXt/iTXt + gAMA + sRGB chunks
│   ├── GIF parser          # Header + LSD block
│   └── BMP parser          # DIB header + compression info
└── ContextResolver
    ├── Temporal context     # File age, EXIF datetime parsing
    ├── Geo context          # Nominatim reverse geocode / ipapi.co
    ├── Device context       # Camera, lens, ISO interpretation
    ├── Network context      # Hostname, local IP
    └── Provenance context   # Edit detection, analysis timestamp
```

---

## Why no dependencies?

Svilia parses binary formats directly — JPEG SOF/EXIF markers, PNG chunks, GIF headers, BMP DIB blocks — using Python's `struct` module. This means:

- Works on any system with Python 3.6+
- No `pip install` ever needed
- No version conflicts
- Air-gapped environments supported
- Single file, copy anywhere

---

## Roadmap

- [ ] `--json` output flag for piping to other tools
- [ ] `--quiet` flag (hashes + key fields only)
- [ ] Video Intelligence module (MP4/MOV metadata)
- [ ] Audio Intelligence module (ID3/MP3 tags)
- [ ] PDF Intelligence module (author, creation tool, page count)
- [ ] Batch mode: `svilia all *.jpg`
- [ ] Cipher / Encryption Analyzer module (`svilia-cipher` integration)

---

## License

```
MIT License

Copyright (c) 2025 sviliadookrpg

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

Made with Python · Zero dependencies · Works everywhere

</div>
