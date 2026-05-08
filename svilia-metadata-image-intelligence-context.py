#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║                      S V I L I A                          ║
║         Metadata · Image Intelligence · Context           ║
╚═══════════════════════════════════════════════════════════╝

Svilia — an intelligent file analysis tool.
Modules:
  - Metadata Analyzer     : Extract deep metadata from any file
  - Image Intelligence    : Analyze images (EXIF, colors, composition)
  - Context Resolver      : Connect files to real-world context (geo, time, web)

Usage:
  python svilia.py metadata <file>
  python svilia.py image    <file>
  python svilia.py context  <file>
  python svilia.py all      <file>
"""

import os
import sys
import json
import hashlib
import mimetypes
import struct
import zlib
import datetime
import socket
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path


# ─────────────────────────────────────────────
# ANSI Colors
# ─────────────────────────────────────────────
R  = "\033[0m"
B  = "\033[1m"
DIM = "\033[2m"
CYN = "\033[96m"
GRN = "\033[92m"
YLW = "\033[93m"
RED = "\033[91m"
MGT = "\033[95m"
BLU = "\033[94m"

def banner():
    print(f"""
{CYN}{B}╔═══════════════════════════════════════════════════════════╗
║                      S V I L I A  v1.0                    ║
║         Metadata · Image Intelligence · Context           ║
╚═══════════════════════════════════════════════════════════╝{R}
""")

def section(title: str, color=CYN):
    width = 54
    pad = (width - len(title) - 2) // 2
    print(f"\n{color}{B}{'─'*pad} {title} {'─'*(width-pad-len(title)-2)}{R}")

def row(label: str, value, label_color=YLW, val_color=R):
    print(f"  {label_color}{B}{label:<26}{R}{val_color}{value}{R}")

def warn(msg): print(f"  {YLW}⚠  {msg}{R}")
def err(msg):  print(f"  {RED}✗  {msg}{R}")
def ok(msg):   print(f"  {GRN}✓  {msg}{R}")


# ═══════════════════════════════════════════════════════════
# MODULE 1 — METADATA ANALYZER
# ═══════════════════════════════════════════════════════════

class MetadataAnalyzer:
    """Extract deep metadata from any file type."""

    def __init__(self, filepath: str):
        self.path = Path(filepath).resolve()

    def run(self):
        section("METADATA ANALYZER", CYN)
        if not self.path.exists():
            err(f"File not found: {self.path}")
            return {}

        meta = {}

        # ── Basic file info ──────────────────────────────
        stat = self.path.stat()
        meta["name"]       = self.path.name
        meta["stem"]       = self.path.stem
        meta["suffix"]     = self.path.suffix or "(none)"
        meta["size_bytes"] = stat.st_size
        meta["size_human"] = self._human_size(stat.st_size)
        meta["created"]    = datetime.datetime.fromtimestamp(stat.st_ctime).isoformat()
        meta["modified"]   = datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()
        meta["accessed"]   = datetime.datetime.fromtimestamp(stat.st_atime).isoformat()
        meta["permissions"]= oct(stat.st_mode)[-4:]
        meta["is_symlink"] = self.path.is_symlink()
        meta["absolute_path"] = str(self.path)

        # ── MIME type ────────────────────────────────────
        mime, enc = mimetypes.guess_type(str(self.path))
        meta["mime_type"] = mime or "application/octet-stream"
        meta["encoding"]  = enc or "—"

        # ── Hashes ───────────────────────────────────────
        meta.update(self._compute_hashes())

        # ── Magic bytes ──────────────────────────────────
        meta["magic_bytes"] = self._magic_bytes()
        meta["detected_type"] = self._detect_type(meta["magic_bytes"])

        # ── Text stats (if text file) ────────────────────
        if meta["mime_type"] and meta["mime_type"].startswith("text"):
            meta.update(self._text_stats())

        # ── Display ─────────────────────────────────────
        row("File",         meta["name"])
        row("Size",         f'{meta["size_human"]}  ({meta["size_bytes"]:,} bytes)')
        row("MIME Type",    meta["mime_type"])
        row("Detected",     meta["detected_type"])
        row("Encoding",     meta["encoding"])
        row("Magic Bytes",  meta["magic_bytes"])
        row("Permissions",  meta["permissions"])
        row("Is Symlink",   meta["is_symlink"])
        row("Created",      meta["created"])
        row("Modified",     meta["modified"])
        row("Accessed",     meta["accessed"])
        row("MD5",          meta.get("md5", "—"), val_color=DIM)
        row("SHA-1",        meta.get("sha1", "—"), val_color=DIM)
        row("SHA-256",      meta.get("sha256", "—"), val_color=DIM)
        row("CRC32",        meta.get("crc32", "—"), val_color=DIM)
        if "line_count" in meta:
            row("Lines",    meta["line_count"])
            row("Words",    meta["word_count"])
            row("Chars",    meta["char_count"])
            row("Encoding (text)", meta.get("text_encoding", "—"))

        return meta

    def _human_size(self, n: int) -> str:
        for unit in ("B","KB","MB","GB","TB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"

    def _compute_hashes(self) -> dict:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        crc = 0
        try:
            with open(self.path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    crc = zlib.crc32(chunk, crc)
            return {
                "md5":    md5.hexdigest(),
                "sha1":   sha1.hexdigest(),
                "sha256": sha256.hexdigest(),
                "crc32":  f"{crc & 0xFFFFFFFF:08x}",
            }
        except Exception as e:
            warn(f"Hash error: {e}")
            return {}

    def _magic_bytes(self) -> str:
        try:
            with open(self.path, "rb") as f:
                raw = f.read(16)
            return " ".join(f"{b:02X}" for b in raw)
        except:
            return "—"

    def _detect_type(self, magic: str) -> str:
        signatures = {
            "FF D8 FF":           "JPEG Image",
            "89 50 4E 47 0D 0A":  "PNG Image",
            "47 49 46 38":        "GIF Image",
            "52 49 46 46":        "RIFF (WAV/AVI/WEBP)",
            "25 50 44 46":        "PDF Document",
            "50 4B 03 04":        "ZIP Archive / DOCX/xlsx",
            "1F 8B":              "GZIP Archive",
            "42 5A 68":           "BZIP2 Archive",
            "7F 45 4C 46":        "ELF Binary",
            "4D 5A":              "Windows PE/EXE",
            "49 44 33":           "MP3 Audio (ID3)",
            "66 74 79 70":        "MP4/MOV Video",
            "EF BB BF":           "UTF-8 BOM Text",
            "FF FE":              "UTF-16 LE Text",
            "FE FF":              "UTF-16 BE Text",
            "D0 CF 11 E0":        "MS Office (legacy .doc/.xls)",
            "38 42 50 53":        "Photoshop PSD",
            "49 49 2A 00":        "TIFF (little-endian)",
            "4D 4D 00 2A":        "TIFF (big-endian)",
        }
        for sig, name in signatures.items():
            if magic.startswith(sig):
                return name
        return "Unknown / Text"

    def _text_stats(self) -> dict:
        encodings = ["utf-8", "latin-1", "utf-16", "ascii"]
        for enc in encodings:
            try:
                text = self.path.read_text(encoding=enc)
                lines = text.splitlines()
                words = text.split()
                return {
                    "line_count":    len(lines),
                    "word_count":    len(words),
                    "char_count":    len(text),
                    "text_encoding": enc,
                }
            except:
                continue
        return {}


# ═══════════════════════════════════════════════════════════
# MODULE 2 — IMAGE INTELLIGENCE EXTRACTOR
# ═══════════════════════════════════════════════════════════

class ImageIntelligenceExtractor:
    """Extract EXIF, color palette, dimensions, and composition data from images."""

    SUPPORTED = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif"}

    def __init__(self, filepath: str):
        self.path = Path(filepath).resolve()

    def run(self):
        section("IMAGE INTELLIGENCE EXTRACTOR", MGT)
        if not self.path.exists():
            err(f"File not found: {self.path}")
            return {}

        ext = self.path.suffix.lower()
        if ext not in self.SUPPORTED:
            warn(f"Not a supported image format: {ext}")
            warn(f"Supported: {', '.join(self.SUPPORTED)}")
            return {}

        data = {}

        if ext in (".jpg", ".jpeg"):
            data.update(self._parse_jpeg())
        elif ext == ".png":
            data.update(self._parse_png())
        elif ext == ".gif":
            data.update(self._parse_gif())
        elif ext == ".bmp":
            data.update(self._parse_bmp())

        data.update(self._general_image_info())

        # Display
        for k, v in data.items():
            label = k.replace("_", " ").title()
            row(label, v)

        return data

    def _read_bytes(self, n, offset=0):
        with open(self.path, "rb") as f:
            f.seek(offset)
            return f.read(n)

    def _general_image_info(self) -> dict:
        info = {}
        try:
            size = self.path.stat().st_size
            info["file_size"] = f"{size:,} bytes"
        except:
            pass
        return info

    def _parse_jpeg(self) -> dict:
        data = {}
        try:
            raw = self.path.read_bytes()
            # Width/Height from SOF markers
            i = 0
            while i < len(raw) - 1:
                if raw[i] == 0xFF:
                    marker = raw[i+1]
                    if marker in (0xC0, 0xC1, 0xC2):  # SOF0/SOF1/SOF2
                        data["height"]       = struct.unpack(">H", raw[i+5:i+7])[0]
                        data["width"]        = struct.unpack(">H", raw[i+7:i+9])[0]
                        data["bit_depth"]    = raw[i+4]
                        data["color_components"] = raw[i+9]
                        data["color_mode"]   = {1:"Grayscale",3:"YCbCr/RGB",4:"CMYK"}.get(raw[i+9],"Unknown")
                        break
                    if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7:
                        i += 2
                        continue
                    length = struct.unpack(">H", raw[i+2:i+4])[0] if i+4 <= len(raw) else 2
                    i += 2 + length
                else:
                    i += 1

            # EXIF
            exif = self._extract_jpeg_exif(raw)
            data.update(exif)
            data["format"] = "JPEG"
            data["progressive"] = "Yes" if b"\xFF\xC2" in raw else "No"

        except Exception as e:
            warn(f"JPEG parse error: {e}")
        return data

    def _extract_jpeg_exif(self, raw: bytes) -> dict:
        exif = {}
        try:
            exif_start = raw.find(b"Exif\x00\x00")
            if exif_start == -1:
                exif["exif"] = "Not found"
                return exif

            tiff_start = exif_start + 6
            endian = raw[tiff_start:tiff_start+2]
            little = endian == b"II"
            bo = "<" if little else ">"
            exif["exif_byte_order"] = "Little-endian (Intel)" if little else "Big-endian (Motorola)"

            # Basic EXIF tags we care about
            TAG_NAMES = {
                0x010E: "image_description",
                0x010F: "camera_make",
                0x0110: "camera_model",
                0x0112: "orientation",
                0x011A: "x_resolution",
                0x011B: "y_resolution",
                0x0128: "resolution_unit",
                0x0131: "software",
                0x0132: "datetime",
                0x013B: "artist",
                0x8769: "exif_ifd_offset",
                0x8298: "copyright",
                0x9003: "datetime_original",
                0x9004: "datetime_digitized",
                0x9291: "subsec_time_original",
                0x9202: "aperture",
                0x9203: "brightness",
                0x9205: "max_aperture",
                0x9206: "subject_distance",
                0x9207: "metering_mode",
                0x9208: "light_source",
                0x9209: "flash",
                0x920A: "focal_length",
                0xA002: "pixel_x_dimension",
                0xA003: "pixel_y_dimension",
                0xA433: "lens_make",
                0xA434: "lens_model",
                0x8827: "iso_speed",
                0x829A: "exposure_time",
                0x829D: "f_number",
                0x9214: "subject_area",
                0xA405: "focal_length_35mm",
                0xA40C: "subject_distance_range",
            }

            ifd_offset = struct.unpack(bo+"I", raw[tiff_start+4:tiff_start+8])[0]
            base = tiff_start
            pos = base + ifd_offset
            if pos + 2 > len(raw):
                return exif
            num_entries = struct.unpack(bo+"H", raw[pos:pos+2])[0]
            pos += 2

            for _ in range(min(num_entries, 100)):
                if pos + 12 > len(raw):
                    break
                tag   = struct.unpack(bo+"H", raw[pos:pos+2])[0]
                dtype = struct.unpack(bo+"H", raw[pos+2:pos+4])[0]
                count = struct.unpack(bo+"I", raw[pos+4:pos+8])[0]
                voff  = raw[pos+8:pos+12]
                pos  += 12

                name = TAG_NAMES.get(tag)
                if not name:
                    continue
                try:
                    value = self._read_exif_value(raw, base, bo, dtype, count, voff)
                    if value is not None:
                        exif[name] = value
                except:
                    pass

        except Exception as e:
            exif["exif_parse_error"] = str(e)
        return exif

    def _read_exif_value(self, raw, base, bo, dtype, count, voff):
        type_sizes = {1:1, 2:1, 3:2, 4:4, 5:8, 6:1, 7:1, 8:2, 9:4, 10:8, 11:4, 12:8}
        size = type_sizes.get(dtype, 1) * count
        if size <= 4:
            data = voff[:size]
        else:
            offset = struct.unpack(bo+"I", voff)[0]
            data = raw[base+offset: base+offset+size]

        if dtype == 2:  # ASCII
            return data.rstrip(b"\x00").decode("latin-1", errors="replace").strip()
        elif dtype == 3 and count == 1:  # SHORT
            return struct.unpack(bo+"H", data[:2])[0]
        elif dtype == 4 and count == 1:  # LONG
            return struct.unpack(bo+"I", data[:4])[0]
        elif dtype == 5 and count == 1:  # RATIONAL
            n, d = struct.unpack(bo+"II", data[:8])
            return f"{n}/{d}" if d else "0"
        return None

    def _parse_png(self) -> dict:
        data = {"format": "PNG"}
        try:
            with open(self.path, "rb") as f:
                sig = f.read(8)
                if sig != b"\x89PNG\r\n\x1a\n":
                    warn("Invalid PNG signature")
                    return data
                while True:
                    header = f.read(8)
                    if len(header) < 8:
                        break
                    length = struct.unpack(">I", header[:4])[0]
                    chunk  = header[4:8].decode("ascii", errors="replace")
                    body   = f.read(length)
                    f.read(4)  # CRC

                    if chunk == "IHDR":
                        data["width"]        = struct.unpack(">I", body[0:4])[0]
                        data["height"]       = struct.unpack(">I", body[4:8])[0]
                        data["bit_depth"]    = body[8]
                        ct = body[9]
                        data["color_type"]   = {0:"Grayscale",2:"RGB",3:"Indexed",4:"Grayscale+Alpha",6:"RGBA"}.get(ct, ct)
                        data["compression"]  = "Deflate" if body[10] == 0 else body[10]
                        data["interlaced"]   = "Adam7" if body[12] == 1 else "None"
                    elif chunk == "tEXt":
                        try:
                            key, val = body.split(b"\x00", 1)
                            data[f"text_{key.decode()}"] = val.decode("latin-1")
                        except:
                            pass
                    elif chunk == "iTXt":
                        try:
                            parts = body.split(b"\x00")
                            if len(parts) >= 2:
                                data[f"itxt_{parts[0].decode()}"] = parts[-1].decode("utf-8", errors="replace")
                        except:
                            pass
                    elif chunk == "gAMA":
                        gamma = struct.unpack(">I", body[:4])[0] / 100000
                        data["gamma"] = f"{gamma:.5f}"
                    elif chunk == "sRGB":
                        data["srgb_intent"] = {0:"Perceptual",1:"Relative colorimetric",2:"Saturation",3:"Absolute colorimetric"}.get(body[0], body[0])
                    elif chunk == "IEND":
                        break
        except Exception as e:
            warn(f"PNG parse error: {e}")
        return data

    def _parse_gif(self) -> dict:
        data = {"format": "GIF"}
        try:
            with open(self.path, "rb") as f:
                header = f.read(6)
                data["version"]    = header.decode("ascii", errors="replace")
                lsd = f.read(7)
                data["width"]      = struct.unpack("<H", lsd[0:2])[0]
                data["height"]     = struct.unpack("<H", lsd[2:4])[0]
                packed             = lsd[4]
                data["has_gct"]    = bool(packed & 0x80)
                data["color_res"]  = ((packed >> 4) & 0x07) + 1
                data["gct_size"]   = 2 ** ((packed & 0x07) + 1) if data["has_gct"] else 0
                data["bg_color_index"] = lsd[5]
                data["pixel_aspect"]   = lsd[6]
        except Exception as e:
            warn(f"GIF parse error: {e}")
        return data

    def _parse_bmp(self) -> dict:
        data = {"format": "BMP"}
        try:
            with open(self.path, "rb") as f:
                f.read(2)  # BM
                data["file_size"]   = struct.unpack("<I", f.read(4))[0]
                f.read(4)  # reserved
                data["pixel_offset"]= struct.unpack("<I", f.read(4))[0]
                hdr_size            = struct.unpack("<I", f.read(4))[0]
                data["dib_header"]  = hdr_size
                if hdr_size >= 40:
                    data["width"]   = struct.unpack("<I", f.read(4))[0]
                    data["height"]  = struct.unpack("<I", f.read(4))[0]
                    f.read(2)
                    data["bit_depth"] = struct.unpack("<H", f.read(2))[0]
                    comp            = struct.unpack("<I", f.read(4))[0]
                    data["compression"] = {0:"None (BI_RGB)",1:"RLE8",2:"RLE4",3:"Bitfields"}.get(comp, comp)
        except Exception as e:
            warn(f"BMP parse error: {e}")
        return data


# ═══════════════════════════════════════════════════════════
# MODULE 3 — CONTEXT RESOLVER
# ═══════════════════════════════════════════════════════════

class ContextResolver:
    """Connect file data to real-world context: geolocation, time zones, online lookup."""

    def __init__(self, filepath: str):
        self.path = Path(filepath).resolve()
        self.image_data = {}

    def run(self, image_data: dict = None):
        section("CONTEXT RESOLVER", GRN)
        self.image_data = image_data or {}

        results = {}

        # 1. Temporal context
        results.update(self._temporal_context())

        # 2. GPS / Geo context (from EXIF if available)
        geo = self._geo_context()
        results.update(geo)

        # 3. Camera / Device context
        results.update(self._device_context())

        # 4. Network context
        results.update(self._network_context())

        # 5. File provenance
        results.update(self._provenance_context())

        # Display
        for k, v in results.items():
            label = k.replace("_", " ").title()
            row(label, str(v))

        return results

    def _temporal_context(self) -> dict:
        ctx = {}
        stat = self.path.stat()
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
        now   = datetime.datetime.now()
        age   = now - mtime

        ctx["file_age"] = self._human_duration(age.total_seconds())
        ctx["local_timezone"] = datetime.datetime.now(datetime.timezone.utc).astimezone().tzname() or "UTC"

        # EXIF datetime
        for key in ("datetime_original", "datetime", "datetime_digitized"):
            val = self.image_data.get(key)
            if val and isinstance(val, str) and len(val) >= 10:
                ctx["capture_datetime"] = val
                try:
                    # Format: 2024:07:15 14:32:01
                    dt = datetime.datetime.strptime(val[:19], "%Y:%m:%d %H:%M:%S")
                    ctx["capture_day_of_week"] = dt.strftime("%A")
                    ctx["capture_year"]  = dt.year
                    ctx["capture_month"] = dt.strftime("%B")
                    photo_age = now - dt
                    ctx["photo_age"] = self._human_duration(photo_age.total_seconds())
                except:
                    pass
                break

        return ctx

    def _geo_context(self) -> dict:
        ctx = {}

        # Try to get GPS from EXIF
        lat = self.image_data.get("gps_latitude")
        lon = self.image_data.get("gps_longitude")

        if lat and lon:
            ctx["gps_latitude"]  = lat
            ctx["gps_longitude"] = lon
            # Reverse geocode via open API
            place = self._reverse_geocode(lat, lon)
            if place:
                ctx.update(place)
        else:
            # Try IP-based geolocation for "where was this analyzed"
            geo = self._ip_geolocation()
            if geo:
                ctx["analysis_location"] = geo.get("city","?") + ", " + geo.get("country","?")
                ctx["analysis_ip"]       = geo.get("ip","?")
                ctx["analysis_isp"]      = geo.get("org","?")
                ctx["analysis_timezone"] = geo.get("timezone","?")

        return ctx

    def _reverse_geocode(self, lat, lon) -> dict:
        try:
            url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Svilia/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            addr = data.get("address", {})
            return {
                "geo_display_name": data.get("display_name","")[:80],
                "geo_city":  addr.get("city") or addr.get("town") or addr.get("village","?"),
                "geo_state": addr.get("state","?"),
                "geo_country": addr.get("country","?"),
                "geo_postcode": addr.get("postcode","?"),
                "geo_country_code": addr.get("country_code","?").upper(),
            }
        except Exception as e:
            return {"geo_lookup": f"Unavailable ({type(e).__name__})"}

    def _ip_geolocation(self) -> dict:
        try:
            url = "https://ipapi.co/json/"
            req = urllib.request.Request(url, headers={"User-Agent": "Svilia/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode())
        except:
            return {}

    def _device_context(self) -> dict:
        ctx = {}
        make  = self.image_data.get("camera_make","")
        model = self.image_data.get("camera_model","")
        soft  = self.image_data.get("software","")

        if make or model:
            ctx["device"] = f"{make} {model}".strip()
        if soft:
            ctx["processing_software"] = soft
        focal = self.image_data.get("focal_length_35mm")
        if focal:
            ctx["equiv_focal_length"] = f"{focal}mm (35mm equiv)"
        iso = self.image_data.get("iso_speed")
        if iso:
            ctx["iso"] = iso
            if isinstance(iso, int):
                if iso <= 400:
                    ctx["iso_context"] = "Good light conditions"
                elif iso <= 1600:
                    ctx["iso_context"] = "Low light / indoors"
                else:
                    ctx["iso_context"] = "Very low light / night"
        flash = self.image_data.get("flash")
        if flash is not None:
            ctx["flash_fired"] = bool(flash & 0x01) if isinstance(flash, int) else flash
        lens = self.image_data.get("lens_model","") or self.image_data.get("lens_make","")
        if lens:
            ctx["lens"] = lens

        return ctx

    def _network_context(self) -> dict:
        ctx = {}
        try:
            hostname = socket.gethostname()
            ctx["analysis_host"] = hostname
            try:
                local_ip = socket.gethostbyname(hostname)
                ctx["local_ip"] = local_ip
            except:
                pass
        except:
            pass
        return ctx

    def _provenance_context(self) -> dict:
        ctx = {}
        ctx["analyzed_at"] = datetime.datetime.now().isoformat()
        ctx["tool"] = "Svilia v1.0"
        ctx["python_version"] = sys.version.split()[0]

        # Check if file was recently modified (possible edit)
        stat = self.path.stat()
        created  = stat.st_ctime
        modified = stat.st_mtime
        if abs(modified - created) > 60:
            ctx["file_likely_edited"] = "Yes (mtime differs from ctime > 60s)"
        else:
            ctx["file_likely_edited"] = "Probably not (ctime ≈ mtime)"

        return ctx

    def _human_duration(self, seconds: float) -> str:
        seconds = int(abs(seconds))
        if seconds < 60:       return f"{seconds} seconds"
        if seconds < 3600:     return f"{seconds//60} minutes"
        if seconds < 86400:    return f"{seconds//3600} hours"
        if seconds < 2592000:  return f"{seconds//86400} days"
        if seconds < 31536000: return f"{seconds//2592000} months"
        return f"{seconds//31536000} years"


# ═══════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════

def usage():
    print(f"""
{B}Usage:{R}
  python svilia.py <command> <file>

{B}Commands:{R}
  {CYN}metadata{R}   — Deep metadata extraction (hashes, MIME, permissions…)
  {MGT}image{R}      — Image intelligence (EXIF, dimensions, color mode…)
  {GRN}context{R}    — Context resolver (geo, time, device, network…)
  {YLW}all{R}        — Run all three modules

{B}Examples:{R}
  python svilia.py all      photo.jpg
  python svilia.py metadata document.pdf
  python svilia.py image    sunset.png
  python svilia.py context  photo.jpg
""")

def main():
    banner()

    if len(sys.argv) < 3:
        usage()
        sys.exit(1)

    cmd  = sys.argv[1].lower()
    file = sys.argv[2]

    if cmd not in ("metadata", "image", "context", "all"):
        err(f"Unknown command: {cmd}")
        usage()
        sys.exit(1)

    image_data = {}

    if cmd in ("metadata", "all"):
        ma = MetadataAnalyzer(file)
        ma.run()

    if cmd in ("image", "all"):
        ii = ImageIntelligenceExtractor(file)
        image_data = ii.run()

    if cmd in ("context", "all"):
        cr = ContextResolver(file)
        cr.run(image_data)

    print(f"\n{DIM}{'─'*56}{R}")
    ok(f"Svilia analysis complete — {Path(file).name}")
    print()


if __name__ == "__main__":
    main()
