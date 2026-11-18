#!/usr/bin/env python3
"""
Histogram of pointer-authentication instructions in the __TEXT,__text of every
image in a (split) dyld shared cache.

Read-only: the cache is mmap()ed and never copied, written or uploaded.
Only the JSON printed to stdout is meant to leave the machine.

Format reference: apple-oss-distributions/dyld dyld-1378
include/mach-o/dyld_cache_format.h

Mapping addresses in every subcache file are the absolute unslid vmaddrs, so
the mapping tables of all files are merged into one address space; the image
list of the main cache is then resolved across files.  __text bytes are
located by vmaddr (not by section.offset), which works for split caches.

Usage:
    dsc_hist.py PATH_TO_dyld_shared_cache_arm64e [--json OUT] [--top N]
    dsc_hist.py --dir /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld
Exit: 0 on success, 3 if no usable cache was found.
"""
import argparse
import glob
import json
import mmap
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pac_count import EXACT, HINTS, LDRA_MASK, LDRA_VALUE, ldra_decode  # noqa: E402

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
INSN_ATTRS = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS

# dyld_cache_header field offsets (64-bit, see dyld_cache_format.h).
H_MAPPING_OFFSET = 16
H_MAPPING_COUNT = 20
H_IMAGES_OFFSET_OLD = 24
H_IMAGES_COUNT_OLD = 28
H_UUID = 88
H_CACHE_TYPE = 104
H_SHARED_REGION_START = 224
H_SHARED_REGION_SIZE = 232
H_OS_VERSION = 364
H_SUBCACHE_OFFSET = 392
H_SUBCACHE_COUNT = 396
H_IMAGES_OFFSET = 448
H_IMAGES_COUNT = 452
HEADER_MIN = 456
MAPPING_SIZE = 32
IMAGE_INFO_SIZE = 32


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def decode_os_version(v):
    return "%d.%d.%d" % ((v >> 16) & 0xFFFF, (v >> 8) & 0xFF, v & 0xFF)


class CacheFile:
    """One file of a (possibly split) dyld shared cache."""

    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        with open(path, "rb") as f:
            self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if len(self.data) < HEADER_MIN:
            raise ValueError("%s: too short for a dyld cache header" % path)
        self.magic = self.data[:16].split(b"\0")[0].decode("latin-1")
        if not self.magic.startswith("dyld_v1"):
            raise ValueError("%s: not a dyld cache (%r)" % (path, self.magic))
        self.mapping_offset = u32(self.data, H_MAPPING_OFFSET)
        self.mapping_count = u32(self.data, H_MAPPING_COUNT)
        self.mappings = []
        for i in range(self.mapping_count):
            off = self.mapping_offset + i * MAPPING_SIZE
            if off + MAPPING_SIZE > len(self.data):
                break
            addr, size, file_off = struct.unpack_from("<QQQ", self.data, off)
            initprot = u32(self.data, off + 28)
            self.mappings.append({
                "address": addr, "size": size, "file_offset": file_off,
                "initprot": initprot, "file": self,
            })

    def close(self):
        try:
            self.data.close()
        except (BufferError, ValueError):
            pass


def load_cache(main_path):
    """Open the main cache and every sibling that is also a dyld cache."""
    files = [CacheFile(main_path)]
    for path in sorted(glob.glob(main_path + ".*")):
        if path == main_path or not os.path.isfile(path):
            continue
        try:
            cf = CacheFile(path)
        except (ValueError, OSError):
            continue
        if cf.mapping_count == 0:
            cf.close()
            continue
        files.append(cf)
    return files


def find_image_list(main):
    data = main.data
    off = u32(data, H_IMAGES_OFFSET)
    count = u32(data, H_IMAGES_COUNT)
    if not off or not count:
        off = u32(data, H_IMAGES_OFFSET_OLD)
        count = u32(data, H_IMAGES_COUNT_OLD)
    return off, count


def image_path(main, path_offset):
    data = main.data
    if not (0 <= path_offset < len(data)):
        return "?"
    end = data.find(b"\0", path_offset)
    if end < 0:
        end = min(path_offset + 512, len(data))
    return data[path_offset:end].decode("utf-8", "replace")


def mapping_for(mappings, addr):
    for m in mappings:
        if m["address"] <= addr < m["address"] + m["size"]:
            return m
    return None


def file_offset_of(mapping, addr):
    return mapping["file_offset"] + (addr - mapping["address"])


def parse_text_section(mapping, addr):
    """Read the mach_header at addr and return (text_addr, text_size, vmaddr) or None."""
    data = mapping["file"].data
    off = file_offset_of(mapping, addr)
    if off + 32 > len(data):
        return None
    if u32(data, off) != MH_MAGIC_64:
        return None
    ncmds, sizeofcmds = struct.unpack_from("<II", data, off + 16)
    p, end = off + 32, min(off + 32 + sizeofcmds, len(data))
    while p < end and ncmds:
        cmd, cmdsize = struct.unpack_from("<II", data, p)
        if cmdsize < 8 or p + cmdsize > len(data):
            return None
        if cmd == LC_SEGMENT_64:
            nsects = u32(data, p + 64)
            soff = p + 72
            for _ in range(nsects):
                if soff + 80 > len(data):
                    break
                sectname = data[soff:soff + 16].split(b"\0")[0]
                segname = data[soff + 16:soff + 32].split(b"\0")[0]
                saddr, ssize = struct.unpack_from("<QQ", data, soff + 32)
                flags = u32(data, soff + 64)
                if segname == b"__TEXT" and sectname == b"__text" and \
                        flags & INSN_ATTRS and ssize:
                    return saddr, ssize
                soff += 80
        p += cmdsize
        ncmds -= 1
    return None


def make_counter():
    rules = [(mask, value, name) for name, mask, value in EXACT]
    prefixes = set()
    for mask, value, _name in rules:
        prefixes.add(value >> 16)
    ldraw_top = 0xF8

    counts = {}

    def count_word(word):
        if word in HINTS:
            name = "hint:" + HINTS[word]
            counts[name] = counts.get(name, 0) + 1
            return
        top = word >> 16
        if top in prefixes:
            for mask, value, name in rules:
                if word & mask == value:
                    counts[name] = counts.get(name, 0) + 1
                    return
            return
        if (word >> 24) == ldraw_top and word & LDRA_MASK == LDRA_VALUE:
            s10, wb = ldra_decode(word)
            if wb == 0 and s10 >= 0:
                name = "ldraa_pos"
            elif wb == 0 and -32 <= s10 <= -1:
                name = "ldraa_neg"
            elif wb == 1 and -32 <= s10 <= 31:
                name = "ldraa_pre"
            else:
                name = "ldraa_wide"
            counts[name] = counts.get(name, 0) + 1
        elif (word & 0xFFE00000) == 0x9AC00000:
            for mask, value, name in rules:
                if word & mask == value:
                    counts[name] = counts.get(name, 0) + 1
                    return

    return counts, count_word


GROUPS = [
    ("retab", ("retab",)),
    ("retaa", ("retaa",)),
    ("eretaa_eretab", ("eretaa", "eretab")),
    ("braa", ("braa", "braab", "braaz", "brabz")),
    ("blraa", ("blraa", "blrab", "blraaz", "blrabz")),
    ("ldraa_ldrab", ("ldraa_pos", "ldraa_neg", "ldraa_pre", "ldraa_wide")),
    ("pacia_pacib_pacda_pacdb", ("pacia", "pacib", "pacda", "pacdb")),
    ("autia_autib_autda_autdb", ("autia", "autib", "autda", "autdb")),
    ("xpaci_xpacd", ("xpaci", "xpacd")),
    ("pacga", ("pacga",)),
    ("pac_key_regs", ("mrs_pac_key", "msr_pac_key")),
]


def histogram(main_path, list_only=False, top=50):
    files = load_cache(main_path)
    main = files[0]
    mappings = []
    for cf in files:
        mappings.extend(cf.mappings)
    mappings.sort(key=lambda m: m["address"])

    images_off, images_count = find_image_list(main)
    result = {
        "cache": {
            "main_file": os.path.basename(main_path),
            "magic": main.magic,
            "uuid": main.data[H_UUID:H_UUID + 16].hex(),
            "cache_type": u64(main.data, H_CACHE_TYPE),
            "os_version": decode_os_version(u32(main.data, H_OS_VERSION)),
            "shared_region_start": u64(main.data, H_SHARED_REGION_START),
            "shared_region_size": u64(main.data, H_SHARED_REGION_SIZE),
            "files": [cf.name for cf in files],
            "mappings": len(mappings),
            "images_total": images_count,
        },
        "images_scanned": 0,
        "images_without_text": 0,
        "images_unmapped": 0,
        "images_bad_header": 0,
        "text_bytes": 0,
        "words_scanned": 0,
        "counts": {},
        "groups": {},
        "ldraa": {},
        "ldraa_wide_examples": [],
        "top_images": [],
    }
    if list_only:
        result["images"] = []
        for i in range(images_count):
            off = images_off + i * IMAGE_INFO_SIZE
            if off + IMAGE_INFO_SIZE > len(main.data):
                break
            addr = u64(main.data, off)
            path_off = u32(main.data, off + 24)
            result["images"].append({"address": addr, "path": image_path(main, path_off)})
        return result

    counts, count_word = make_counter()
    per_image = []

    for i in range(images_count):
        off = images_off + i * IMAGE_INFO_SIZE
        if off + IMAGE_INFO_SIZE > len(main.data):
            break
        addr = u64(main.data, off)
        path = image_path(main, u32(main.data, off + 24))
        mapping = mapping_for(mappings, addr)
        if mapping is None:
            result["images_unmapped"] += 1
            continue
        try:
            text = parse_text_section(mapping, addr)
        except (struct.error, IndexError):
            text = None
        if text is None:
            try:
                magic_ok = u32(mapping["file"].data, file_offset_of(mapping, addr)) == MH_MAGIC_64
            except (struct.error, IndexError):
                magic_ok = False
            if magic_ok:
                result["images_without_text"] += 1
            else:
                result["images_bad_header"] += 1
            continue
        text_addr, text_size = text
        m = mapping_for(mappings, text_addr)
        if m is None:
            result["images_unmapped"] += 1
            continue
        off_in_file = file_offset_of(m, text_addr)
        avail = min(text_size, m["size"] - (text_addr - m["address"]))
        if off_in_file + avail > len(m["file"].data):
            avail = len(m["file"].data) - off_in_file
        avail &= ~3
        if avail <= 0:
            result["images_without_text"] += 1
            continue

        before = dict(counts)
        mv = memoryview(m["file"].data)[off_in_file:off_in_file + avail].cast("I")
        words = len(mv)
        for w in mv:
            count_word(w)
        mv.release()
        result["images_scanned"] += 1
        result["text_bytes"] += avail
        result["words_scanned"] += words
        delta = {k: v - before.get(k, 0) for k, v in counts.items() if v != before.get(k, 0)}
        pac = sum(v for k, v in delta.items() if not k.startswith("hint:"))
        if pac:
            per_image.append((pac, path, avail))

    result["counts"] = dict(sorted(counts.items()))
    per_image.sort(reverse=True)
    result["top_images"] = [
        {"path": p, "pac": n, "text_bytes": a} for n, p, a in per_image[:top]
    ]

    def g(names):
        return sum(result["counts"].get(n, 0) for n in names)

    result["groups"] = {name: g(names) for name, names in GROUPS}
    ldra = {k: result["counts"].get("ldraa_" + k, 0)
            for k in ("pos", "neg", "pre", "wide")}
    result["ldraa"] = {
        "pos": ldra["pos"],
        "neg": ldra["neg"],
        "pre_index": ldra["pre"],
        "not_rewritable_1to1": ldra["wide"],
        "offset_lt_minus_256": ldra["neg"] + ldra["wide"],
        "total": sum(ldra.values()),
    }
    result["total_non_hint_pac"] = sum(
        v for k, v in result["counts"].items() if not k.startswith("hint:"))
    result["total_hint_pac"] = sum(
        v for k, v in result["counts"].items() if k.startswith("hint:"))
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cache", nargs="?", help="path to dyld_shared_cache_arm64e*")
    ap.add_argument("--dir", help="directory that contains the cache")
    ap.add_argument("--json")
    ap.add_argument("--list", action="store_true", help="only list images")
    ap.add_argument("--top", type=int, default=50)
    args = ap.parse_args()

    path = args.cache
    if not path and args.dir:
        candidates = []
        for pattern in ("dyld_shared_cache_arm64e*", "dyld_shared_cache_arm64*"):
            candidates.extend(sorted(glob.glob(os.path.join(args.dir, pattern))))
        candidates = [c for c in candidates
                      if os.path.basename(c) == "dyld_shared_cache_arm64e"
                      or os.path.basename(c).startswith("dyld_shared_cache_arm64e.")]
        if not candidates:
            print("no dyld_shared_cache_arm64e* in %s" % args.dir, file=sys.stderr)
            return 3
        path = candidates[0]
    if not path:
        ap.error("give a cache path or --dir")
    if not os.path.isfile(path):
        print("%s: not a file" % path, file=sys.stderr)
        return 3

    result = histogram(path, list_only=args.list, top=args.top)
    out = json.dumps(result, indent=1)
    if args.json:
        with open(args.json, "w") as f:
            f.write(out + "\n")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
