#!/usr/bin/env python3
"""
Count pointer-authentication instructions in a Mach-O / MH_FILESET kernel by
decoding the instruction words directly (no otool text dump).

Masks come from llvm-mc encodings (ci/README.md) and match
tools/nopac/rewrite_rules.json, so the words counted here are exactly the
words the in-place rewriter would look at.

By default only real function bodies are scanned: LC_FUNCTION_STARTS bounds
the sweep and LC_DATA_IN_CODE ranges (literal pools, jump tables) are cut out,
just like tools/nopac/nopac_rewrite.py.  Hits outside function bodies and
inside data-in-code ranges are reported separately instead of being dropped,
so nothing is invisible.  --scan-all sweeps whole instruction sections.

Usage:  pac_count.py FILE [--json OUT] [--scan-all] [--top N]
Exit:   0 if no non-hint PAC instruction was found, 2 otherwise.
"""
import argparse
import bisect
import json
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
MH_FILESET = 0xC
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_FILESET_ENTRY = 0x80000034

S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
INSN_ATTRS = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS

# (class, mask, value).  First match wins; every mask below is mutually
# exclusive, so this table is also the classifier.
EXACT = [
    ("retaa", 0xFFFFFFFF, 0xD65F0BFF),
    ("retab", 0xFFFFFFFF, 0xD65F0FFF),
    ("eretaa", 0xFFFFFFFF, 0xD69F0BFF),
    ("eretab", 0xFFFFFFFF, 0xD69F0FFF),
    ("xpaci", 0xFFFFFC00, 0xDAC14000),
    ("xpacd", 0xFFFFFC00, 0xDAC14400),
    ("pacga", 0xFFE0FC00, 0x9AC03000),
    ("pacia", 0xFFFFFC00, 0xDAC10000),
    ("pacib", 0xFFFFFC00, 0xDAC10400),
    ("pacda", 0xFFFFFC00, 0xDAC10800),
    ("pacdb", 0xFFFFFC00, 0xDAC10C00),
    ("autia", 0xFFFFFC00, 0xDAC11000),
    ("autib", 0xFFFFFC00, 0xDAC11400),
    ("autda", 0xFFFFFC00, 0xDAC11800),
    ("autdb", 0xFFFFFC00, 0xDAC11C00),
    ("braa", 0xFFFFFC00, 0xD71F0800),
    ("brab", 0xFFFFFC00, 0xD71F0C00),
    ("braaz", 0xFFFFFC1F, 0xD61F081F),
    ("brabz", 0xFFFFFC1F, 0xD61F0C1F),
    ("blraa", 0xFFFFFC00, 0xD73F0800),
    ("blrab", 0xFFFFFC00, 0xD73F0C00),
    ("blraaz", 0xFFFFFC1F, 0xD63F081F),
    ("blrabz", 0xFFFFFC1F, 0xD63F0C1F),
    ("mrs_pac_key", 0xFFFFF000, 0xD5382000),
    ("msr_pac_key", 0xFFFFF000, 0xD5182000),
]

LDRA_MASK = 0xFF200400
LDRA_VALUE = 0xF8200400

# HINT-space encodings: architecturally NOPs on a CPU without FEAT_PAuth.
# Only PAC-related hints and not the general NOP/BTI space, which would add
# millions of useless counts.
HINTS = {
    0xD503231F: "paciaz", 0xD503239F: "autiaz", 0xD503233F: "paciasp",
    0xD50323BF: "autiasp", 0xD503235F: "pacibz", 0xD50323DF: "autibz",
    0xD503237F: "pacibsp", 0xD50323FF: "autibsp", 0xD503211F: "pacia1716",
    0xD503215F: "pacib1716", 0xD503219F: "autia1716", 0xD50321DF: "autib1716",
    0xD50320FF: "xpaclri",
}

# Cheap pre-filter: top 16 bits that can start a match.  Every LDRAA/LDRAB
# word has top byte 0xf8.
PREFIXES = frozenset([
    0xD65F, 0xD69F, 0xDAC1, 0xD71F, 0xD61F, 0xD73F, 0xD63F,
    0x9AC0, 0xD538, 0xD518, 0xD503,
])


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def uleb(data, off):
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


def ldra_decode(word):
    """Return (simm_in_8byte_units, writeback) for an LDRAA/LDRAB word.

    simm10 = {bit22, bits20:12}, signed, scaled by 8 bytes.  Bit 21 is fixed
    by the opcode mask and is NOT part of the immediate.
    """
    s10 = (((word >> 22) & 1) << 9) | ((word >> 12) & 0x1FF)
    if s10 & 0x200:
        s10 -= 0x400
    return s10, (word >> 11) & 1


def classify(word):
    """Return the PAC class of one instruction word, or None."""
    if word not in HINTS:
        if not ((word >> 16) in PREFIXES or (word >> 24) == 0xF8
                or (word & 0xFFE00000) == 0x9AC00000):
            return None
    for name, mask, value in EXACT:
        if word & mask == value:
            return name
    if word & LDRA_MASK == LDRA_VALUE:
        s10, writeback = ldra_decode(word)
        if writeback == 0 and s10 >= 0:
            return "ldraa_pos"
        if writeback == 0 and -32 <= s10 <= -1:
            return "ldraa_neg"
        if writeback == 1 and -32 <= s10 <= 31:
            return "ldraa_pre"
        return "ldraa_wide"
    if word in HINTS:
        return "hint:" + HINTS[word]
    return None


def text_segment_vmaddr(data, base):
    """vmaddr of the __TEXT segment (the base LC_FUNCTION_STARTS deltas use)."""
    ncmds, sizeofcmds = struct.unpack_from("<II", data, base + 16)
    off, end = base + 32, min(base + 32 + sizeofcmds, len(data))
    while off < end and ncmds:
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            return None
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].split(b"\0")[0].decode("latin-1")
            if segname == "__TEXT":
                return u64(data, off + 24)
        off += cmdsize
        ncmds -= 1
    return None


def parse_sections(data, base):
    """Return [(segname, sectname, addr, size, fileoff, flags)] for one image."""
    if len(data) < base + 32 or u32(data, base) != MH_MAGIC_64:
        raise ValueError("not a little-endian 64-bit Mach-O at %#x" % base)
    ncmds, sizeofcmds = struct.unpack_from("<II", data, base + 16)
    off, end = base + 32, min(base + 32 + sizeofcmds, len(data))
    out = []
    while off < end and ncmds:
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            break
        if cmd == LC_SEGMENT_64:
            nsects = u32(data, off + 64)
            soff = off + 72
            for _ in range(nsects):
                if soff + 80 > len(data):
                    break
                sectname = data[soff:soff + 16].split(b"\0")[0].decode("latin-1")
                segname = data[soff + 16:soff + 32].split(b"\0")[0].decode("latin-1")
                addr, size = struct.unpack_from("<QQ", data, soff + 32)
                foff = u32(data, soff + 48)
                flags = u32(data, soff + 64)
                out.append((segname, sectname, addr, size, foff, flags))
                soff += 80
        off += cmdsize
        ncmds -= 1
    return out


def load_command(data, base, wanted):
    ncmds, sizeofcmds = struct.unpack_from("<II", data, base + 16)
    off, end = base + 32, min(base + 32 + sizeofcmds, len(data))
    while off < end and ncmds:
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            return None
        if cmd == wanted:
            return off
        off += cmdsize
        ncmds -= 1
    return None


def symbols(data, base):
    off = load_command(data, base, LC_SYMTAB)
    if off is None:
        return []
    symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
    if not nsyms or symoff + nsyms * 16 > len(data) or stroff + strsize > len(data):
        return []
    out = []
    for i in range(nsyms):
        p = symoff + i * 16
        n_strx, n_type, _sect, _desc, n_value = struct.unpack_from("<IBBHQ", data, p)
        if (n_type & 0x0E) != 0x0E or not n_value:   # N_SECT only
            continue
        s = stroff + n_strx
        e = data.find(b"\0", s)
        if e > s:
            out.append((n_value, data[s:e].decode("latin-1")))
    out.sort()
    return out


def function_ranges(data, base, sections, text_vmaddr):
    """LC_FUNCTION_STARTS -> [(file_start, file_end, vm_start)]."""
    off = load_command(data, base, LC_FUNCTION_STARTS)
    if off is None:
        return []
    dataoff, datasize = struct.unpack_from("<II", data, off + 8)
    start_blob = base + dataoff
    if not datasize or start_blob + datasize > len(data) or not text_vmaddr:
        return []
    blob = data[start_blob:start_blob + datasize]
    addrs, p, addr = [], 0, text_vmaddr
    while p < len(blob):
        delta, p = uleb(blob, p)
        if delta == 0:
            break
        addr += delta
        addrs.append(addr)
    insn = [s for s in sections if s[5] & INSN_ATTRS]
    out = []
    for i, a in enumerate(addrs):
        hit = None
        for seg, sect, saddr, size, foff, flags in insn:
            if saddr <= a < saddr + size:
                hit = (seg, sect, saddr, size, foff, flags)
                break
        if hit is None:
            continue
        _seg, _sect, saddr, size, foff, _flags = hit
        start = base + foff + (a - saddr)
        end = base + foff + size
        if i + 1 < len(addrs):
            nxt = addrs[i + 1]
            if saddr <= nxt < saddr + size:
                end = base + foff + (nxt - saddr)
        out.append((start, min(end, len(data)), a))
    return out


def data_in_code(data, base):
    off = load_command(data, base, LC_DATA_IN_CODE)
    if off is None:
        return []
    dataoff, datasize = struct.unpack_from("<II", data, off + 8)
    start = base + dataoff
    if start + datasize > len(data):
        return []
    out = []
    for k in range(0, max(0, datasize - 7), 8):
        offset, length, kind = struct.unpack_from("<IHH", data, start + k)
        if kind:
            out.append((base + offset, base + offset + length))
    return out


def subtract(ranges, cuts):
    out = []
    for s, e in ranges:
        cur = s
        for cs, ce in cuts:
            if ce <= cur or cs >= e:
                continue
            if cs > cur:
                out.append((cur, min(cs, e)))
            cur = max(cur, ce)
            if cur >= e:
                break
        if cur < e:
            out.append((cur, e))
    return out


def intersect(ranges, cuts):
    out = []
    for s, e in ranges:
        for cs, ce in cuts:
            lo, hi = max(s, cs), min(e, ce)
            if lo < hi:
                out.append((lo, hi))
    return out


def scan_image(data, base, label, result, top, scan_all):
    sections = parse_sections(data, base)
    secs = []
    for seg, sect, addr, size, foff, flags in sections:
        if not (flags & INSN_ATTRS) or not size:
            continue
        start = base + foff
        end = min(start + size, len(data))
        if end > start:
            secs.append((start, end, addr, "%s,%s" % (seg, sect)))
    if not secs:
        return

    text_vmaddr = text_segment_vmaddr(data, base)
    if text_vmaddr is None:
        text_vmaddr = secs[0][2]

    funcs = [] if scan_all else function_ranges(data, base, sections, text_vmaddr)
    cuts = [] if scan_all else data_in_code(data, base)
    syms = symbols(data, base)
    sym_addrs = [a for a, _ in syms]
    func_vms = [f[2] for f in funcs]

    def section_name(off):
        for s, e, _vm, name in secs:
            if s <= off < e:
                return name
        return "?"

    def vm_of(off):
        for s, e, vm, _name in secs:
            if s <= off < e:
                return vm + (off - s)
        return None

    def owner(off):
        vm = vm_of(off)
        if vm is None:
            return "%s@file+%#x" % (label, off)
        if func_vms:
            i = bisect.bisect_right(func_vms, vm) - 1
            if i >= 0:
                fvm = func_vms[i]
                if syms:
                    j = bisect.bisect_right(sym_addrs, fvm) - 1
                    if j >= 0 and syms[j][0] == fvm:
                        return "%s+%#x" % (syms[j][1], vm - fvm)
                return "%s@%#x+%#x" % (label, fvm, vm - fvm)
        if syms:
            j = bisect.bisect_right(sym_addrs, vm) - 1
            if j >= 0:
                return "%s+%#x" % (syms[j][1], vm - syms[j][0])
        return "%s@%#x" % (label, vm)

    def scan(start, end, bucket, bucket_key):
        for off in range(start, end - 3, 4):
            w = u32(data, off)
            cls = classify(w)
            if cls is None:
                continue
            result["words_pac"] += 1
            result["counts"][cls] = result["counts"].get(cls, 0) + 1
            per_bucket = result["bucket_counts"].setdefault(bucket_key, {})
            per_bucket[cls] = per_bucket.get(cls, 0) + 1
            key = section_name(off)
            per = result["sections"].setdefault(key, {})
            per[cls] = per.get(cls, 0) + 1
            if cls.startswith("hint:"):
                name = cls[5:]
                result["hints"][name] = result["hints"].get(name, 0) + 1
                continue
            item = {"addr": vm_of(off), "class": cls, "image": label,
                    "owner": owner(off)}
            if bucket is not None and len(bucket) < top:
                bucket.append(item)
            if cls == "ldraa_wide" and len(result["ldraa_wide_examples"]) < top:
                s10, writeback = ldra_decode(w)
                result["ldraa_wide_examples"].append({
                    "addr": item["addr"], "image": label, "owner": item["owner"],
                    "offset": s10 * 8, "writeback": bool(writeback),
                })

    if scan_all:
        for start, end, _vm, _name in secs:
            scan(start, end, result["hits"], "bodies")
        return

    # 1. function bodies minus literal pools / jump tables
    for start, end in subtract([(s, e) for s, e, _vm in funcs], cuts):
        scan(start, end, result["hits"], "bodies")
    # 2. instruction bytes that are not covered by a function start
    covered = [(s, e) for s, e, _vm in funcs]
    for start, end, _vm, name in secs:
        for lo, hi in subtract([(start, end)], covered + cuts):
            scan(lo, hi, result["outside"], "outside")
    # 3. data-in-code ranges inside instruction sections
    for start, end, _vm, _name in secs:
        for lo, hi in intersect([(start, end)], cuts):
            scan(lo, hi, result["data_in_code"], "data_in_code")


def analyze(data, name, scan_all=False, top=200):
    result = {
        "file": name,
        "mode": "instruction-sections" if scan_all else "function-bodies",
        "words_pac": 0,
        "counts": {},
        "bucket_counts": {},
        "sections": {},
        "hits": [],
        "outside": [],
        "data_in_code": [],
        "hints": {},
        "ldraa_wide_examples": [],
        "images": 0,
        "fat_slices": 0,
    }

    images = []
    magic = u32(data, 0) if len(data) >= 8 else 0
    if magic in (FAT_MAGIC, FAT_CIGAM):
        # "cafebabe" bytes read little-endian give FAT_CIGAM: big-endian layout.
        order = ">" if magic == FAT_CIGAM else "<"
        nfat = struct.unpack_from(order + "I", data, 4)[0]
        for i in range(nfat):
            _cpu, _sub, off, _size, _align = struct.unpack_from(
                order + "IIIII", data, 8 + i * 20)
            images.append((off, "slice%d" % i))
        result["fat_slices"] = nfat
    else:
        if len(data) < 32:
            print("file too short", file=sys.stderr)
            return 3
        if u32(data, 12) == MH_FILESET:
            ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
            off, end = 32, min(32 + sizeofcmds, len(data))
            while off < end and ncmds:
                cmd, cmdsize = struct.unpack_from("<II", data, off)
                if cmdsize < 8 or off + cmdsize > len(data):
                    break
                if cmd == LC_FILESET_ENTRY and cmdsize >= 32:
                    foff = u64(data, off + 16)
                    if foff and foff + 32 <= len(data) and u32(data, foff) == MH_MAGIC_64:
                        images.append((foff, "fileset%#x" % foff))
                off += cmdsize
                ncmds -= 1
        if not images:
            images.append((0, "kernel"))

    for base, label in images:
        try:
            scan_image(data, base, label, result, top, scan_all)
        except ValueError:
            continue
        result["images"] += 1

    total = sum(v for k, v in result["counts"].items() if not k.startswith("hint:"))

    def bucket_total(key):
        return sum(v for k, v in result["bucket_counts"].get(key, {}).items()
                   if not k.startswith("hint:"))

    result["total_non_hint_pac"] = total
    result["in_function_bodies"] = bucket_total("bodies")
    result["outside_function_bodies"] = bucket_total("outside")
    result["in_data_in_code"] = bucket_total("data_in_code")
    result["total_hint_pac"] = sum(result["hints"].values())
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
    result["ok"] = total == 0
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--json")
    ap.add_argument("--scan-all", action="store_true",
                    help="sweep whole instruction sections (ignore function starts)")
    ap.add_argument("--top", type=int, default=200)
    args = ap.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()

    result = analyze(data, args.file, args.scan_all, args.top)
    out = json.dumps(result, indent=1)
    if args.json:
        with open(args.json, "w") as f:
            f.write(out + "\n")
    print(out)
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
