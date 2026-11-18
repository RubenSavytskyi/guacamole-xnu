#!/usr/bin/env python3
"""Unit tests for ci/dsc_hist.py on a synthetic split dyld shared cache.

Run: python3 ci/test_dsc_hist.py
The cache files are written to a temp directory and deleted afterwards; no
real Apple binaries are involved.
"""
import json
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import dsc_hist as dh  # noqa: E402
import pac_count as pc  # noqa: E402

FAILS = []


def check(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        FAILS.append(msg)


MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
PURE = 0x80000000 | 0x00000400

PACIA = 0xDAC10020
RETAB = 0xD65F0FFF
RET = 0xD65F03C0


def macho_image(vm_base, text_off, words):
    """__TEXT segment at vm_base, __text at vm_base+text_off."""
    sect_size = len(words) * 4
    seg_cmdsize = 72 + 80
    hdr = struct.pack("<IIIIIIII", MH_MAGIC_64, 0x0100000C, 0x80000002, 2,
                      1, seg_cmdsize, 0, 0)
    seg = struct.pack("<II16sQQQQiiII", LC_SEGMENT_64, seg_cmdsize, b"__TEXT",
                      vm_base, 0x4000, 0, text_off + sect_size, 5, 5, 1, 0)
    sect = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT",
                       vm_base + text_off, sect_size, text_off,
                       2, 0, 0, PURE, 0, 0, 0)
    return hdr + seg + sect


def build_cache(directory):
    main = os.path.join(directory, "dyld_shared_cache_arm64e")
    sub1 = main + ".01"
    sub2 = main + ".02"
    SRS = 0x180000000

    def header(mapping_off, mapping_count, images_off, images_count):
        h = bytearray(0x8000)
        h[0:16] = b"dyld_v1  arm64e\0\0"
        struct.pack_into("<II", h, 16, mapping_off, mapping_count)
        struct.pack_into("<II", h, 24, 0, 0)          # old image fields unused
        h[88:104] = bytes(range(16))
        struct.pack_into("<Q", h, 104, 2)             # cacheType = multi-cache
        struct.pack_into("<QQ", h, 224, SRS, 0x40000)  # sharedRegionStart/Size
        struct.pack_into("<I", h, 364, 0x1A0500)      # 26.5.0
        struct.pack_into("<II", h, 448, images_off, images_count)
        return h

    def mapping(h, index, addr, size, fileoff):
        struct.pack_into("<QQQii", h, 0x100 + index * 32, addr, size, fileoff, 5, 5)

    # ---- main file: vm 0x180000000..0x180008000 mapped at file 0
    m = header(0x100, 1, 0x300, 2)
    mapping(m, 0, SRS, 0x8000, 0)
    struct.pack_into("<QQQII", m, 0x300, SRS + 0x10000, 0, 0, 0x600, 0)
    path0 = b"/usr/lib/libfirst.dylib\0"
    path1 = b"/usr/lib/libsecond.dylib\0"
    m[0x600:0x600 + len(path0)] = path0
    struct.pack_into("<QQQII", m, 0x320, SRS + 0x20000, 0, 0, 0x600 + len(path0), 0)
    m[0x600 + len(path0):0x600 + len(path0) + len(path1)] = path1

    # image 0 lives in subcache .01: vm 0x180010000 -> file 0x1000
    words0 = [PACIA, RET, RETAB, RET]
    img0 = macho_image(SRS + 0x10000, 0x1000, words0)
    image0 = bytearray(0x1000 + len(words0) * 4)
    image0[0:len(img0)] = img0
    for i, w in enumerate(words0):
        struct.pack_into("<I", image0, 0x1000 + i * 4, w)

    s1 = header(0x100, 1, 0, 0)
    mapping(s1, 0, SRS + 0x10000, 0x4000, 0x1000)
    s1[0x1000:0x1000 + len(image0)] = image0

    # image 1 lives in subcache .02: vm 0x180020000 -> file 0x1000
    words1 = [PACIA, RETAB, PACIA, RET]
    img1 = macho_image(SRS + 0x20000, 0x1000, words1)
    image1 = bytearray(0x1000 + len(words1) * 4)
    image1[0:len(img1)] = img1
    for i, w in enumerate(words1):
        struct.pack_into("<I", image1, 0x1000 + i * 4, w)

    s2 = header(0x100, 1, 0, 0)
    mapping(s2, 0, SRS + 0x20000, 0x4000, 0x1000)
    s2[0x1000:0x1000 + len(image1)] = image1

    with open(main, "wb") as f:
        f.write(bytes(m))
    with open(sub1, "wb") as f:
        f.write(bytes(s1))
    with open(sub2, "wb") as f:
        f.write(bytes(s2))
    # a non-cache sibling that must be ignored
    with open(main + ".map", "w") as f:
        f.write("not a cache\n")
    return main


print("== fast counter matches pac_count.classify")
counter = {}
count_word = dh.make_counter()[1]


def words_for_test():
    forms = []
    for line in open(os.path.join(HERE, "test_pac_count.py")):
        if '", 0x' in line and line.strip().startswith('("'):
            try:
                parts = line.strip().rstrip(",").split(", 0x")
                form = parts[0].strip('( "')
                word = int(parts[1].split(",")[0], 16)
                forms.append((form, word))
            except (ValueError, IndexError):
                pass
    return forms


forms = words_for_test()
mismatch = []
for form, word in forms:
    got = pc.classify(word)
    counts, count_word = dh.make_counter()
    count_word(word)
    fast = next(iter(counts), None)
    if got != fast:
        mismatch.append((form, word, got, fast))
check(len(forms) >= 30 and not mismatch,
      "%d words agree with classify() (mismatches: %s)" % (len(forms), mismatch[:3]))

import random  # noqa: E402
random.seed(1234)
bad = 0
for _ in range(20000):
    w = random.getrandbits(32)
    a = pc.classify(w)
    counts, count_word = dh.make_counter()
    count_word(w)
    b = next(iter(counts), None)
    if a != b:
        bad += 1
        if bad < 4:
            print("   mismatch %#010x classify=%r fast=%r" % (w, a, b))
check(bad == 0, "20000 random words agree")

print()
print("== split cache parsing")
with tempfile.TemporaryDirectory() as tmp:
    main_path = build_cache(tmp)
    res = dh.histogram(main_path)
    check(res["cache"]["files"] == ["dyld_shared_cache_arm64e",
                                    "dyld_shared_cache_arm64e.01",
                                    "dyld_shared_cache_arm64e.02"],
          "three cache files found, .map ignored: %s" % res["cache"]["files"])
    check(res["cache"]["mappings"] == 3, "three mappings merged")
    check(res["cache"]["images_total"] == 2, "two images in the list")
    check(res["images_scanned"] == 2, "two images scanned")
    check(res["text_bytes"] == 32, "32 bytes of __text")
    check(res["words_scanned"] == 8, "8 instruction words")
    check(res["counts"].get("pacia") == 3 and res["counts"].get("retab") == 2,
          "pacia=3 retab=2 in counts: %s" % res["counts"])
    check(res["total_non_hint_pac"] == 5, "5 non-hint PAC words")
    check(res["groups"]["ldraa_ldrab"] == 0, "no LDRAA")
    check(res["ldraa"]["total"] == 0, "ldraa breakdown empty")
    check(res["cache"]["os_version"] == "26.5.0",
          "os_version %s" % res["cache"]["os_version"])
    top = {t["path"]: t["pac"] for t in res["top_images"]}
    check(top.get("/usr/lib/libsecond.dylib") == 3,
          "top_images attributes 3 PAC words to libsecond: %s" % top)

    listed = dh.histogram(main_path, list_only=True)
    paths = [i["path"] for i in listed["images"]]
    check(paths == ["/usr/lib/libfirst.dylib", "/usr/lib/libsecond.dylib"],
          "--list returns both paths: %s" % paths)

print()
if FAILS:
    print("FAILED: %d" % len(FAILS))
    sys.exit(1)
print("all dsc_hist tests passed")
