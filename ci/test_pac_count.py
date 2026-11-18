#!/usr/bin/env python3
"""Unit tests for ci/pac_count.py (run: python3 ci/test_pac_count.py).

No external tools required.  The expected words were produced with llvm-mc
(-triple=arm64 -mattr=+pauth,+rcpc) and are cross-checked against it when it
is available.
"""
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pac_count as pc  # noqa: E402

FAILS = []


def check(cond, msg):
    if cond:
        print("OK   " + msg)
    else:
        print("FAIL " + msg)
        FAILS.append(msg)


# ---------------------------------------------------------------- encodings
# form -> (word, expected class)
FORMS = [
    ("pacia x0, x1", 0xDAC10020, "pacia"),
    ("pacib x2, x3", 0xDAC10462, "pacib"),
    ("pacda x4, x5", 0xDAC108A4, "pacda"),
    ("pacdb x6, x7", 0xDAC10CE6, "pacdb"),
    ("autia x8, x9", 0xDAC11128, "autia"),
    ("autib x10, x11", 0xDAC1156A, "autib"),
    ("autda x12, x13", 0xDAC119AC, "autda"),
    ("autdb x14, x15", 0xDAC11DEE, "autdb"),
    ("xpaci x16", 0xDAC143F0, "xpaci"),
    ("xpacd x17", 0xDAC147F1, "xpacd"),
    ("pacga x18, x19, x20", 0x9AD43272, "pacga"),
    ("braa x0, x1", 0xD71F0801, "braa"),
    ("brab x2, x3", 0xD71F0C43, "brab"),
    ("braaz x5", 0xD61F08BF, "braaz"),
    ("brabz x7", 0xD61F0CFF, "brabz"),
    ("blraa x8, x9", 0xD73F0909, "blraa"),
    ("blrab x10, x11", 0xD73F0D4B, "blrab"),
    ("blraaz x13", 0xD63F09BF, "blraaz"),
    ("blrabz x15", 0xD63F0DFF, "blrabz"),
    ("ldraa x0, [x1, #8]", 0xF8201420, "ldraa_pos"),
    ("ldraa x2, [x3, #-8]", 0xF87FF462, "ldraa_neg"),
    ("ldraa x4, [x5, #8]!", 0xF8201CA4, "ldraa_pre"),
    ("ldraa x6, [x7, #-512]", 0xF87C04E6, "ldraa_wide"),
    ("ldraa x8, [x9, #504]", 0xF823F528, "ldraa_pos"),
    ("ldraa x10, [x11, #-256]", 0xF87E056A, "ldraa_neg"),
    ("ldraa x12, [x13, #248]!", 0xF821FDAC, "ldraa_pre"),
    ("ldraa x14, [x15, #-256]!", 0xF87E0DEE, "ldraa_pre"),
    ("ldraa x16, [x17, #256]!", 0xF8220E30, "ldraa_wide"),
    ("ldraa x18, [x19]", 0xF8200672, "ldraa_pos"),
    ("ldrab x0, [x1, #8]", 0xF8A01420, "ldraa_pos"),
    ("ldrab x24, [x25, #-40]!", 0xF8FFBF38, "ldraa_pre"),
]

# form -> (word, byte offset, writeback)
LDRA = [
    ("ldraa x0, [x1, #8]", 0xF8201420, 8, 0),
    ("ldraa x2, [x3, #-8]", 0xF87FF462, -8, 0),
    ("ldraa x4, [x5, #8]!", 0xF8201CA4, 8, 1),
    ("ldraa x6, [x7, #-512]", 0xF87C04E6, -512, 0),
    ("ldraa x8, [x9, #504]", 0xF823F528, 504, 0),
    ("ldraa x10, [x11, #-256]", 0xF87E056A, -256, 0),
    ("ldraa x12, [x13, #248]!", 0xF821FDAC, 248, 1),
    ("ldraa x14, [x15, #-256]!", 0xF87E0DEE, -256, 1),
    ("ldraa x16, [x17, #256]!", 0xF8220E30, 256, 1),
    ("ldraa x18, [x19]", 0xF8200672, 0, 0),
    ("ldrab x0, [x1, #8]", 0xF8A01420, 8, 0),
    ("ldrab x24, [x25, #-40]!", 0xF8FFBF38, -40, 1),
]

# ordinary instructions that share prefixes and must stay clean
CLEAN = [
    ("ret", 0xD65F03C0),
    ("eret", 0xD69F03E0),
    ("blr x0", 0xD63F0000),
    ("br x0", 0xD61F0000),
    ("bl x1", 0x94000001),
    ("ldr x0, [x1]", 0xF9400020),
    ("ldr x0, [x1, #-8]!", 0xF85F8C20),
    ("ldr x0, [x1], #8", 0xF8408420),
    ("ldur x0, [x1, #-8]", 0xF85F8020),
    ("movz x0, #0", 0xD2800000),
    ("nop", 0xD503201F),
    ("mrs x0, tpidr_el0", 0xD53BD040),
    ("add x0, x1, x2", 0x8B020020),
    ("hint #7", 0xD503207F),
]

print("== classifier vs llvm-mc encodings")
for form, word, want in FORMS:
    got = pc.classify(word)
    check(got == want, "%-28s 0x%08X -> %s (want %s)" % (form, word, got, want))

print()
print("== ordinary instructions are not PAC")
for form, word in CLEAN:
    got = pc.classify(word)
    check(got is None, "%-24s 0x%08X -> %s" % (form, word, got))

print()
print("== LDRAA/LDRAB immediate decoding")
for form, word, want_off, want_wb in LDRA:
    s10, wb = pc.ldra_decode(word)
    check(s10 * 8 == want_off and wb == want_wb,
          "%-24s offset=%d writeback=%d" % (form, s10 * 8, wb))

print()
print("== PAC hints")
for word, name in ((0xD503233F, "paciasp"), (0xD50323BF, "autiasp"),
                   (0xD503211F, "pacia1716"), (0xD50320FF, "xpaclri")):
    check(pc.classify(word) == "hint:" + name,
          "0x%08X -> hint:%s" % (word, name))

# ------------------------------------------------------------ synthetic file
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 0x80000002
MH_EXECUTE = 2
MH_FILESET = 0xC
LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_FILESET_ENTRY = 0x80000034
PURE = 0x80000000 | 0x00000400

TEXT_VMADDR = 0x100000000
TEXT_FILEOFF = 0x400
TEXT_SIZE = 0x100
FUNC_A = 0x440
FUNC_B = 0x480
DATA_WORD = 0x448

PACIA = 0xDAC10220
PACIB = 0xDAC10462
PACDA = 0xDAC108A4
RETAA = 0xD65F0BFF
RETAB = 0xD65F0FFF
NOP = 0xD503201F


def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def macho():
    seg_cmdsize = 72 + 80
    ncmds = 4
    sizeofcmds = seg_cmdsize + 16 + 16
    hdr = struct.pack("<IIIIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E,
                      MH_EXECUTE, ncmds, sizeofcmds, 0, 0)
    seg = struct.pack("<II16sQQQQiiII", LC_SEGMENT_64, seg_cmdsize, b"__TEXT",
                      TEXT_VMADDR, 0x4000, 0, TEXT_FILEOFF + TEXT_SIZE, 7, 5, 1, 0)
    sect = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT",
                       TEXT_VMADDR + TEXT_FILEOFF, TEXT_SIZE, TEXT_FILEOFF,
                       2, 0, 0, PURE, 0, 0, 0)
    fstarts = uleb(FUNC_A) + uleb(FUNC_B - FUNC_A) + b"\0"
    dic = struct.pack("<IHH", DATA_WORD, 4, 1)
    fst_cmd = struct.pack("<IIII", LC_FUNCTION_STARTS, 16, 0x300, len(fstarts))
    dic_cmd = struct.pack("<IIII", LC_DATA_IN_CODE, 16, 0x310, len(dic))
    buf = bytearray(0x500)
    buf[0:len(hdr)] = hdr
    p = len(hdr)
    buf[p:p + seg_cmdsize] = seg + sect
    p += seg_cmdsize
    buf[p:p + 16] = fst_cmd
    p += 16
    buf[p:p + 16] = dic_cmd
    buf[0x300:0x300 + len(fstarts)] = fstarts
    buf[0x310:0x310 + len(dic)] = dic
    for off in range(TEXT_FILEOFF, TEXT_FILEOFF + TEXT_SIZE, 4):
        struct.pack_into("<I", buf, off, NOP)
    for off in range(TEXT_FILEOFF, FUNC_A, 4):           # 16 words before func A
        struct.pack_into("<I", buf, off, PACIA)
    for off in range(0x460, 0x480, 4):
        struct.pack_into("<I", buf, off, 0xDEADBEEF)
    for off, w in {FUNC_A: PACIA, FUNC_A + 4: PACIB, DATA_WORD: PACIA,
                   FUNC_A + 0x10: RETAA, FUNC_B: PACDA,
                   FUNC_B + 4: RETAB}.items():
        struct.pack_into("<I", buf, off, w)
    return bytes(buf)


def fat(img):
    """One-slice fat binary with the Mach-O at offset 0x4000."""
    off = 0x4000
    out = bytearray(off + len(img))
    struct.pack_into(">II", out, 0, 0xCAFEBABE, 1)
    struct.pack_into(">IIIII", out, 8, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, off, len(img), 12)
    out[off:] = img
    return bytes(out)


def fileset(img):
    """MH_FILESET whose single entry is the Mach-O at offset 0x1000."""
    off = 0x1000
    out = bytearray(off + len(img))
    entry_id = 32                                  # lc_str offset inside the cmd
    hdr = struct.pack("<IIIIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E,
                      MH_FILESET, 1, entry_id, 0, 0)
    cmd = struct.pack("<IIQQII", LC_FILESET_ENTRY, 32, 0x100000000, off,
                      entry_id, 0) + b"com.apple.kernel\0"
    cmd = cmd[:32]                                  # keep the fixed part only
    out[0:len(hdr)] = hdr
    out[len(hdr):len(hdr) + len(cmd)] = cmd
    out[off:] = img
    return bytes(out)


def assert_exact(res, label):
    counts = {k: v for k, v in res["counts"].items() if not k.startswith("hint:")}
    check(counts == {"pacia": 18, "pacib": 1, "retaa": 1, "pacda": 1, "retab": 1},
          "%s aggregate counts %s (16 padding + 1 data-in-code + 1 body PACIA)" % (label, counts))
    check(res["in_function_bodies"] == 5, "%s 5 PAC words in function bodies" % label)
    check(res["outside_function_bodies"] == 16, "%s 16 before the first function" % label)
    check(res["in_data_in_code"] == 1, "%s 1 inside LC_DATA_IN_CODE" % label)
    check(res["total_non_hint_pac"] == 22, "%s total 22" % label)
    check(res["images"] == 1, "%s images == 1" % label)
    check(res["ok"] is False, "%s ok == False" % label)
    check(res["ldraa"]["total"] == 0, "%s no LDRAA" % label)


print()
print("== synthetic Mach-O: function bodies, padding, data-in-code")
img = macho()
res = pc.analyze(img, "synthetic")
assert_exact(res, "thin")
bodies = sorted(h["class"] for h in res["hits"])
check(bodies == ["pacda", "pacia", "pacib", "retaa", "retab"],
      "body hits are exactly the five real instructions: %s" % bodies)
check(len(res["outside"]) == 16 and all(h["class"] == "pacia" for h in res["outside"]),
      "outside hits are only the 16 padding PACIA words")
check(len(res["data_in_code"]) == 1 and res["data_in_code"][0]["class"] == "pacia",
      "data-in-code hit is the recorded PACIA word")

print()
print("== --scan-all sweeps whole instruction sections")
res = pc.analyze(img, "synthetic-all", scan_all=True)
check(res["total_non_hint_pac"] == 22, "scan-all total == 22")
check(res["outside_function_bodies"] == 0 and res["in_data_in_code"] == 0,
      "scan-all has no separate buckets")

print()
print("== fat slice")
res = pc.analyze(fat(img), "synthetic-fat")
check(res["fat_slices"] == 1, "fat_slices == 1")
assert_exact(res, "fat")

print()
print("== MH_FILESET entry")
res = pc.analyze(fileset(img), "synthetic-fileset")
check(res["images"] == 1, "fileset images == 1")
assert_exact(res, "fileset")

print()
print("== LDRAA breakdown in a tiny image")
# Build one function body of 4 words: wide LDRAA, neg LDRAA, pre LDRAA, RETAA.
tiny = bytearray(macho())
wide = 0xF87C04E6      # ldraa x6, [x7, #-512]
neg = 0xF87FF462       # ldraa x2, [x3, #-8]
pre = 0xF8201CA4       # ldraa x4, [x5, #8]!
for off, w in ((FUNC_A, wide), (FUNC_A + 4, neg), (FUNC_A + 8, pre),
               (FUNC_A + 12, RETAA)):
    struct.pack_into("<I", tiny, off, w)
res = pc.analyze(bytes(tiny), "ldra")
check(res["ldraa"] == {"pos": 0, "neg": 1, "pre_index": 1,
                       "not_rewritable_1to1": 1,
                       "offset_lt_minus_256": 2, "total": 3},
      "ldraa breakdown %s" % res["ldraa"])
check(res["ldraa_wide_examples"][0]["offset"] == -512
      and res["ldraa_wide_examples"][0]["writeback"] is False,
      "wide example records offset -512, no writeback")

# --------------------------------------------------- optional llvm-mc check
if os.environ.get("PAC_TEST_NO_LLVM") != "1":
    asm = "\n".join(f for f, _w, _c in FORMS) + "\n"
    try:
        p = subprocess.run(["llvm-mc", "-triple=arm64", "-mattr=+pauth,+rcpc",
                            "-show-encoding"], input=".text\n" + asm,
                           capture_output=True, text=True)
        encs = [l for l in p.stdout.splitlines() if "encoding:" in l]
        ok = len(encs) == len(FORMS)
        for (form, word, _cls), line in zip(FORMS, encs):
            bs = [int(x, 16) for x in __import__("re").findall(r"0x([0-9a-f]{2})", line)]
            got = bs[0] | bs[1] << 8 | bs[2] << 16 | bs[3] << 24
            ok = ok and got == word
        print()
        check(ok, "hardcoded words match llvm-mc (%d forms)" % len(FORMS))
    except FileNotFoundError:
        print("SKIP llvm-mc cross-check (llvm-mc not in PATH)")

print()
if FAILS:
    print("FAILED: %d" % len(FAILS))
    sys.exit(1)
print("all pac_count tests passed")
