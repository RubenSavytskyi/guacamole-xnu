#!/usr/bin/env python3
"""Acceptance criteria (a)-(e) for the SWEET kernel build, from evidence.

Input is the raw build output (make + clang, i.e. the CI `build.log`) and,
optionally, the kernel it produced. Nothing here guesses: every verdict
carries the number of matching lines and up to three samples.

  a) no `-arch arm64e`, `-fptrauth`, `-mbranch-protection`, `+pauth` in the log
  b) `CPU_HAS_APPLE_PAC` is never defined
  c) the kernel is a single arm64 (not arm64e) Mach-O slice
  d) zero non-hint PAC instructions in function bodies (ci/pac_count.py)
  e) the full list of compiler errors, deduplicated
  f) no linker or make failure, and a kernel was produced

Usage:
  python3 ci/accept.py --log build.log [--kernel kernel.development.sweet]
                       [--json out.json] [--samples 3]

Exit code: 0 only if every criterion that could be evaluated passed.
Criteria that cannot be evaluated (missing input) report "skipped" and make
the exit code 3, so a partial answer is never mistaken for a pass.
"""

import argparse
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# criterion (a): tokens that must not appear in a plain-arm64 build
FLAG_TOKENS = ("-arch arm64e", "-fptrauth", "-mbranch-protection", "+pauth")

# a clang diagnostic looks like `path:12:34: error: ...`
CLANG_ERROR = re.compile(r":\d+:\d+: (?:fatal )?error: ")
# `path:12: error: ...` (some diagnostics have no column)
CLANG_ERROR_NOCOL = re.compile(r":\d+: (?:fatal )?error: ")

CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
CPU_SUBTYPE_MASK = 0xFF000000
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64_V8 = 1


def cpu_name(cputype, cpusubtype):
    """Decode (cputype, cpusubtype) the way `lipo -info` does."""
    sub = cpusubtype & ~CPU_SUBTYPE_MASK
    if cputype == CPU_TYPE_ARM64:
        if sub == CPU_SUBTYPE_ARM64E:
            return "arm64e"
        if sub == CPU_SUBTYPE_ARM64_V8:
            return "arm64_32"  # not used on macOS, but keeps names distinct
        return "arm64"
    if cputype == CPU_TYPE_X86_64:
        return "x86_64"
    return "cputype=%#x subtype=%#x" % (cputype, sub)


def kernel_slices(path):
    """Return [(offset, cputype, cpusubtype)] for a Mach-O or fat file."""
    with open(path, "rb") as f:
        data = f.read(1 << 16)
    if len(data) < 8:
        raise ValueError("file too short to be a Mach-O")
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        nfat = struct.unpack_from(">I", data, 4)[0]
        out = []
        for i in range(nfat):
            if 0xCAFEBABF == magic:
                cpu, sub, off = struct.unpack_from(">iiQ", data, 8 + i * 32)
            else:
                cpu, sub, off = struct.unpack_from(">iiI", data, 8 + i * 20)
            out.append((off, cpu & 0xFFFFFFFF, sub & 0xFFFFFFFF))
        return out
    if magic in (0xFEEDFACE, 0xFEEDFACF):
        cpu, sub = struct.unpack_from(">ii", data, 4)
        return [(0, cpu & 0xFFFFFFFF, sub & 0xFFFFFFFF)]
    if magic in (0xCEFAEDFE, 0xCFFAEDFE):
        cpu, sub = struct.unpack_from("<ii", data, 4)
        return [(0, cpu & 0xFFFFFFFF, sub & 0xFFFFFFFF)]
    raise ValueError("not a Mach-O (magic %#x)" % magic)


def scan_log(path, samples):
    """One pass over the (possibly huge) log.

    Returns the evidence for criteria a, b and e. Parallel make interleaves
    lines, so nothing here assumes a line starts where it should.
    """
    flags = {t: {"count": 0, "samples": []} for t in FLAG_TOKENS}
    pac_mentions = 0
    pac_definitions = []
    errors = {}          # deduplicated clang diagnostics -> count
    other_errors = {}    # git apply / ld / misc -> count
    link_errors = {}
    make_failures = []
    bytes_read = 0

    with open(path, "rb") as f:
        for raw in f:
            bytes_read += len(raw)
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line:
                continue
            for token in FLAG_TOKENS:
                if token in line:
                    entry = flags[token]
                    entry["count"] += 1
                    if len(entry["samples"]) < samples:
                        entry["samples"].append(line.strip()[:300])
            if "CPU_HAS_APPLE_PAC" in line:
                pac_mentions += 1
                # a definition, not a use: -D..., #define ... 1, ...=1
                if re.search(r"-D\s*CPU_HAS_APPLE_PAC(?![A-Za-z0-9_])"
                             r"|#\s*define\s+CPU_HAS_APPLE_PAC(?![A-Za-z0-9_])"
                             r"|CPU_HAS_APPLE_PAC\s*=\s*1", line):
                    if len(pac_definitions) < samples:
                        pac_definitions.append(line.strip()[:300])
            if "error:" in line:
                if CLANG_ERROR.search(line):
                    key = line[line.index("error:"):].strip()
                    # keep the file of the diagnostic, it is what identifies it
                    loc = line[:line.index("error:")].strip()
                    key = "%s | %s" % (loc, key)
                    errors[key] = errors.get(key, 0) + 1
                elif CLANG_ERROR_NOCOL.search(line):
                    loc = line[:line.index("error:")].strip()
                    key = "%s | %s" % (loc, line[line.index("error:"):].strip())
                    errors[key] = errors.get(key, 0) + 1
                else:
                    key = line.strip()[:200]
                    other_errors[key] = other_errors.get(key, 0) + 1
            if ("Undefined symbols for architecture " in line
                    or "ld: symbol(s) not found for architecture " in line
                    or "clang++: error: linker command failed" in line
                    or re.search(r"ld: library '.+' not found", line)):
                key = line.strip()[:300]
                link_errors[key] = link_errors.get(key, 0) + 1
            if "***" in line and ("Error " in line or "not remade" in line):
                if len(make_failures) < 10:
                    make_failures.append(line.strip()[:300])

    return {
        "log_bytes": bytes_read,
        "flags": flags,
        "pac_mentions": pac_mentions,
        "pac_definitions": pac_definitions,
        "errors": errors,
        "other_errors": other_errors,
        "link_errors": link_errors,
        "make_failures": make_failures,
    }


def criterion_a(flags):
    hits = {t: v["count"] for t, v in flags.items() if v["count"]}
    if not hits:
        return "pass", "no -arch arm64e / -fptrauth / -mbranch-protection / +pauth"
    parts = []
    for token, count in sorted(hits.items()):
        s = flags[token]["samples"]
        parts.append("%s x%d%s" % (token, count,
                                   ("" if not s else "  e.g. " + s[0])))
    return "fail", "; ".join(parts)


def criterion_b(scan):
    if scan["pac_definitions"]:
        return "fail", "CPU_HAS_APPLE_PAC defined: " + " | ".join(
            scan["pac_definitions"])
    return "pass", ("CPU_HAS_APPLE_PAC never defined (%d mentions, all uses)"
                    % scan["pac_mentions"])


def criterion_c(kernel):
    if not kernel:
        return "skipped", "no kernel given"
    try:
        slices = kernel_slices(kernel)
    except (OSError, ValueError) as exc:
        return "fail", str(exc)
    names = [cpu_name(cpu, sub) for _off, cpu, sub in slices]
    detail = "lipo -info: " + " ".join(names)
    if len(slices) != 1:
        return "fail", "%d slices: %s" % (len(slices), detail)
    if names[0] != "arm64":
        return "fail", detail
    return "pass", detail


def criterion_d(kernel):
    if not kernel:
        return "skipped", "no kernel given"
    import pac_count
    with open(kernel, "rb") as f:
        data = f.read()
    res = pac_count.analyze(data, os.path.basename(kernel))
    total = res["total_non_hint_pac"]
    detail = ("%d non-hint PAC in %d image(s), %d in function bodies, "
              "%d outside, %d in data-in-code"
              % (total, res["images"], res["in_function_bodies"],
                 res["outside_function_bodies"], res["in_data_in_code"]))
    if total == 0:
        return "pass", detail
    functions = []
    for hit in res["hits"]:
        functions.append(hit.get("owner") or "?")
    uniq = sorted(set(functions))
    return "fail", detail + "; functions: " + ", ".join(uniq[:40])


def criterion_e(scan):
    errors = scan["errors"]
    if not errors:
        if scan["other_errors"]:
            return "pass", ("no clang errors; non-clang error lines (%d distinct): %s"
                            % (len(scan["other_errors"]),
                               " | ".join(scan["other_errors"])))
        return "pass", "no errors in the log"
    lines = ["%s  (x%d)" % (k, v) if v > 1 else k for k, v in errors.items()]
    extra = ""
    if scan["other_errors"]:
        extra = "\n  non-clang error lines (%d distinct): %s" % (
            len(scan["other_errors"]), " | ".join(scan["other_errors"]))
    return "fail", "%d distinct clang error(s):\n  %s%s" % (
        len(errors), "\n  ".join(lines), extra)


def criterion_f(scan, kernel):
    failures = []
    if scan["link_errors"]:
        failures.extend("%s (x%d)" % (line, count)
                        for line, count in scan["link_errors"].items())
    if scan["make_failures"]:
        failures.extend(scan["make_failures"])
    if failures:
        return "fail", "build failed:\n  " + "\n  ".join(failures[:20])
    if not kernel:
        return "skipped", "no kernel was produced"
    return "pass", "kernel artifact produced with no linker or make failures"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", help="build.log (make + clang output)")
    ap.add_argument("--kernel", help="kernel.development.sweet")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--samples", type=int, default=3)
    args = ap.parse_args()

    scan = {"log_bytes": 0, "flags": {t: {"count": 0, "samples": []}
                                     for t in FLAG_TOKENS},
            "pac_mentions": 0, "pac_definitions": [],
            "errors": {}, "other_errors": {}, "link_errors": {},
            "make_failures": []}
    if args.log:
        scan = scan_log(args.log, args.samples)

    verdicts = {
        "a": criterion_a(scan["flags"]) if args.log else (
            "skipped", "no --log given"),
        "b": criterion_b(scan) if args.log else ("skipped", "no --log given"),
        "c": criterion_c(args.kernel),
        "d": criterion_d(args.kernel),
        "e": criterion_e(scan) if args.log else ("skipped", "no --log given"),
        "f": criterion_f(scan, args.kernel) if args.log else (
            "skipped", "no --log given"),
    }
    order = ["a", "b", "c", "d", "e", "f"]
    statuses = [verdicts[k][0] for k in order]
    if "fail" in statuses:
        code = 1
    elif "skipped" in statuses:
        code = 3
    else:
        code = 0

    print("acceptance criteria (a)-(f)")
    if args.log:
        print("log: %s (%.1f MB)" % (args.log, scan["log_bytes"] / 1e6))
    if args.kernel:
        print("kernel: %s (%d B)" % (args.kernel, os.path.getsize(args.kernel)))
    print()
    for k in order:
        status, detail = verdicts[k]
        print("(%s) %-7s %s" % (k, status.upper(), detail.replace(
            "\n", "\n    ")))
    print()
    print("result: %s (exit %d)" % (
        "PASS" if code == 0 else ("FAIL" if code == 1 else "INCOMPLETE"), code))

    if args.json:
        report = {
            "criteria": {k: {"status": verdicts[k][0],
                             "detail": verdicts[k][1]} for k in order},
            "exit_code": code,
            "log": args.log,
            "log_bytes": scan["log_bytes"],
            "flags": {t: scan["flags"][t]["count"] for t in FLAG_TOKENS},
            "pac_mentions": scan["pac_mentions"],
            "clang_errors": scan["errors"],
            "non_clang_errors": scan["other_errors"],
            "link_errors": scan["link_errors"],
            "make_failures": scan["make_failures"],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
    return code


if __name__ == "__main__":
    sys.exit(main())

