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
  g) every patch in patches/ was applied (not "Skipping patch", not missing)
  h) the added lines of every patch are present in the source that the
     artifact ships (buildtree.tgz), when --tree-tgz is given

Usage:
  python3 ci/accept.py --log build.log [--kernel kernel.development.sweet]
                       [--tree-tgz buildtree.tgz] [--patches-dir DIR]
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
    applied_patches = {}    # patch basename -> path from the log
    skipped_patches = {}    # patch basename -> why DXB skipped it
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
            # DXB says "Applying patch: <path>" or
            # "Skipping patch <path> (reason): error: patch failed: ...".
            # The prefix is wrapped in ANSI colours, so only the name matters.
            m = re.search(r"Applying patch: (.+?)\s*$", line)
            if m:
                name = _patch_name(m.group(1))
                if name:
                    applied_patches[name] = m.group(1)
            m = re.search(r"Skipping patch (.+?) \(", line)
            if m:
                name = _patch_name(m.group(1))
                if name:
                    skipped_patches[name] = line.strip()[:300]

    return {
        "log_bytes": bytes_read,
        "flags": flags,
        "pac_mentions": pac_mentions,
        "pac_definitions": pac_definitions,
        "errors": errors,
        "other_errors": other_errors,
        "link_errors": link_errors,
        "make_failures": make_failures,
        "applied_patches": applied_patches,
        "skipped_patches": skipped_patches,
    }


def _patch_name(path):
    """`/a/b/0016-foo.patch` -> `0016-foo.patch`; None for DXB's own patches."""
    base = path.strip().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return base if re.match(r"^\d{4}-.*\.patch$", base) else None


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


def expected_patches(patches_dir):
    """Patch files of this repository, in application order."""
    if not patches_dir or not os.path.isdir(patches_dir):
        return []
    return sorted(n for n in os.listdir(patches_dir)
                  if re.match(r"^\d{4}-.*\.patch$", n))


def criterion_g(scan, patches_dir):
    """Every patch of ours must show up as applied, never as skipped.

    Run 18 was "success" while 0016 was skipped, so the artifact silently
    lacked the post-MMU markers. A skipped patch has to be a red criterion.
    """
    expected = expected_patches(patches_dir)
    if not expected:
        return "skipped", "no patches found in %s" % (patches_dir or "?")
    applied = scan["applied_patches"]
    skipped = scan["skipped_patches"]
    missing = [n for n in expected if n not in applied]
    bad = [n for n in expected if n in skipped]
    if not missing and not bad:
        return "pass", "all %d patches applied: %s .. %s" % (
            len(expected), expected[0], expected[-1])
    parts = []
    for n in bad + [n for n in missing if n not in bad]:
        if n in skipped:
            parts.append("%s SKIPPED: %s" % (n, skipped[n]))
        else:
            parts.append("%s: no 'Applying patch' line in the log" % n)
    return "fail", "\n  ".join(parts)


ADDED_LINE = re.compile(r"^\+(?!\+\+)")


def patch_added_lines(patch_path):
    """{repo-relative target file: [added lines worth checking]}."""
    files = {}
    target = None
    with open(patch_path, "rb") as f:
        for raw in f:
            line = raw.decode("utf-8", "replace").rstrip("\r\n").lstrip("\ufeff")
            if line.startswith("+++ "):
                name = line[4:].split("\t")[0].strip()
                target = name[2:] if name.startswith("b/") else name
                if target == "/dev/null":
                    target = None
                continue
            if target and ADDED_LINE.match(line):
                body = line[1:].strip()
                if len(body) >= 12:   # long enough to be evidence, not `}`
                    files.setdefault(target, []).append(body)
    return files


def criterion_h(patches_dir, tree_tgz):
    """The patched source inside the artifact really contains our changes.

    build.log says the patch was applied; this says the tree that produced
    the kernel carries it. Skipped entirely without --tree-tgz.
    """
    if not tree_tgz:
        return "skipped", "no --tree-tgz given"
    expected = expected_patches(patches_dir)
    if not expected:
        return "skipped", "no patches found in %s" % (patches_dir or "?")
    import tarfile
    problems = []
    checked_files = 0
    checked_lines = 0
    with tarfile.open(tree_tgz, "r:gz") as tar:
        for name in expected:
            files = patch_added_lines(os.path.join(patches_dir, name))
            for target, lines in files.items():
                member = "xnu/" + target
                try:
                    fh = tar.extractfile(member)
                except KeyError:
                    problems.append("%s: %s missing from the tree"
                                    % (name, target))
                    continue
                if fh is None:
                    problems.append("%s: %s is not a file" % (name, target))
                    continue
                text = fh.read().decode("utf-8", "replace")
                checked_files += 1
                for body in lines:
                    checked_lines += 1
                    if body not in text:
                        problems.append("%s: %s lacks %r"
                                        % (name, target, body[:60]))
    if problems:
        return "fail", "%d patch line(s) absent:\n  %s" % (
            len(problems), "\n  ".join(problems[:12]))
    if not checked_lines:
        return "skipped", "no added line long enough to verify"
    return "pass", ("%d added line(s) of %d patches present in %d file(s) of %s"
                    % (checked_lines, len(expected), checked_files,
                       os.path.basename(tree_tgz)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", help="build.log (make + clang output)")
    ap.add_argument("--kernel", help="kernel.development.sweet")
    ap.add_argument("--tree-tgz", help="buildtree.tgz from the CI artifact")
    ap.add_argument("--patches-dir",
                    default=os.path.join(HERE, os.pardir, "patches"),
                    help="directory with NNNN-*.patch (default: ../patches)")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--samples", type=int, default=3)
    args = ap.parse_args()

    scan = {"log_bytes": 0, "flags": {t: {"count": 0, "samples": []}
                                     for t in FLAG_TOKENS},
            "pac_mentions": 0, "pac_definitions": [],
            "errors": {}, "other_errors": {}, "link_errors": {},
            "make_failures": [], "applied_patches": {},
            "skipped_patches": {}}
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
        "g": criterion_g(scan, args.patches_dir) if args.log else (
            "skipped", "no --log given"),
        "h": criterion_h(args.patches_dir, args.tree_tgz),
    }
    order = ["a", "b", "c", "d", "e", "f", "g", "h"]
    statuses = [verdicts[k][0] for k in order]
    if "fail" in statuses:
        code = 1
    elif "skipped" in statuses:
        code = 3
    else:
        code = 0

    print("acceptance criteria (a)-(h)")
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
            "applied_patches": sorted(scan["applied_patches"]),
            "skipped_patches": scan["skipped_patches"],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
    return code


if __name__ == "__main__":
    sys.exit(main())

