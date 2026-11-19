#!/usr/bin/env python3
"""Tests for ci/accept.py: the evidence behind acceptance criteria a-e.

Each case is a synthetic build log and/or Mach-O header, so the test says
exactly which line or header field drives each verdict.
"""

import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ACCEPT = os.path.join(HERE, "accept.py")

CPU_TYPE_ARM64 = 0x0100000C


def macho(cputype, cpusubtype, ncmds=0):
    """Minimal 64-bit Mach-O header, no load commands."""
    return struct.pack(">IIIIIIII", 0xFEEDFACF, cputype, cpusubtype,
                       2, ncmds, 0, 0, 0) + b"\x00" * 32


class AcceptTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="accept-")
        self.patches = os.path.join(self.dir, "patches")
        os.makedirs(self.patches)

    def path(self, name):
        return os.path.join(self.dir, name)

    def write(self, name, data):
        p = self.path(name)
        with open(p, "wb" if isinstance(data, bytes) else "w") as f:
            f.write(data)
        return p

    def write_patch(self, name, target, added):
        body = ["diff --git a/%s b/%s" % (target, target),
                "--- a/%s" % target,
                "+++ b/%s" % target,
                "@@ -1,1 +1,2 @@"]
        body += ["+" + line for line in added]
        return self.write(os.path.join("patches", name), "\n".join(body) + "\n")

    def run_accept(self, log=None, kernel=None, tree=None):
        cmd = [sys.executable, ACCEPT, "--patches-dir", self.patches]
        if log:
            cmd += ["--log", log]
        if kernel:
            cmd += ["--kernel", kernel]
        if tree:
            cmd += ["--tree-tgz", tree]
        p = subprocess.run(cmd, capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def status(self, out, letter):
        for line in out.splitlines():
            if line.startswith("(%s) " % letter):
                return line.split()[1]
        self.fail("no verdict for (%s) in:\n%s" % (letter, out))

    # (a) -------------------------------------------------------------
    def test_a_clean_log_passes(self):
        log = self.write("a.log", "clang -arch arm64 -c foo.c\nfoo done\n")
        code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "a"), "PASS")
        self.assertEqual(self.status(out, "b"), "PASS")

    def test_a_arch_arm64e_fails_and_quotes_the_line(self):
        log = self.write("a.log",
                         "clang -arch arm64e -c foo.c\n"
                         "clang -arch arm64 -c bar.c\n")
        code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "a"), "FAIL")
        self.assertIn("-arch arm64e x1", out)
        self.assertEqual(code, 1)

    def test_a_each_flag_is_detected(self):
        for flag in ("-fptrauth", "-mbranch-protection=pac-ret", "+pauth"):
            log = self.write("a.log", "clang %s -c foo.c\n" % flag)
            _code, out = self.run_accept(log=log)
            self.assertEqual(self.status(out, "a"), "FAIL", flag)

    # (b) -------------------------------------------------------------
    def test_b_conditional_use_is_not_a_definition(self):
        log = self.write(
            "b.log",
            "#if defined(CPU_HAS_APPLE_PAC)\n"
            "  clang -DCPU_HAS_APPLE_PAC_NOTE -c x.c\n")
        _code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "b"), "PASS")
        self.assertIn("all uses", out)

    def test_b_define_fails(self):
        log = self.write("b.log", "clang -DCPU_HAS_APPLE_PAC=1 -c x.c\n")
        _code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "b"), "FAIL")

    def test_b_header_define_fails(self):
        log = self.write("b.log", "#define CPU_HAS_APPLE_PAC 1\n")
        _code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "b"), "FAIL")

    # (c) -------------------------------------------------------------
    def test_c_plain_arm64_passes(self):
        k = self.write("kernel", macho(CPU_TYPE_ARM64, 0))
        _code, out = self.run_accept(kernel=k)
        self.assertEqual(self.status(out, "c"), "PASS")
        self.assertIn("arm64", out)

    def test_c_little_endian_arm64_passes(self):
        hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, CPU_TYPE_ARM64, 0,
                          0, 0, 0, 0, 0)
        k = self.write("kernel", hdr)
        _code, out = self.run_accept(kernel=k)
        self.assertEqual(self.status(out, "c"), "PASS")
        self.assertIn("arm64", out)

    def test_c_arm64e_fails(self):
        k = self.write("kernel", macho(CPU_TYPE_ARM64, 0x80000002))
        _code, out = self.run_accept(kernel=k)
        self.assertEqual(self.status(out, "c"), "FAIL")
        self.assertIn("arm64e", out)

    def test_c_pac_capable_subtype_fails(self):
        # CPU_SUBTYPE_ARM64E is 2; the capability bit 0x80000000 is not required
        k = self.write("kernel", macho(CPU_TYPE_ARM64, 2))
        _code, out = self.run_accept(kernel=k)
        self.assertEqual(self.status(out, "c"), "FAIL")

    def test_c_fat_with_two_slices_fails(self):
        slice0 = macho(CPU_TYPE_ARM64, 0)
        slice1 = macho(0x01000007, 3)
        hdr = 8 + 2 * 20
        off0, off1 = hdr, hdr + len(slice0)
        fat = struct.pack(">II", 0xCAFEBABE, 2)
        fat += struct.pack(">IIIII", CPU_TYPE_ARM64, 0, off0, len(slice0), 12)
        fat += struct.pack(">IIIII", 0x01000007, 3, off1, len(slice1), 12)
        k = self.write("kernel", fat + slice0 + slice1)
        _code, out = self.run_accept(kernel=k)
        self.assertEqual(self.status(out, "c"), "FAIL")
        self.assertIn("2 slices", out)

    def test_c_rejects_non_macho(self):
        k = self.write("kernel", b"not a mach-o at all, definitely not\n")
        _code, out = self.run_accept(kernel=k)
        self.assertEqual(self.status(out, "c"), "FAIL")

    # (d) -------------------------------------------------------------
    def test_d_empty_kernel_has_no_pac(self):
        k = self.write("kernel", macho(CPU_TYPE_ARM64, 0))
        _code, out = self.run_accept(kernel=k)
        self.assertEqual(self.status(out, "d"), "PASS")

    # (e) -------------------------------------------------------------
    def test_e_deduplicates_clang_errors(self):
        log = self.write(
            "e.log",
            "x.c:10:2: error: use of undeclared identifier 'A'\n"
            "y.c:20:2: error: use of undeclared identifier 'B'\n"
            "x.c:10:2: error: use of undeclared identifier 'A'\n"
            "make: *** [install] Error 2\n")
        _code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "e"), "FAIL")
        self.assertIn("2 distinct clang error(s)", out)
        self.assertIn("(x2)", out)

    def test_e_clean_log_passes(self):
        log = self.write("e.log", "clang -c foo.c\nfoo done\n")
        _code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "e"), "PASS")

    def test_e_patch_failures_are_listed_separately(self):
        log = self.write(
            "e.log",
            "error: patch failed: osfmk/vm/vm_resident.c:61\n"
            "error: osfmk/vm/vm_resident.c: patch does not apply\n")
        _code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "e"), "PASS")
        self.assertIn("non-clang error lines (2 distinct)", out)

    # (f) -------------------------------------------------------------
    def test_f_unresolved_symbols_fail_build(self):
        log = self.write(
            "f.log",
            "Undefined symbols for architecture arm64:\n"
            "  \"_pmap_bootstrap\", referenced from:\n"
            "ld: symbol(s) not found for architecture arm64\n"
            "clang++: error: linker command failed with exit code 1\n"
            "make[3]: *** [kernel.development.sweet] Error 1\n")
        _code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "f"), "FAIL")
        self.assertIn("Undefined symbols for architecture arm64", out)
        self.assertIn("linker command failed", out)

    def test_f_missing_kernel_is_incomplete(self):
        log = self.write("f.log", "clang -c foo.c\n")
        code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "f"), "SKIPPED")
        self.assertEqual(code, 3)

    # (g) -------------------------------------------------------------
    def test_g_all_patches_applied_pass(self):
        self.write_patch("0001-a.patch", "osfmk/arm64/start.s", ["\tmov x0, #1"])
        self.write_patch("0002-b.patch", "osfmk/arm64/proc_reg.h", ["#define X 1"])
        log = self.write(
            "g.log",
            "\x1b[35;01m ? \x1b[39;49;00mApplying patch:"
            " /w/dxb/patches/26.0/0001-a.patch\n"
            "\x1b[35;01m ? \x1b[39;49;00mApplying patch:"
            " /w/dxb/patches/26.0/0002-b.patch\n")
        code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "g"), "PASS")
        self.assertIn("all 2 patches applied", out)

    def test_g_skipped_patch_fails_like_run18(self):
        self.write_patch("0016-c.patch", "osfmk/arm64/start.s",
                         ["\tSWEET_FB_MARK 512, 0x00ff, 0xffff"])
        log = self.write(
            "g.log",
            "\x1b[33;01m[warning] \x1b[39;49;00mSkipping patch"
            " /w/dxb/patches/26.0/0016-c.patch (already upstream, previously"
            " applied, or malformed): error: patch failed: osfmk/arm64/start.s:651\n")
        code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "g"), "FAIL")
        self.assertIn("0016-c.patch SKIPPED", out)
        self.assertEqual(code, 1)

    def test_g_patch_absent_from_log_fails(self):
        self.write_patch("0003-d.patch", "osfmk/arm64/start.s", ["\tnop"])
        log = self.write("g.log",
                         "Applying patch: /w/dxb/patches/26.0/0001-a.patch\n")
        _code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "g"), "FAIL")
        self.assertIn("no 'Applying patch' line", out)

    def test_g_ignores_patches_of_the_build_driver(self):
        self.write_patch("0001-a.patch", "osfmk/arm64/start.s", ["\tnop"])
        log = self.write(
            "g.log",
            "Applying patch: /w/dxb/patches/26.0/0001-a.patch\n"
            "[warning] Skipping patch /w/dxb/patches/26.0/link_kdk.patch"
            " (already upstream, previously applied, or malformed): error:"
            " patch failed: makedefs/MakeInc.def:1095\n")
        _code, out = self.run_accept(log=log)
        self.assertEqual(self.status(out, "g"), "PASS")

    # (h) -------------------------------------------------------------
    def make_tree(self, files):
        import io
        import tarfile
        p = self.path("buildtree.tgz")
        with tarfile.open(p, "w:gz") as tar:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return p

    def test_h_added_lines_present_in_tree(self):
        self.write_patch("0016-c.patch", "osfmk/arm64/start.s",
                         ["\tSWEET_FB_MARK 512, 0x00ff, 0xffff"])
        tree = self.make_tree(
            {"xnu/osfmk/arm64/start.s":
             "common_start:\n\tSWEET_FB_MARK 512, 0x00ff, 0xffff\n"})
        _code, out = self.run_accept(tree=tree)
        self.assertEqual(self.status(out, "h"), "PASS")

    def test_h_catches_patch_that_never_landed(self):
        self.write_patch("0016-c.patch", "osfmk/arm64/start.s",
                         ["\tSWEET_FB_MARK 512, 0x00ff, 0xffff"])
        tree = self.make_tree({"xnu/osfmk/arm64/start.s": "common_start:\n\tnop\n"})
        _code, out = self.run_accept(tree=tree)
        self.assertEqual(self.status(out, "h"), "FAIL")
        self.assertIn("SWEET_FB_MARK 512", out)

    def test_h_missing_target_file_fails(self):
        self.write_patch("0016-c.patch", "osfmk/arm64/start.s",
                         ["\tSWEET_FB_MARK 512, 0x00ff, 0xffff"])
        tree = self.make_tree({"xnu/other.c": "int x;\n"})
        _code, out = self.run_accept(tree=tree)
        self.assertEqual(self.status(out, "h"), "FAIL")
        self.assertIn("missing from the tree", out)

    # partial input -----------------------------------------------------
    def test_missing_kernel_is_incomplete_not_pass(self):
        log = self.write("a.log", "clang -arch arm64 -c foo.c\n")
        code, out = self.run_accept(log=log)
        self.assertEqual(code, 3)
        self.assertEqual(self.status(out, "c"), "SKIPPED")
        self.assertIn("INCOMPLETE", out)

    def test_json_report(self):
        log = self.write("a.log", "clang -arch arm64e -c foo.c\n")
        k = self.write("kernel", macho(CPU_TYPE_ARM64, 0))
        j = self.path("r.json")
        cmd = [sys.executable, ACCEPT, "--log", log, "--kernel", k, "--json", j]
        subprocess.run(cmd, capture_output=True, text=True)
        import json
        with open(j, encoding="utf-8") as f:
            r = json.load(f)
        self.assertEqual(r["criteria"]["a"]["status"], "fail")
        self.assertEqual(r["criteria"]["c"]["status"], "pass")
        self.assertEqual(r["flags"]["-arch arm64e"], 1)
        self.assertEqual(r["exit_code"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

