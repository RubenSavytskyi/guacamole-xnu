# guacamole-xnu

Patches and CI for building **XNU 12377.121.6** for macOS Tahoe (26.5) on the
OnePlus 7 Pro (`guacamole`, Qualcomm SM8150 / Snapdragon 855) as **plain
arm64** â€” no pointer authentication, no Apple SoC headers.

This repository contains only the kernel-side work: machine-config patches,
the build workflow, and the PAC/DSC analysis tools used to check the result.
The userland, shim, installer and the full project handoff live in the
umbrella repository (`ios-guacamole` on the same account).

## Why

macOS 26 ships arm64e only, and arm64e assumes `FEAT_PAuth`. Kryo 485
(Cortex-A76/A55, ARMv8.2-A) has no PAC, so the kernel must be built as arm64
and userland is rewritten statically (or emulated) separately. `SWEET.h`
deliberately does not define `CPU_HAS_APPLE_PAC`; combined with
`-arch arm64` this leaves `HAS_APPLE_PAC` undefined (`apple_arm64_common.h`)
and the whole kernel compiles without pointer authentication.

## Layout

```
patches/   0001..0016 applied in order; 0015 adds pre-MMU and 0016 adds post-MMU framebuffer diagnostics
ci/        pac_count.py, dsc_hist.py, their tests and rule tables
.github/   tahoe-xnu.yml: pinned darwin-xnu-build (DXB) + macos-15-intel
```

### Patches

| # | file | what it does |
|---|---|---|
| 0001 | `makedefs/MakeInc.def` | registers `SWEET` in `SUPPORTED_ARM64_MACHINE_CONFIGS`, sets `-march=armv8.2-a+crypto`, keeps `ARCH_STRING` at `arm64` |
| 0002 | `pexpert/pexpert/arm64/SWEET.h` + `Makefile` | board header: no `CPU_HAS_APPLE_PAC`, `NO_MONITOR`, `NO_ECORE`, 16K pages, GICv3, vtimer INTID 19 |
| 0003 | `pexpert/pexpert/arm64/board_config.h` | `ARM64_BOARD_CONFIG_SWEET`: `MAX_L2_CLINE 6`, `MAX_CPUS 8`, `MAX_CPU_CLUSTERS 2`, `NO_XNU_PLATFORM_ERROR_HANDLER` |
| 0004 | `osfmk/arm64/proc_reg.h` | `MMU_I_CLINE`/`MMU_CLINE` = 6 for SWEET |
| 0005 | `pexpert/arm/pe_fiq.c` | GIC **Group 1 NS** for SWEET: Group 0 belongs to TrustZone, so the vtimer and IPIs would never arrive otherwise |
| 0006 | `SWEET.h` + `osfmk/arm64/cpc_arm64.c` | supplies `CPMU_PMC_COUNT` and marks the Apple CPMU unsupported: SM8150 has an ARM PMU, not Apple's |
| 0007 | `apple_arm64_cpu.h` | directly includes `apple_arm64_regs.h` for `MPIDR_CORETYPE_*` |
| 0008 | `makedefs/MakeInc.def` | skips the absent Apple KDK `libSWEET` archive |
| 0009 | `config/MASTER.arm64.MacOSX` | selects generic ARM64 `nos_arm_pmap` and `nos_arm_asm` sources for SWEET |
| 0010 | `osfmk/arm/pmap/pmap.c`, `osfmk/arm64/start.s` | guards Apple private PPL/tunables files for SWEET |
| 0011 | `osfmk/arm/pmap/pmap.c` | removes PPL-only calls from the non-monitor path |
| 0012 | `config/MASTER`, `osfmk/conf/files.arm64` | excludes Apple AMCC sources absent from public XNU and Qualcomm hardware |
| 0013 | arm64 runtime sources | supplies non-Apple fallbacks and skips arm64e-only Tightbeam startup on SWEET |
| 0014 | `config/Makefile`, `config/Private.SWEET.exports` | excludes Apple/KDK exports and export checks for SWEET; provides an empty SWEET private symbol list for plist generation |
| 0015 | `osfmk/arm64/start.s` | paints four 32-by-32 framebuffer blocks at `_start`, `start_first_cpu`, after bootstrap table setup, and before MMU enable; compiled in run 17 |
| 0016 | `osfmk/arm64/start.s` | maps the 32 MB framebuffer block in the early V=P table and paints post-MMU and post-SCTLR-check markers; LF-normalized and queued in run 19 |

Run `44400572741` linked down to five missing symbols; patch 0013 adds the
non-Apple runtime paths. Run `44406649506` produced a kernel artifact but failed
in the Apple export checks; the acceptance report counted 10 non-hint PAC
instructions and its Mach-O check did not recognize the little-endian header.
Patch 0014 excludes the Apple/KDK export inputs from SWEET and supplies an empty
private export list. Run `44414383264` then failed while generating
`Private.symbolset.plist` because that list had no input file; patch 0014 now
includes `Private.SWEET.exports`. See [`patches/README.md`](patches/README.md)
for the build history.

Details, rationale and the exact compiler errors that produced 0005/0006 are
in [`patches/README.md`](patches/README.md).

## Build

The workflow is manual + on push to `patches/**`. It:

1. runs the tool unit tests (`ci/test_pac_count.py`, `ci/test_dsc_hist.py`);
2. fetches the pinned `darwin-xnu-build` commit and copies `patches/*.patch`
   into `dxb/patches/26.0` (the driver has no `patches/26.5`);
3. picks an explicit non-beta Xcode 26.x and refuses to continue unless the
   macOS SDK starts with `26`;
4. builds `DEVELOPMENT ARM64 SWEET` with `make -k`, tees `build.log`;
5. uploads `xnu-buildtree` (object tree, `build.log`, SDK platform headers)
   plus the kernel and `pac-count.json` when a kernel was produced.

## Acceptance criteria (enforced by CI)

| # | criterion |
|---|---|
| a | no `-fptrauth`, `-mbranch-protection`, `+pauth`; `-arch arm64e` only where unavoidable (KDK host-side tools), never for kernel sources |
| b | `CPU_HAS_APPLE_PAC` is defined nowhere |
| c | `lipo -info kernel.development.sweet` reports `arm64` |
| d | zero non-hint PAC instructions in the kernel (`ci/pac_count.py`), otherwise the list of functions |
| e | no compiler errors |
| f | a kernel artifact exists and the build has no linker or make failures |

## Status (2026-11-19)

- Run `44521215540`: kernel artifact is 24,879,760 bytes, `arm64`, SHA-256 `a32b89d60bed7deccf4d465be34340fda67ee68cfe0206e0dcc47e49dd9ff8d1`; PAC count is 0 non-hint instructions.
- Run `44521215540`: `libfirehose_kernel` was built for `x86_64 arm64`; no `arm64e` target or kernel link-command reference to `liblibfirehose_kernel.a` was present.
- Run `44520878510`: unit-test failure exposed that the DSC fast counter still used the old PAC-key match; fixed in `ci/dsc_hist.py` and confirmed by the successful run above.
- Patches `0001..0014` passed ordered `git apply --check` on clean XNU commit `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`; run 17 built the kernel with patch `0015` applied.
- Run `44546255336` (run 17): kernel artifact is 24,880,032 bytes, `arm64`, SHA-256 `19a14fe5d19ed0b1a6782924f073a08183ea64ae47395b3c5ff6574deada0bb2`; all acceptance criteria passed and PAC count is 0.
- Run `44563569996` (run 18): kernel artifact is 24,880,032 bytes, `arm64`, SHA-256 `ed8bf394297983c86da5a29c1ee765c6f3aa6bc3fd1f8b267a996f862480aae0`; PAC count is 0, but `build.log` reports patch 0016 did not apply, so this artifact lacks the post-MMU markers.
- Run `44546255336` produced four early framebuffer checkpoints. Device test of `tahoe-firstboot-0015.img` showed blue, yellow and white markers; execution past the pre-MMU checkpoint is not confirmed.
- Run `44521215540` device test: shim printed `JUMP`; display stayed red. XNU execution past the handoff was not confirmed. That image did not contain patch `0015`.
- The run 17 kernel was wrapped locally as `tahoe-firstboot-0015.img` with the existing D22 ADT and shim. It has not been tested on-device.

No Apple binaries, IPSWs, KDKs or device dumps belong in this repository.

## iOS 27 P3 comparison and shim format audit

These are source-level audits only. No device boot was performed as part of
these checks.

### iOS 27 platform diffs

Compared the public `coreycusick/ios-guacamole` `ios27` XNU diffs with the
clean XNU base plus SWEET patches `0001..0014`. The diffs are incremental
changes against that project's SWEET/iOS 27 platform tree; they are not a
standalone patch series for clean XNU. The checked paths below are absent from
our current tree, so the diffs cannot be applied directly here. This is a
missing-base dependency, not evidence that the corresponding implementation
conflicts with a same-purpose patch in `0001..0014`.

| Area | iOS 27 source found | Directly applies to `0001..0014` | Relevant local patch/conflict |
|---|---|---|---|
| UART | No dedicated UART bring-up diff; `fb-hwscale` also changes serial-console code | No; its SWEET platform context is absent | None identified |
| Framebuffer | `xnu12377-fb-*.diff`, against `SweetFramebuffer.cpp` | No; `SweetFramebuffer.cpp` is absent | None identified |
| UFS | `xnu12377-disk0-nub.diff`; creates a disk0 media nub, expects the platform UFS driver | No; required SWEET files/context are absent | None identified |
| Touch | No touch-specific XNU diff found in `xnu/ios27` | N/A | None identified |
| PMIC | No PMIC-specific diff found; `psci-power.diff` concerns RTC/power startup | No; its SWEET RTC files/context are absent | None identified |
| Battery | No battery-specific XNU diff found | N/A | None identified |
| GPU | `xnu12377-gpu-*.diff`, against `SweetAccelerator.cpp` / `sweet_gpu.c` | No; those platform files are absent | None identified |

The iOS 27 repository has no root `LICENSE` file and its GitHub license
endpoint reports no detected license. Preserve Corey Cusick's attribution for
the audited diffs and check the origin/license of any copied component before
porting it; this audit does not establish a blanket license for the diff set.
The iOS 27 P3 tree is a useful same-device platform reference, but these
incremental diffs should not be bulk-applied to Tahoe or treated as a drop-in
replacement for the approximately 240-patch 8796 port.

### Mach-O to shim payload

The input was the artifact from run `44521215540`, parsed with
`ios-guacamole/tools/mkpayload.py`'s `parse_macho` and compared with its
`build()` implementation. `otool` is not installed in the Windows audit
environment, so this is a parser-based inspection rather than an `otool -l`
transcript.

| Check | Kernel result | Shim requirement/result |
|---|---|---|
| Mach-O | 64-bit little-endian, `MH_EXECUTE`, CPU type `arm64` (`0x0100000c`), subtype 0 | Parser accepts 64-bit Mach-O; no arm64e-only requirement |
| Entry | `LC_UNIXTHREAD` PC `0xfffffe0007572488`, inside `__TEXT_EXEC` | Used as `entry_va` in the payload header |
| Segments | 19 `LC_SEGMENT_64` commands; first is `__TEXT`, `fileoff=0` | Satisfies `build()`'s first-text-segment check |
| 16 KB granule | Non-empty segments have 16 KB-aligned `vmaddr`, `vmsize` and `fileoff` | Compatible with the shim's 16 KB page constant; file byte count need not be page-aligned (`__LINKEDIT` is not) |
| Chained fixups | No `LC_DYLD_CHAINED_FIXUPS` command | `apply_chained_fixups()` returns zero; no fixup rewrite is needed |
| Payload | The artifact starts with Mach-O magic, not `SWEETXNU` | It is a raw kernel; `mkpayload.py` must wrap it with a matching ADT before the shim can load it |

No ADT (`.adt`/`.dtb`) or wrapped payload was found in the workspace during
this audit. The raw kernel therefore has not yet been prepared for a device
boot. `fastboot boot` remains a user-run hardware check after the payload and
matching ADT are available.
