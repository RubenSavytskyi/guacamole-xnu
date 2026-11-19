# guacamole-xnu

Patches and CI for building **XNU 12377.121.6** for macOS Tahoe (26.5) on the
OnePlus 7 Pro (`guacamole`, Qualcomm SM8150 / Snapdragon 855) as **plain
arm64** — no pointer authentication, no Apple SoC headers.

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
patches/   0001..0014, applied in order to the clean xnu-12377.121.6 tag
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

- Run `44431047165`: XNU build succeeded and produced a 24,879,760-byte kernel. CI reported `lipo -info: arm64`. Its PAC report initially showed 10 false positives because `ci/pac_count.py` matched TCR/TTBR system-register accesses as PAC-key registers. Re-analysis with the corrected classifier reports 0 non-hint PAC instructions.
- Run `44431047165`: build log shows `libfirehose_kernel` targeted `x86_64 arm64`; no kernel link command references `liblibfirehose_kernel.a`.
- Patches `0001..0014` passed ordered `git apply --check` on clean XNU commit `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`.
- The workflow now runs on `ci/**` changes and fails if an acceptance criterion fails. A fresh CI run is pending the PAC-counter fix.

No Apple binaries, IPSWs, KDKs or device dumps belong in this repository.

