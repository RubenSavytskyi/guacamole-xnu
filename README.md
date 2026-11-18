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
patches/   0001..0008, applied in order to the clean xnu-12377.121.6 tag
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

The latest build reached final linking but failed with 241 groups of undefined
symbols because generic ARM64 XNU sources were not selected for SWEET. Patch
0009 adds those selectors to `KERNEL_BASE` for SWEET. Run 44377642599 then exposed
two Apple-only headers missing from the public XNU drop; 0010 gates those paths
for non-Apple SWEET hardware. The next CI build must verify compilation and
linking. See `patches/README.md` for details.

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

## Acceptance criteria (checked separately, from the log)

| # | criterion |
|---|---|
| a | no `-fptrauth`, `-mbranch-protection`, `+pauth`; `-arch arm64e` only where unavoidable (KDK host-side tools), never for kernel sources |
| b | `CPU_HAS_APPLE_PAC` is defined nowhere |
| c | `lipo -info kernel.development.sweet` reports `arm64` |
| d | zero non-hint PAC instructions in the kernel (`ci/pac_count.py`), otherwise the list of functions |
| e | the complete list of compile errors, from a `-k` run |

## Status (2026-11-18)

- **No kernel has been produced yet.** Two compile errors from the first real
  build (run `44195811557`) are fixed by 0005/0006; the next run decides
  whether the list is exhausted.
- `ci/dsc_hist.py` has been run against the real macOS 26.5 dyld shared cache:
  3,529 images, 2,860,830,300 bytes of `__text`, 23,086,877 non-hint PAC
  instructions + 11,090,781 hint ones. Only 22 `LDRAA` exist, so a 1:1 rewrite
  covers almost all of them. Result: `ci/dsc-26.5.json`.

No Apple binaries, IPSWs, KDKs or device dumps belong in this repository.

