# P0: SWEET machine config для `xnu-12377.121.6`

База: публічний тег **`xnu-12377.121.6`** (`apple-oss-distributions/xnu`,
`git describe` → `xnu-12377.121.6`, HEAD `ac9718f`).

Статус: **P0/P1-компіляційні фікси, збірка ще не завершена.** Перший реальний
прогін CI (run `44195811557`, XNU 12377.121.6, `DEVELOPMENT ARM64 SWEET`)
показав рівно дві помилки компіляції; обидві закриті патчами 0005 і 0006.
Локально немає macOS SDK i KDK, тому перевірено лише: патчі чисто накладаються
на незайманий тег у заданому порядку (див. «Перевірка» нижче).

Джерело змісту: `ios-guacamole/xnu/patches/0004-sweet-machine-config.patch`
(8796, той самий SoC-клас), перенесено лише **не-PAC** частину. PAC-hunks
(`sleh.c` trap, `start.s`) свідомо не беремо: у 12377 вони або вже є, або
належать P2.

---

## Патчі

| # | файл | що робить |
|---|---|---|
| 0001 | `makedefs/MakeInc.def` | додає `SWEET` у `SUPPORTED_ARM64_MACHINE_CONFIGS`; `MACHINE_FLAGS_ARM64_SWEET = -DARM64_BOARD_CONFIG_SWEET -march=armv8.2-a+crypto`; для `CURRENT_MACHINE_CONFIG=SWEET` **не** підміняє `ARCH_STRING_FOR_CURRENT_MACHINE_CONFIG` на `arm64e` |
| 0002 | `pexpert/pexpert/arm64/SWEET.h` (новий) + `pexpert/pexpert/arm64/Makefile` | board-заголовок guacamole: `NO_MONITOR`, `NO_ECORE`, 16K pages, GICv3, INTID відрахування Qualcomm (vtimer = 19), регістри GICv3; **без** `CPU_HAS_APPLE_PAC` |
| 0003 | `pexpert/pexpert/arm64/board_config.h` | `#ifdef ARM64_BOARD_CONFIG_SWEET` → include `SWEET.h`, `MAX_L2_CLINE 6`, `MAX_CPUS 8`, `MAX_CPU_CLUSTERS 2`, `CORE_NCTRS 8`, `NO_XNU_PLATFORM_ERROR_HANDLER 1` |
| 0004 | `osfmk/arm64/proc_reg.h` | `#elif defined (SWEET)` → `MMU_I_CLINE 6`, `MMU_CLINE 6` |
| 0005 | `pexpert/arm/pe_fiq.c` | для `SWEET` конфігурує GIC **Group 1 NS** (IGROUPR0=all-1, пріоритети, vtimer INTID 19 + SGI1, `ICC_BPR1_EL1`, `ARE_NS\|EnableGrp1A\|EnableGrp1`, `ICC_IGRPEN1_EL1`); Apple-гілка з `GICD_CTLR_ENABLEGRP0` лишається під `#else`. Прибирає `use of undeclared identifier 'GICD_CTLR_ENABLEGRP0'` і одночасно runtime-блокер: Group 0 належить TrustZone |
| 0006 | `pexpert/pexpert/arm64/SWEET.h` + `osfmk/arm64/cpc_arm64.c` | дає `CPMU_PMC_COUNT 10` та нулі для решти CPMU-фіч (структури CPC існують, нічого не програмується) і виставляє `cpc_cpmu_supported = false` для `SWEET`. Прибирає `use of undeclared identifier 'CPMU_PMC_COUNT'`: у 12377 `CONFIG_CPU_COUNTERS` увімкнено завжди, а CPMU-константи є лише в Apple-заголовках `H1x.h` |
| 0007 | `pexpert/pexpert/arm64/apple_arm64_cpu.h` | включає `apple_arm64_regs.h` перед `arm64_core_type()`. Без нього `MPIDR_CORETYPE_*` невидимі в `osfmk/arm/machine_routines_common.c`, `osfmk/arm64/pcb.c` і `sleh.c`: на Apple-конфігах їх приносить `apple_arm64_common.h` через `board_config.h`, а SWEET його не включає |
| 0008 | `makedefs/MakeInc.def` | вимикає примусове лінкування `$(KDKROOT)/System/Library/KernelSupport/libSWEET.os.DEVELOPMENT.a` для `SWEET` (`ifeq ($(filter NONE SWEET,$(CURRENT_MACHINE_CONFIG)),)`). У KDK Apple є такі архіви лише для Apple SoC (T6000, T8103 тощо); для кастомних платформ (як і для `SHENG` у пріор-арті akita) вони відсутні |

Порядок застосування — саме 0001 → 0008.

### Чому саме так

- **[перевірено]** `apple_arm64_common.h:76`: `HAS_APPLE_PAC` визначається лише
  при `defined(CPU_HAS_APPLE_PAC) && defined(__arm64e__)`. `SWEET.h` не задає
  `CPU_HAS_APPLE_PAC`, а `ARCH_STRING…=arm64` прибирає `__arm64e__` → усе ядро
  збирається без PAC.
- **[перевірено]** `osfmk/arm64/platform_error_handler.c:26` містить
  `#error XNU_PLATFORM_ERROR_HANDLER is not defined in board_config.h`, якщо
  `NO_XNU_PLATFORM_ERROR_HANDLER` не визначений. Тому він обов'язковий, а не
  «як у VMAPPLE».
- **[перевірено]** `pexpert/arm/pe_fiq.c:15` компілює GICv3-гілку під
  `#if HAS_GIC_V3`; `SWEET.h` його задає.
- **[перевірено]** `board_config.h` для `MAX_CPU_CLUSTERS != 1` **не** визначає
  `__ARM_AMP__` (він визначається лише в `H1x.h`), тому 2 кластери безпечні:
  гетерогенних кешів у нас немає.
- **[перевірено]** `MACHINE_FLAGS_ARM64_SWEET` не задає `-mcpu`: `-march=armv8.2-a+crypto`
  — це рівень A76/A55 (і прибирає Apple-специфічні інструкції).

### Що з 8796-патча **не** перенесено

- `osfmk/arm64/start.s` (`#if !VMAPPLE && !defined(SWEET)`): **[перевірено]** у
  12377 цей блок — `MOV64 x0, DEFAULT; MSR; MOV64 x1, DEFAULT; cmp x0,x1; bne .`,
  тобто порівняння двох однакових констант (macro `MSR_SCTLR_EL1_X0` не
  переписує `x0`). Це мертвий код і в 8796 (`xnu-8796.101.5`,
  `start.s:743-750`). На boot не впливає — не включаємо.
- `osfmk/arm64/sleh.c`, `pexpert/arm/pe_fiq.c` (GIC Group 1 / vtimer INTID 19):
  це **runtime**-блокер (TrustZone володіє Group 0), не компіляційний.
  У 12377 `pe_fiq.c` ідентичний 8796, тому переноситься 1:1 — це перший патч
  P3 (див. `docs/stage2-xnu12377.md` §5).

  **Оновлено після run 44195811557:** GIC-гілка в `pe_fiq.c` компілюється вже
  зараз, бо `SWEET.h` задає `HAS_GIC_V3 1`. Тому перенос став обов'язковим
  P0-фіксом — патч 0005.

## Фактичні помилки першої збірки

Run `44195811557` (`macos-15-intel`, Xcode 26.3.0, SDK 26.2, 17m14s) дав
лише дві причини падіння (решта — очікувані warning'и DXB):

```text
pexpert/arm/pe_fiq.c:167:15: error: use of undeclared identifier 'GICD_CTLR_ENABLEGRP0'
osfmk/arm64/cpc_arm64.h:48:27: error: use of undeclared identifier 'CPMU_PMC_COUNT'; did you mean 'CPC_HW_COUNT'?
osfmk/arm64/cpc_arm64.h:122:39: same
osfmk/arm64/cpc_arm64.h:123:42: same
```

`link_kdk.patch` / `remove_applefeatures_include.patch` DXB пропускає з
warning'ом — це не причина падіння.

## Фактичні помилки другої збірки (run 44271872336)

Крок Build у GitHub показав **зелений ✓**, але ядра в артефакті немає:
`bash build.sh 2>&1 | tee build.log` виконувався без `set -o pipefail`, тому
статус повертав `tee`, а не `build.sh`. У `build.log` (727 MB) —

```text
make[2]: Target `build_all' not remade because of errors.
make[1]: *** [build_all_bootstrap_DEVELOPMENT^ARM64^SWEET] Error 2
make: *** [install] Error 2
```

Єдина причина — `MPIDR_CORETYPE_*` у `pexpert/pexpert/arm64/apple_arm64_cpu.h`
(рядки 40–42, 54), які приходять із `apple_arm64_regs.h`. На Apple-конфігах
цей заголовок уже включений через `apple_arm64_common.h` → `board_config.h`,
а SWEET включає лише свій `SWEET.h`. Ламалися `osfmk/arm/machine_routines_common.c`
і `osfmk/arm64/pcb.c` (по два входження кожного ідентифікатора). Патч 0007
включає `apple_arm64_regs.h` безпосередньо в `apple_arm64_cpu.h`.

Workflow тепер має `set -o pipefail` і падає, якщо `kernel.development.*`
не з'явився, — «зелений без ядра» більше неможливий.

## Фактичні помилки третьої збірки (run 44278053892)

Run `44278053892` (`macos-15-intel`, Xcode 26.3.0, SDK 26.2, 28m27s) у `RubenSavytskyi/guacamole-xnu`:
завдяки `pipefail` помилка виявлена коректно (exit code 2).
Усі 8 компонентів ядра (`osfmk`, `bsd`, `libkern`, `iokit`, `pexpert`, `libsa`, `security`, `san`)
успішно скомпільовані без жодної C/C++ помилки (патч 0007 повністю закрив проблему з `MPIDR_CORETYPE_*`).
Генерація `link.filelist` пройшла успішно.
Збірка дійшла до фінального лінкування `kernel.development.sweet.unstripped.noctf`.

Єдина помилка логу:
```text
ld: library '/Library/Developer/KDKs/KDK_26.5_25F71.kdk//System/Library/KernelSupport/libSWEET.os.DEVELOPMENT.a' not found
clang++: error: linker command failed with exit code 1 (use -v to see invocation)
make[3]: *** [/Users/runner/work/guacamole-xnu/guacamole-xnu/dxb/build/xnu.obj/DEVELOPMENT_ARM64_SWEET//kernel.development.sweet.unstripped.noctf] Error 1
```

Причина: `makedefs/MakeInc.def:1154` безумовно додає `-Wl,-force_load,$(KDKROOT)/System/Library/KernelSupport/lib$(CURRENT_MACHINE_CONFIG).os.$(CURRENT_KERNEL_CONFIG).a`
для будь-якого `CURRENT_MACHINE_CONFIG != NONE`. Apple KDK не має бінарної бібліотеки підтримки для `SWEET`.
У пріор-арті akita (`macos-pixel8a`) для `SHENG` зроблено виняток `ifeq ($(filter NONE SHENG,$(CURRENT_MACHINE_CONFIG)),)`.
Патч 0008 додає `SWEET` до цього винятку (`ifeq ($(filter NONE SWEET,$(CURRENT_MACHINE_CONFIG)),)`).

---

## Як збирати

Скрипт: `blacktop/darwin-xnu-build` (той самий, що в
`ios-guacamole/.github/workflows/xnu.yml`; для 26.5 потрібен **найновіший**
Xcode/SDK 26.x, а не найстаріший, як зараз у workflow).

```bash
# у дереві xnu-12377.121.6, після застосування 0001..0008
git apply /path/to/0001-makeinc-sweet-machine-config.patch
git apply /path/to/0002-sweet-board-header.patch
git apply /path/to/0003-sweet-board-config.patch
git apply /path/to/0004-sweet-cache-geometry.patch
git apply /path/to/0005-sweet-gic-group1.patch
git apply /path/to/0006-sweet-no-cpmu.patch
git apply /path/to/0007-sweet-mpidr-coretype-include.patch
git apply /path/to/0008-sweet-no-kdk-kernelsupport.patch

# те, що робить build.sh всередині:
MACOS_VERSION=26.5 \
KERNEL_CONFIG=DEVELOPMENT \
MACHINE_CONFIG=SWEET \
bash build.sh
```

Очікуваний продукт: `kernel.development.sweet` (ARCH_STRING = `arm64`).
`-arch arm64e` у логах бути **не повинно** — це перша перевірка після збірки:

```bash
lipo -info build/obj/kernel.development.sweet   # очікуємо: arm64
```

`BTI_BUILD=1` (типово в `MakeInc.def`) додає `-DXNU_BUILT_WITH_BTI`; `BTI` —
інструкції з HINT-простору, на A76/A55 це NOP, тому лишаємо.

---

## Припущення, які перевіряються тільки на залізі

- `MAX_CPU_CLUSTERS 2` (4x A76 = кластер 0, 4x A55 = кластер 1, MPIDR Aff1 = 0/1).
  У 8796-порту стояло `1`; у 12377 `__ARM_AMP__` усе одно не визначається
  (він визначається лише в `H1x.h`), тому різниця — тільки в `MAX_CPU_CLUSTER_PHY_ID`.
  Якщо на boot буде «wrong cluster»/втрачені CPU — повернути `1`.
- `ICC_CTLR_EOIMODE = 0x2` (біт 1, як у GICv3 spec і Linux), а не `0x1`, як у
  `VMAPPLE.h`. 8796-порт sweet використовував `0x2` і працював на реальному
  залізі.
- `GICR_PE_SIZE 0x20000` (redistributor на кожне PE, GICv3 без VLPI) — як у
  VMAPPLE; для SM8150 це коректно, але підтверджується лише `pe_init_fiq()` на
  пристрої.
- `__ARM_16K_PG__`: 16K-сторінки потрібні, щоб збігтися з userland/DSC; на
  guacamole це вже перевірено 8796/ios27-портами.

## Перевірка

```bash
cd xnu-12377.121.6            # чистий тег
git status --short            # порожньо
for f in 000{1,2,3,4,5,6,7}-*.patch; do git apply --check "$f" && git apply "$f"; done
git status --short
#  M makedefs/MakeInc.def
#  M osfmk/arm64/cpc_arm64.c
#  M osfmk/arm64/proc_reg.h
#  M pexpert/arm/pe_fiq.c
#  M pexpert/pexpert/arm64/Makefile
#  M pexpert/pexpert/arm64/apple_arm64_cpu.h
#  M pexpert/pexpert/arm64/board_config.h
# ?? pexpert/pexpert/arm64/SWEET.h
git checkout -- . && git clean -fd     # повернути дерево в тег
```

Результат на 2026-11-17/18: усі сім пройшли `git apply --check` і наклалися
саме з таким `git status`. Після цього дерево повернуто до `ac9718f`
(працюємо з патчами, а не зі зміненим деревом).

Додатково (не компіляція, але й не «на віру»): після накладання патчів
`board_config.h` + `proc_reg.h` препроцесуються для `aarch64` з
`-DARM64_BOARD_CONFIG_SWEET -DKERNEL_PRIVATE=1` і статичними перевірками
`SWEET`, `MAX_CPUS == 8`, `MAX_CPU_CLUSTERS == 2`, `MAX_L2_CLINE == 6`,
`MMU_CLINE == MMU_I_CLINE == 6`, `NO_XNU_PLATFORM_ERROR_HANDLER` визначений,
`CPU_HAS_APPLE_PAC` **не** визначений — усе проходить. Це ловить помилки в
самому board-заголовку, але нічого не каже про решту ядра.

## Чого ще немає (і чому)

- **Компіляції.** Перша збірка (run `44195811557`) дала дві помилки, обидві
  закриті (0005, 0006). Чи цим список вичерпано — покаже наступний прогін; нові
  помилки з логу стануть `0007+`, наперед нічого не додаємо.
- **P1** (grading `arm64e`, slide v3/v5, `vm_dyld_pager`, `max_slide`,
  опційний `ptrauth_disabled`) — див. `docs/stage2-xnu12377.md` §3, §3.1, §5;
  це окремі патчі, не частина P0.
- **P3** (framebuffer/UFS/PMIC/USB/touch, GIC Group 1) — порт з 8796/ios27,
  по одному патчу на підсистему.
