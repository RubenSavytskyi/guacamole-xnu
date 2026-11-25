# Аудит: `coreycusick/ios-guacamole@macos27` проти `guacamole-xnu`

Дата: 2026-11-25. Гілка Corey: `macos27`, HEAD `daea11d` (2026-11-23).
Наш репозиторій: `main`, 26 патчів.

## Короткий висновок

Corey's tree — функціональний суперсет нашого: той самий тег XNU, той самий
SoC, plain arm64, і він доходить до робочого стола macOS. Але **його репозиторій
не збирається з нуля**: серія патчів — це послідовні знімки його приватного
дерева `work/xnu-12377`, якого в git немає. Тому «взяти його ядро і запустити»
можна лише в одному з двох випадків:

1. отримати від нього повний diff дерева (або готовий kernel);
2. повторити forward-port платформи самостійно.

Скопіювати `xnu/patches` + `xnu/macos27` і зібрати — не вийде (доведено нижче).

## Що перевірено

| Факт | Значення |
|---|---|
| XNU | `xnu-12377.121.6` (`ac9718f`), Darwin 25.5.0 — **ядро Tahoe 26.5**, не macOS 27 |
| Corey patches | `xnu/patches` 217 `.patch` (78 `sweet-*`, 136 `guacamole-*`, 3 build/compat) + 3 staging `.sh` |
| Corey macOS | `xnu/macos27` 25 `.patch` + `MASTER.arm64.sweet.MacOSX` |
| Corey iOS 27 | `xnu/ios27` 57 `.diff` + 2 `.patch` |
| Вже у нас | `ios-guacamole/xnu/patches` містить 211 файлів; **209 байт-у-байт ідентичні** Corey |
| Розбіжність | у нас зайві `0157-touch-bitbang`, `0257-touch-sense-order`; немає 8: `0167`, `0258`–`0266` |
| Застосовність | з 211 патчів на чистий тег накладаються **20**, падають **191** |
| Сумісність з нашими 26 | ті самі **20** накладаються поверх нашої серії без конфліктів |

### Доказ, що база приватна

`0003-sweet-framebuffer-serial-console.patch` очікує blob `pexpert/arm/pe_serial.c`
=`997a4ab`. У публічному тегу — `032d9e0`. Перевірено всі теги 12377
(`.1.9`, `.41.6`, `.61.12`, `.81.4`, `.101.15`, `.121.6`): усі мають `032d9e0`.
Контекст патча також інший: у ньому після `register_serial_functions()` одразу
`#if HIBERNATION`, а в Apple — `irq_initialized()`.

Сам Corey це підтверджує у `xnu/ios27/README.md`:

> The iOS 27.2 kernel is built from `work/xnu-12377` … **which is not in this
> repository**. These are the individual changes … they apply in the order the
> work was done … **not to a clean xnu tree**.

У репозиторії немає ні releases, ні CI-артефактів для 12377 (його workflow
`xnu.yml` досі збирає `macos_version: 13.5` → xnu-8796).

## Що з цього реально можна взяти

### 1. Вже ідентичне (209 патчів)

Нічого нового не дає. Наші 26 — це підмножина його `sweet-*` (0001–0081):
machine config, GIC Group 1, CPMU, MASTER, bootstrap, physmap padding
(наш `0023` == його `0011`, байт-у-байт по суті).

### 2. Самодостатні патчі (накладаються поверх наших 26)

Це справжня цінність: сховище, AMFI, crypto. Ще **не компілювались**.

```
0006-sweet-master-config-open-source-asm-pmap
0020-sweet-portable-aes-cbc
0021-sweet-mockfs-ramdisk-root
0022-sweet-ramdisk-root-without-iomedia
0023-sweet-builtin-sha256-for-libkern
0024-sweet-mockfs-virtual-ramdisk-io
0025-sweet-builtin-amfi-no-entitlements
0027-sweet-bearssl-md5
0028-sweet-ufs-root-device          <- цілий bsd/dev/sweet_ufs.c
0029-sweet-unsealed-root-volume
0030-sweet-ufs-writes
0032-sweet-bearssl-sha1
0033-sweet-bearssl-sha384-sha512
0034-sweet-ufs-dma-above-4g
0042-sweet-short-exec-log
0048-sweet-devnull-tee
0049-sweet-iokit-trace
0052-sweet-hfs-rename-swap
0120-guacamole-pmap-sync-attributes-64bit-pa
0142-guacamole-webkit-memlimit
```

Залежності: `0026-sweet-builtin-hfs` (створює `bsd/sweet_hfs/...`) падає лише
на `bsd/conf/Makefile.template`, а `0031-sweet-read-write-root` — похідний від
нього. Тобто HFS-стек відновлюється виправленням одного хунка, а не всього
дерева.

Порядок вмикання: ці патчі мають сенс **після** `arm_vm_init()` і
`bsd_init()`, тобто не раніше, ніж ядро дійде до користувацького простору.

### 3. Конфіг, рецепт і карта блокерів

- `xnu/macos27/MASTER.arm64.sweet.MacOSX` — MACOSX-конфіг SWEET.
- `tools/mkmacos27kernel.sh` — точні прапорці: macOS SDK, `MEMORY_SIZE=34359738368`,
  `RC_DARWIN_KERNEL_VERSION=25.5.0`, окремий `KERNEL_SDKROOT` з macOS
  `libfirehose_kernel.a`, перевірка, що ядро не arm64e.
- `tools/mkmacos27boot.sh` — boot-args (без `-v`/`debug`), `ufsroot=macos`,
  `rootrw=1`, підміна `/product` на «OnePlus 7 Pro».
- `xnu/ios27/README.md` + `NOTES.md` — впорядкований список того, що ламалося
  далі (platform expert, vtimer IRQ, boot CPU, SMP/PSCI, UFS root, unsealed
  root, AMFI, HID/IOSurface stand-ins, framebuffer, GPU, touch).

## Чому це важливо для Tahoe

Corey збирає **те саме ядро**, що потрібне Tahoe 26.5: `xnu-12377.121.6` з
`RC_DARWIN_KERNEL_VERSION=25.5.0`. Його macOS 27.2 userland працює поверх
darwin 25.5.0. Отже:

- апаратна частина доведена: SM8150/guacamole здатен вести macOS-ядро до
  користувацького простору;
- різниця між «наше ядро гине в `arm_vm_init()`» і «його десктоп» — не залізо,
  а ~150 відсутніх механізмів платформи;
- окремо залишається userland: arm64e→arm64 lowering + HFS+ root (у нього
  скрипти lowering і lowered overlays теж git-ignored, лише на Mac).

## Рекомендація

A. **Запросити повний diff дерева** (найкоротший шлях). Не 217 патчів, а один
   `git diff ac9718f..work` або tar `work/xnu-12377` (~200 MB) + kernel 17 MB.
   Це єдина відсутня ланка; усе інше вже є в обох репозиторіях.

B. **Продовжувати свою лінію** паралельно: 0026 → текстова консоль замість
   бінарних міток → platform expert / vtimer / CPU → `bsd_init` → storage
   (20 патчів вище).

C. Forward-port 8796→12377 (85 публічних патчів `dipa-studio/ios-sweet`) —
   окремий великий трек; саме його Corey пройшов вручну.

Рекомендація: A + B одночасно.
