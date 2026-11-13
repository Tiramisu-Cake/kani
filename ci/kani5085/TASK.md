# KANI5085 — воспроизводитель #5085 на CBMC с фиксом diffblue/cbmc#9487 (ISSUED 2026-11-13 → worker15)

Это верификация корректности, не security-работа. Подготовка CI-пакета; push/dispatch делает координатор.
Локально никаких cargo/rustc/Kani/CBMC/сборок; только Python/static. Без комментариев/issue/PR куда-либо.

## Цель
Подтвердить или опровергнуть, что фикс CBMC (`bits2expr`: `> bitst{0}` → `>= bitst{0}`) устраняет падение из
model-checking/kani#5085, чтобы владелец мог оставить точный комментарий в #5085.

## Входы
- CBMC fix: Tiramisu-Cake/cbmc ветка `fix/array-zero-width-elements-v2` @ `9f2d01ec2bf115879c86e22203d403ba156d22e5`
  (база diffblue develop `107a1e504c`). Контроль: та же база без фикса (`107a1e504c`) ИЛИ релиз 6.11.0 — выбери дешевле,
  но base и fix должны отличаться только фиксом (предпочтительно собрать обе из исходников одной сборкой с одним toolchain,
  либо собрать fix и сравнить с stock 6.11.0, честно записав разницу).
- Kani: upstream model-checking/kani `main` (актуальный SHA зафиксировать) — без наших Part 1/B3 изменений.
  Kani использует CBMC из своей установки; найди по исходникам (kani-driver: как выбирается бинарь `cbmc`, `KANI_CBMC`/PATH/bundle)
  самый простой корректный способ подставить собранный CBMC, и докажи в CI-логе, что реально использовался он (`cbmc --version`/путь).
- Воспроизводитель: текст issue #5085 дословно (прочитай `gh issue view 5085 -R model-checking/kani`, сохрани копию с SHA256).

## Корни (минимум)
1. #5085 дословно; 2. его вариант с `const` вместо `static` (или наоборот, что в issue нет);
3. типизированная копия `struct Tail { b: u8, z: [(); 2] }` (из t0 kani3300/b3p/PR-UPSTREAM.md, Limitations);
4. вариант с недетерминированными байтами (`kani::any()`), идущий через lowering, а не сворачивание констант.
Для каждого корня: stock/base CBMC и fix CBMC; сохранить exit, verdict, `Invariant check failed`-блок (если есть), версии.
Ожидание (не подгонять): base — invariant в bits2expr для 1–3; fix — без invariant; 4 — может упасть иначе (lowering, вне фикса).

## Результат
t0 `kani3300/kani5085-patched-cbmc/`: TASK-копия входов, workflow (один job, Linux x86_64, timeout ≤ 90 мин, сборка CBMC через
cmake Release как в штатном CI CBMC, без лишних целей), CI-REQUEST.md (что пушить и куда: CI-only ветка в Tiramisu-Cake/kani,
`uninit-ci/kani5085-*`), RESULT-template. Research-коммит [skip ci], автор Tiramisu-Cake <igkharin@gmail.com> через -c, без push.
Финал: `READY <sha>`.
