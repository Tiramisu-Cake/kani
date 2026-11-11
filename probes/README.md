# KANI3300 B2 — coordinator CI input

Исходные 25 независимых бинарей, edition 2021, без зависимостей; общий код/библиотека отсутствуют.
Локальный pin — `nightly-2026-10-23`, компонент `miri`; `[workspace]` изолирует crate от корневого Rust workspace.
В B2 ничего не компилировалось и не запускалось. Следующие команды — вход для **CI координатора**, не локальные checks:

```sh
cd research/challenge-8/kani-k1/kani3300/b2/probes
rustc -Vv
cargo miri --version
# Для каждого src/bin/<name>.rs отдельно, сохраняя ошибку ожидаемого UB и продолжая остальные:
rustc --edition=2021 -Zunpretty=mir src/bin/<name>.rs
cargo miri run --bin <name>
```

Координатор фиксирует exact research SHA, rustc/Miri identities, target, flags, полный список бинарей и отдельный outcome каждого.
Не отключать validity/uninit/alias checks. Не добавлять opt/inlining flags незаметно; записывать штатные flags среды.
`-Zunpretty=mir` — обзор, а не доказательство идентичности MIR, исполняемого Miri: при расхождении выяснить фазу/lowering.
В MIR сопоставить исходный local/field, `Copy`/assignment `Move`/`Call(Move)`, промежуточные temporaries,
исчезновение intrinsic forget, reinit и `StorageDead`. Особенно проверить, получает ли callee сам source или временную копию.

Каждый из исходных 25 main печатает сценарий **до** передачи/чтения, затем читает ровно четыре байта исходного local/field через
raw pointer, созданный до передачи. Успешные reads отмечаются постоянной строкой без печати значений.
`read_volatile::<u8>` удерживает наблюдение; volatile не разрешает читать uninit. Не заменять на чтение `MaybeUninit<u8>`.
Word/NonCopyWord/union payload состоят из четырех инициализированных байтов без padding; негативный MU control намеренно uninit.
Нет heap ownership, Drop, освобождений, integer→pointer round trips и чтений caller storage внутри callee.
Источники — именованные locals, остающиеся в лексическом scope до конца main; field probes сохраняют родительский Pair.
Reinit пишет в тот же mut local; последующий read использует **старый** raw pointer. Sibling control читает другой field явно.

Для принятия результата проверить allocation/source identity и live storage у наблюдаемого read, а не только равенство адресов.
Различать `uninitialized` в исходном read, dangling/alias/invalid-value/compile error и UB в другом месте.
`OK` означает только исход конкретного pinned Miri пути, а не разрешение такого кода Rust Reference или Kani proof credit.

## B2b — четыре дополнительных custom MIR бинаря

`custom_call_move_read`, `custom_call_move_write`, `custom_call_copy_read`, `custom_call_copy_write`:
итого в crate 29 бинарей. Feature gates `custom_mir, core_intrinsics`; dialect `runtime`, phase `optimized`.
Пробы читают **один** байт `src: u8`, инициализированный `0x51`, после прямого Call тем же place.
`addr_of!(src)` — документированный RawPtr rvalue; Copy задаётся bare place `src`, Move — `Move(src)`.
Никаких assignment temporaries перед consume; source не reinit и не StorageDead.
У callee только by-value u8; в write-варианте volatile запись `0xA7` и последующий volatile read.
Если post-call source read завершается, main печатает callee/source значения; Copy-контроли проверяют оба,
Move проверяет callee и оставляет source значение для интерпретации CI без навязанного исхода.
Прогнозы и точные source:line ссылки: B2b раздел `../EXPECTATIONS.md`.

Существующий coordinator-only цикл выше применим и к этим четырём бинарям без новых flags.
CI сверяет `probe` MIR (не только `main`): raw address относится к `src`, consume получает именно
`Move(src)`/`Copy(src)`, а post-call `read_volatile` — сохранённый `p` до возврата из probe.
В стандартном callee MIR также подтвердить volatile read/write параметра. Не запускать весь crate
без выбора bin и не трактовать ожидаемую Move UB как ошибку доставки пробы.
Все исполнения остаются CI координатора; в B2b локально только чтение исходников и static checks.
