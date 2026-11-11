# KANI3300 B2 — coordinator CI input

25 независимых бинарей, edition 2021, без зависимостей; общий код/библиотека отсутствуют.
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

Каждый main печатает сценарий **до** передачи/чтения, затем читает ровно четыре байта исходного local/field через
raw pointer, созданный до передачи. Успешные reads отмечаются постоянной строкой без печати значений.
`read_volatile::<u8>` удерживает наблюдение; volatile не разрешает читать uninit. Не заменять на чтение `MaybeUninit<u8>`.
Word/NonCopyWord/union payload состоят из четырех инициализированных байтов без padding; негативный MU control намеренно uninit.
Нет heap ownership, Drop, освобождений, integer→pointer round trips и чтений caller storage внутри callee.
Источники — именованные locals, остающиеся в лексическом scope до конца main; field probes сохраняют родительский Pair.
Reinit пишет в тот же mut local; последующий read использует **старый** raw pointer. Sibling control читает другой field явно.

Для принятия результата проверить allocation/source identity и live storage у наблюдаемого read, а не только равенство адресов.
Различать `uninitialized` в исходном read, dangling/alias/invalid-value/compile error и UB в другом месте.
`OK` означает только исход конкретного pinned Miri пути, а не разрешение такого кода Rust Reference или Kani proof credit.
