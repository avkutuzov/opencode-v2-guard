# Журнал: ревью часовой canary-автоматизации (pre-enablement review)

Дата: 2026-11-25. Ревью planned PowerShell 5.1 automation (hourly canary через
`opencode run --server http://127.0.0.1:28999`). Вердикт: **REJECT** (нужна
исправленная версия, см. отчёт ревью). Ничего не включено; все проверки
read-only/dry-run, без вызовов LLM.

## Root cause (дефекты предложенного скрипта)

1. **КРИТИЧНО**: `[datetime]::Parse($e.ts)` для ISO-строки с `Z` возвращает
   `DateTime` с `Kind=Local` — на машине (Turkey Standard Time, UTC+3) ts
   сдвигается на +3ч, а `$cut` остаётся в UTC → окно «свежести» фактически
   растягивается до ~3ч15м. Dry-run: proposed-логика вернула
   `audit_prompt=true`, хотя новейший kind=prompt вход — 52 минуты назад.
   Исправление: `[datetimeoffset]::Parse($e.ts).UtcDateTime`.
2. **HIGH**: нет таймаута на `opencode run` — зависший вызов модели живёт >1ч,
   часовые запуски накапливают повисшие powershell/opencode-процессы.
   Исправление: `Start-Process -PassThru` + `WaitForExit(900000)` +
   `Stop-Process -Id $p.Id` (kill только по собственному PID).
3. **MEDIUM**: нет проверки живости serve (лог есть — порт может быть закрыт)
   и наличия `opencode` в PATH → безликие all-false статусы вместо явной
   причины. Исправление: `Get-NetTCPConnection -LocalPort 28999` и
   `Get-Command opencode` → result-enum (`serve_not_listening`,
   `opencode_not_found`).
4. **LOW**: пароль-regex `(.+)$` захватил бы хвостовые пробелы (сейчас их нет);
   заменить на `(\S+)`.
5. **LOW**: `Get-Content | Select-Object -Last 200` читает весь файл; заменить
   на `Get-Content -Tail 2000`.
6. **LOW**: `$Matches` после `-match` внутри `Where-Object` в pipeline —
   работает на этой PS 5.1 (scriptblock Where-Object течёт в caller-scope),
   но хрупко; заменить на same-scope `foreach`.
7. **LOW**: нет result-enum/exit-code для мониторинга; добавить
   `result:"ok"/...` и `exit 0/1`.
8. **INFO**: PS 5.1 `Start-Process -ArgumentList` не квотирует элементы массива
   с пробелами → передавать одной заранее заквоченной строкой.
9. **INFO**: `[string]$out` cast для защиты от null (проверено: `Out-String`
   пустого входа даёт `""`, не `$null` — но cast оставлен defensively).
10. **INFO**: `--archived` у `opencode run` — часовые canary-сессии не замусоривают
    списки сессий.

## Тупики (T1..Tn)

- **T1**: гипотеза «`$Matches` из `Where-Object` не видна в pipeline → пароль
  всегда не извлекается» — НЕ подтвердилась: эмпирически на этой PS 5.1
  scriptblock `Where-Object` выполняется в caller-scope
  (`whereobject_scope_leaks_to_caller=True`), извлечение работает и в
  pipeline, и внутри функции, значение совпадает с same-scope-вариантом.
  Понижено до LOW (хрупкость, не баг).
- **T2**: попытка websearch документации opencode (env OPENCODE_PASSWORD) —
  HTTP 403, тупик; заменено строковой проверкой бинарника (CHK-5).

## Чекпоинты (CHK-1..N)

- **CHK-1**: serve2.log существует, ровно 2 строки, 1 строка `server password`;
  извлечённый пароль — 43 символа, без хвостовых пробелов; пароль нигде не
  печатался/не сохранялся (только booleans/counters).
- **CHK-2**: порт 28999 слушается, PID 21840.
- **CHK-3**: audit-файл `%USERPROFILE%\.local\share\opencode\guard\guard-audit.jsonl`:
  1473 строки; за 24ч — 51, за 1ч — 5; kinds: context=1214, tool.after=123,
  tool.before=82, prompt=20, skill=12, deps=21, shell=1; последний
  kind=prompt — последняя строка файла, 52 мин назад. Вывод: `-Last 200`
  достаточно (рост ~2-5/ч), но `-Tail 2000` дешевле и на вырост.
- **CHK-4**: dry-run freshness: proposed-логика (`[datetime]::Parse`) → true
  (ЛОЖНО-ЗДОРОВЫЙ, при возрасте 52 мин); исправленная
  (`[datetimeoffset]::Parse(...).UtcDateTime`) → false, 0 ошибок парсинга
  на 20 prompt-записях.
- **CHK-5**: `C:\Users\admin\.opencode\bin\opencode.exe` содержит строки
  `OPENCODE_PASSWORD` и `server password` (env-переменная существует в
  бинарнике; полный e2e-путь не тестировался — потребовал бы вызов LLM).
- **CHK-6**: конструкция status-строки валидна: JSON парсится, `exact_raw` —
  Boolean, ts round-trip строкой; тестовая строка записана в
  canary-status.jsonl и удалена (файл возвращён в исходное состояние
  «не существует»); в status-файле нет литералов `npm_*[36]`.
- **CHK-7**: `opencode v2.4.0`; `opencode run --help` подтверждает флаги
  `--server string` (global) и `--archived`.
- **CHK-8**: TZ машины — Turkey Standard Time (UTC+3);
  `[datetime]::Parse('...Z')` → `Kind=Local`; `[datetimeoffset]::Parse(...).UtcDateTime`
  → корректный UTC.

## Артефакты и очистка

- Тестовая строка в `...\repro-guard13\canary-status.jsonl` — удалена вместе
  с файлом (до теста файл не существовал).
- Литералы секретов в источниках/скриптах отсутствуют: canary-токен
  генерируется в рантайме, пароль читается из лога только в память/ env
  процесса.
- Единственная временная запись на диск: stdout/stderr canary-run во
  временные файлы `%TEMP%\canary_*.tmp` (удаляются сразу после чтения) —
  компромисс ради `WaitForExit`+PID-kill; содержат максимум синтетический
  токен, не пароль serve.
