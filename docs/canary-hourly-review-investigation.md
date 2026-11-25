# Investigation: hourly canary automation — pre-flight review (guard-13)

Date: 2026-11-25. Read-only review; no automation enabled, no processes created/stopped.

## Root cause (main finding)

The planned canary passes the synthetic token as a **command-line argument**
(`opencode run --server ... "<prompt with token>"`). The opencode CLI logs its
own argv at INFO level (`message="cli starting" ... args="[...]"`) into the
shared log `%USERPROFILE%\.local\share\opencode\log\opencode.log`. Therefore the
**raw synthetic token is persisted unmasked** on every run, regardless of
whether the prompt hook is alive (the client logs argv before the server-side
hook runs). This violates the experiment's own contract "token never persisted
anywhere". Mitigation: pass the prompt via **stdin** (`... | opencode run` or
`opencode run` with piped input) so argv contains no token — verify with a
dry-run; or explicitly accept + document (token is synthetic, local-only).

The serve password value was **not** found in the shared log (checked with
masked regexes); it exists only in `serve2.log` (by design).

## Тупики (T)

- **T1** — regex `(?i)password["\s=:]+\S{20,}` over the shared log matched 3
  lines → looked like a password-value leak. On inspection all 3 are
  `spawning process` lines from 2026-11-12/17 whose *script text* contains the
  word "password" (old experiments). Not values → dead end for a password leak.
- **T2** — 18 `server password` lines in the shared log: all `spawning process`
  lines from 2026-11-17 (old script args), none from the current serve
  (started 2026-11-25 10:29). Not a leak path → dead end.

## Чекпоинты (CHK)

- **CHK-1** — port 28999 LISTENING, process `opencode`, addr 127.0.0.1
  (Get-NetTCPConnection, pid 21840).
- **CHK-2** — `serve2.log`: exactly 2 lines / 212 bytes, exactly 1
  `server password` line; value not printed (masked check). 0 token lines.
- **CHK-3** — shared `opencode.log`: 48,747,502 bytes, oldest line
  2026-10-11, no rotated files in the log directory (single append file).
- **CHK-4** — 13 `npm_`-token matches in shared log: **all 13** inside client
  `cli starting args=` lines; 0 matches anywhere else (server-side/model-side
  output never contained the token → in earlier runs the hook masked before the
  model).
- **CHK-5** — `guard-audit.jsonl`: 206,386 bytes; line keys
  `ts,kind,sessionID,categories,count,action`; **no prompt-content field**;
  0 token matches. Primary audit signal is safe to use.
- **CHK-6** — `canary-status.jsonl`: does not exist yet.
- **CHK-7** — shared-log growth observed: ~21,881 lines / ~6.6 MB in the last
  hour (all activity combined, not canary-only).
- **CHK-8** — project session storage
  (`~\.local\share\opencode\project`): empty/absent; 0 files containing the
  token pattern.

## Артефакты и очистка

- No files created besides this journal. No secrets printed or written; all
  greps used masking placeholders. Nothing to clean up.
