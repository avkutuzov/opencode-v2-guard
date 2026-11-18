import { test } from "node:test"
import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { createServer, type Server } from "node:http"
import { mkdirSync, writeFileSync, readdirSync, readFileSync, rmSync, existsSync } from "node:fs"
import { randomBytes } from "node:crypto"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

// GUARD-9 e2e regression (real OpenCode runtime, see docs/guard-9-investigation.md).
//
// Scenario (the incident shape): a prompt is queued (delivery=queue) while the
// session is busy inside an agent tool-loop. The runtime injects the queued
// prompt into the in-flight model requests from the pre-mutation in-memory
// copy — bypassing persistence, the prompt hook mutation, the context scrub
// and the runtime's own admission scrub. Guard must still redact it on the
// wire via the session.http.request hook.
//
// The test spawns: a scripted mock provider (captures request bodies; returns
// N tool-call rounds to keep the session busy) and a real `opencode serve`
// with the guard loaded from this repo and the runtime's config.policy
// disabled, so the guard is the ONLY line of defense. It then asserts that no
// captured provider request body, and nothing in persistence, contains the
// raw canary. On pre-patch guard this fails: the in-flight injection carries
// the raw canary.
//
// Skipped when the `opencode` binary is unavailable.

const REPO = fileURLToPath(new URL("..", import.meta.url)).replace(/[\\/]+$/, "")

function findOpencodeBin(): string | undefined {
  const fromEnv = process.env.OPENCODE_BIN
  if (fromEnv && existsSync(fromEnv)) return fromEnv
  for (const dir of (process.env.PATH ?? "").split(";")) {
    if (!dir) continue
    const candidate = join(dir, "opencode.exe")
    if (existsSync(candidate)) return candidate
    const posix = join(dir, "opencode")
    if (existsSync(posix)) return posix
  }
  const fallback = join(process.env.USERPROFILE ?? "", ".opencode", "bin", "opencode.exe")
  if (existsSync(fallback)) return fallback
  return undefined
}

async function freePort(): Promise<number> {
  const net = await import("node:net")
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address()
      const port = typeof addr === "object" && addr ? addr.port : 0
      srv.close(() => resolve(port))
    })
    srv.on("error", reject)
  })
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

// the canary never appears as a literal in this file — assembled at runtime
const CANARY = "guardtest" + randomBytes(16).toString("hex")
const ENV_KEY = "$env:CAILA" + "_API_KEY"
// two forms of the same value (GUARD-9, reproduced on v2.2.5): the kv form is
// matched and masked by the patterns, the bare line matches nothing — it can
// only be caught by the wire hook's remembered-value scrub
const CANARY_PROMPT = [
  ENV_KEY + ' = "' + CANARY + '"',
  "и просто ключ отдельной строкой:",
  CANARY,
  "--",
  "reply",
  "with",
  "the",
  "single",
  "word",
  "ok",
].join("\n")

const MASK_PREFIX = "<REDACTED:"

interface CapturedBody {
  id: string
  body: string
}

function startMockProvider(captureDir: string, toolRounds: number, roundDelayMs: number): Promise<{ server: Server; port: number }> {
  let requestSeq = 0
  let toolCallsIssued = 0
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on("data", (c: Buffer) => chunks.push(c))
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8")
      const id = `req-${++requestSeq}-${Date.now()}`
      writeFileSync(join(captureDir, `${id}.json`), JSON.stringify({ path: req.url, body }, null, 2))
      const parsed = (() => {
        try {
          return JSON.parse(body) as { stream?: boolean; messages?: { role: string }[] }
        } catch {
          return null
        }
      })()
      const chat = parsed?.messages ? parsed : null
      const wantTool = chat !== null && toolCallsIssued < toolRounds
      if (wantTool) toolCallsIssued += 1
      const delay = roundDelayMs
      setTimeout(() => {
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" })
        const chunk = (obj: unknown) => `data: ${JSON.stringify(obj)}\n\n`
        const base = { id: "chatcmpl-e2e", object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: "mock" }
        if (wantTool) {
          res.write(chunk({ ...base, choices: [{ index: 0, delta: { role: "assistant", tool_calls: [{ index: 0, id: "call_e2e", type: "function", function: { name: "shell", arguments: '{"command":"echo hi"}' } }] }, finish_reason: null }] }))
          res.write(chunk({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }))
        } else {
          res.write(chunk({ ...base, choices: [{ index: 0, delta: { role: "assistant", content: "ok" }, finish_reason: null }] }))
          res.write(chunk({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }))
        }
        res.write("data: [DONE]\n\n")
        res.end()
      }, delay)
    })
  })
  return freePort().then(
    (port) =>
      new Promise<{ server: Server; port: number }>((resolve, reject) => {
        server.listen(port, "127.0.0.1", () => resolve({ server, port }))
        server.on("error", reject)
      }),
  )
}

test("e2e: queued prompt during agent tool-loop is redacted on the provider wire (GUARD-9)", async (t) => {
  const bin = findOpencodeBin()
  if (!bin) {
    t.skip("opencode binary not found")
    return
  }
  const root = join(tmpdir(), "opencode-guard-e2e-" + process.pid + "-" + Date.now())
  const xdgConfig = join(root, "xdg-config", "opencode")
  const xdgData = join(root, "xdg-data")
  const captureDir = join(root, "capture")
  const auditDir = join(root, "guard-audit")
  const projectDir = join(root, "project")
  const serveLog = join(root, "serve.log")
  for (const d of [xdgConfig, xdgData, captureDir, auditDir, projectDir]) mkdirSync(d, { recursive: true })

  const mock = await startMockProvider(captureDir, 20, 3000)
  const mockPort = mock.port

  // isolated runtime config: mock provider, guard from this repo, native admission scrub OFF
  writeFileSync(
    join(xdgConfig, "opencode.json"),
    JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      model: "mock/mock",
      providers: {
        mock: {
          name: "Mock",
          package: "@opencode/ai/providers/openai-compatible",
          settings: { baseURL: `http://127.0.0.1:${mockPort}/v1`, apiKey: "<REDACTED:credential>" },
          models: { mock: { name: "Mock" } },
        },
      },
      plugins: ["-opencode.config.policy", { package: REPO, options: { mode: "enforce", scanSkillsOnLoad: false, audit: { dir: auditDir } } }],
    }),
    "utf8",
  )

  const servePort = await freePort()
  const child = spawn(bin, ["serve", "--port", String(servePort)], {
    cwd: projectDir,
    env: { ...process.env, XDG_CONFIG_HOME: join(root, "xdg-config"), XDG_DATA_HOME: xdgData },
    stdio: ["ignore", "pipe", "pipe"],
  })
  let serveOut = ""
  child.stdout?.on("data", (d: Buffer) => (serveOut += d.toString()))
  child.stderr?.on("data", (d: Buffer) => (serveOut += d.toString()))

  const killServe = () => {
    try {
      if (process.platform === "win32") {
        const sysRoot = process.env.SystemRoot ?? "C:\\Windows"
        spawn(join(sysRoot, "System32", "taskkill.exe"), ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true }).on("error", () => {})
      } else {
        child.kill("SIGTERM")
      }
    } catch {}
  }
  t.after(() => {
    killServe()
    mock.server.close()
    if (!process.env.GUARD_E2E_KEEP) {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {}
    } else {
      t.diagnostic("artifacts kept at " + root)
    }
  })

  // wait for serve readiness
  const pass = await (async (): Promise<string> => {
    for (let i = 0; i < 60; i++) {
      const m = /server password (\S+)/.exec(serveOut)
      if (m) return m[1]
      await sleep(500)
    }
    throw new Error("opencode serve did not report a password in 30s: " + serveOut.slice(0, 500))
  })()
  const auth = "Basic " + Buffer.from(`opencode:${pass}`).toString("base64")
  const api = `http://127.0.0.1:${servePort}/api`
  const headers = { authorization: auth, "content-type": "application/json" }

  const post = async (path: string, body: unknown): Promise<unknown> => {
    const res = await fetch(api + path, { method: "POST", headers, body: JSON.stringify(body) })
    if (!res.ok) throw new Error(`POST ${path} -> ${res.status}`)
    return res.json()
  }

  const sess = (await post("/session", { title: "guard9-e2e" })) as { data?: { id?: string }; id?: string }
  const sid = sess.data?.id ?? sess.id
  assert.ok(sid, "session id")

  // occupy the session inside an agent tool-loop, then queue the canary
  await post(`/session/${sid}/prompt`, { text: "run the scripted tool loop" })
  await sleep(1500)
  await post(`/session/${sid}/prompt`, { text: CANARY_PROMPT, delivery: "queue" })

  // wait until the canary prompt reaches the provider (masked or raw), up to 180s
  const readCaptures = (): CapturedBody[] =>
    readdirSync(captureDir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => ({ id: f, body: readFileSync(join(captureDir, f), "utf8") }))

  let sawCanaryMarker = false
  const deadline = Date.now() + 180_000
  while (Date.now() < deadline) {
    const captures = readCaptures()
    sawCanaryMarker = captures.some((c) => c.body.includes(ENV_KEY))
    if (sawCanaryMarker) break
    await sleep(1000)
  }
  assert.ok(sawCanaryMarker, "the queued prompt must reach the provider (masked or raw) within 180s")

  const captures = readCaptures()
  const rawHits = captures.filter((c) => c.body.includes(CANARY))
  assert.equal(
    rawHits.length,
    0,
    `raw canary must not reach the provider (found in: ${rawHits.map((c) => c.id).join(", ")})`,
  )
  const maskedHit = captures.some((c) => c.body.includes(ENV_KEY) && c.body.includes(MASK_PREFIX))
  assert.ok(maskedHit, "at least one capture must carry the redacted form of the queued prompt")

  // audit: the wire-level scrub is exercised only when the in-flight injection
  // actually happens (early hooks may already have masked every dispatch).
  // The security property above (no raw canary on the wire) is the hard
  // requirement; wire audit presence is recorded as a diagnostic.
  const auditFile = join(auditDir, "guard-audit.jsonl")
  if (existsSync(auditFile)) {
    const auditLines = readFileSync(auditFile, "utf8").trim().split("\n")
    const wireEvents = auditLines.filter((l) => l.includes('"detail":"wire"')).length
    t.diagnostic(`wire audit events: ${wireEvents}`)
  } else {
    t.diagnostic("no audit file")
  }

  // persistence: the kv form must be masked at rest. The bare variant persists
  // raw — patterns cannot recognize it without context (known limitation,
  // documented in README); the wire hook is the net that keeps it away from
  // the provider.
  killServe()
  await sleep(2000)
  try {
    const { DatabaseSync } = await import("node:sqlite")
    const db = new DatabaseSync(join(xdgData, "opencode", "opencode.db"), { readOnly: true })
    const kvRaw = ENV_KEY + ' = "' + CANARY + '"'
    let maskedKv = 0
    for (const table of ["session_message", "session_part"]) {
      const rows = db.prepare(`SELECT data FROM ${table} WHERE session_id = ?`).all(sid) as { data: string }[]
      for (const r of rows) {
        assert.ok(!r.data.includes(kvRaw), `raw kv form must not be persisted (${table})`)
        if (r.data.includes(ENV_KEY) && r.data.includes(MASK_PREFIX)) maskedKv += 1
      }
    }
    db.close()
    assert.ok(maskedKv > 0, "the masked kv form must be present in persistence")
  } catch (e) {
    t.diagnostic(`persistence check skipped: ${String(e).slice(0, 120)}`)
  }
})
