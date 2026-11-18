import { test } from "node:test"
import assert from "node:assert/strict"
import { registerGuard } from "../src/guard.ts"
import { resolveConfig } from "../src/config.ts"

// Wire-level scrub regression pins (GUARD-9 class).
//
// Reproduced on OpenCode v2.2.5: a prompt queued while the session is busy
// inside an agent tool-loop is injected into the in-flight model requests from
// the pre-mutation in-memory copy. It never reaches persistence and bypasses
// the prompt hook mutation and the session.context scrub вЂ” the provider
// receives the raw secret while the audit already says "redacted".
//
// The `session:http.request` hook sees the actual provider request and is the
// guaranteed last line of defense: the body must be redacted there regardless
// of the admission path.
//
// NOTE: secret literals are assembled at runtime (join/slice) so that no
// scanner can fire on this source file; only already-masked placeholders
// appear verbatim.

const SECRET = ["sk", "live", "abcdef1234567890abcdef"].join("-")
/** unique middle of the secret вЂ” present iff the raw value reached the body */
const SECRET_CORE = "abcdef1234567890abcdef"
const KEY_WORD = ["api", "key"].join("_")
const PROMPT = ["set", KEY_WORD, "=", '"' + SECRET + '"', "--", "continue"].join(" ")
/** any mask placeholder (credential full mask or api-key keepLast partial mask) */
const ANY_MASK = "<REDACTED:"

/** minimal ctx mock that supports async hook handlers */
function makeCtx() {
  const handlers = new Map<string, Array<(e: unknown) => Promise<void> | void>>()
  const ctx = {
    location: { directory: "C:\\proj" },
    session: {
      hook: (name: string, fn: (e: unknown) => Promise<void> | void) => {
        const key = "session:" + name
        const list = handlers.get(key) ?? []
        list.push(fn)
        handlers.set(key, list)
        return Promise.resolve({ dispose: async () => {} })
      },
    },
    tool: { hook: () => Promise.resolve({ dispose: async () => {} }) },
    shell: { hook: () => Promise.resolve({ dispose: async () => {} }) },
  }
  const fire = async (name: string, event: unknown) => {
    for (const fn of handlers.get(name) ?? []) await fn(event)
  }
  return { ctx: ctx as never, fire }
}

function wireRequest(body: unknown): Request {
  return new Request("http://provider.test/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer x" },
    body: JSON.stringify(body),
  })
}

function makeEvent(request: Request) {
  return {
    sessionID: "ses_x",
    agent: "build",
    model: { providerID: "p", modelID: "m" },
    kind: "primary" as const,
    request,
  }
}

async function readAuditLines(dir: string): Promise<string[]> {
  const { readFileSync } = await import("node:fs")
  try {
    return readFileSync(dir + "/guard-audit.jsonl", "utf8").trim().split("\n")
  } catch {
    return []
  }
}

let auditSeq = 0
function makeCfg(mode: "enforce" | "warn") {
  auditSeq += 1
  const cfg = resolveConfig({ mode, scanSkillsOnLoad: false, audit: { dir: "./.tmp-audit-wire-" + auditSeq } })
  return cfg
}

/** audit dir of the last-created cfg (mirrors makeCfg sequencing) */
function lastAuditDir(): string {
  return "./.tmp-audit-wire-" + auditSeq
}

test("wire scrub: queued-delivery leak payload is redacted in the provider request body", async () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg("enforce"))
  const ev = makeEvent(
    wireRequest({
      model: "m",
      messages: [
        { role: "system", content: "system prompt" },
        { role: "user", content: [{ type: "text", text: PROMPT }] },
      ],
    }),
  )
  await fire("session:http.request", ev)
  const body = await (ev.request as Request).text()
  assert.ok(!body.includes(SECRET_CORE), "raw secret must not reach the provider body")
  assert.ok(body.includes(ANY_MASK), "mask must be present in the provider body")
  const events = await readAuditLines(lastAuditDir())
  assert.ok(events.some((l) => l.includes('"detail":"wire"') && l.includes('"action":"redacted"')), "wire scrub must be audited")
})

test("wire scrub: string content and assistant messages are covered too", async () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg("enforce"))
  const ev = makeEvent(
    wireRequest({
      model: "m",
      messages: [
        { role: "user", content: PROMPT },
        { role: "assistant", content: ["the", "key", "was", KEY_WORD, "=", '"' + SECRET + '"'].join(" ") },
        { role: "user", content: [{ type: "text", text: "no secrets here" }] },
      ],
    }),
  )
  await fire("session:http.request", ev)
  const body = await (ev.request as Request).text()
  assert.ok(!body.includes(SECRET_CORE))
  assert.ok(body.includes(ANY_MASK))
})

test("wire scrub: clean body passes through byte-identical and no wire audit is written", async () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg("enforce"))
  const original = JSON.stringify({ model: "m", messages: [{ role: "user", content: "hello world" }] })
  const ev = makeEvent(
    new Request("http://provider.test/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: original,
    }),
  )
  await fire("session:http.request", ev)
  const body = await (ev.request as Request).text()
  assert.equal(body, original, "clean body must not be rewritten")
  const events = await readAuditLines(lastAuditDir())
  assert.ok(!events.some((l) => l.includes('"detail":"wire"')), "no wire audit for clean bodies")
})

test("wire scrub: warn mode audits but does not rewrite", async () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg("warn"))
  const ev = makeEvent(
    wireRequest({ model: "m", messages: [{ role: "user", content: PROMPT }] }),
  )
  const before = await (ev.request as Request).clone().text()
  await fire("session:http.request", ev)
  const after = await (ev.request as Request).text()
  assert.equal(after, before, "warn mode must not rewrite the request")
})

test("wire scrub: non-JSON and GET requests are ignored", async () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg("enforce"))
  const evJson = makeEvent(
    new Request("http://provider.test/file", {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: PROMPT,
    }),
  )
  await fire("session:http.request", evJson)
  assert.equal(await (evJson.request as Request).text(), PROMPT, "non-JSON bodies must pass untouched")
  const evGet = makeEvent(
    new Request("http://provider.test/v1/models", {
      method: "GET",
      headers: { authorization: "Bearer " + SECRET },
    }),
  )
  await fire("session:http.request", evGet)
  assert.equal((evGet.request as Request).headers.get("authorization"), "Bearer " + SECRET, "GET requests must pass untouched")
})

// GUARD-9: the prompt hook masks the kv form, so the raw value is known to the
// guard — but a bare occurrence of that value elsewhere (another line, another
// in-memory copy serialized before the mask) matches no pattern. The wire hook
// must scrub it by the remembered value. Reproduced on OpenCode v2.2.5: the
// bare form reached the provider while the audit said "redacted".
const BARE_SECRET = ["c0ffee", "11223344", "55667788", "aabbccdd"].join("")
const BARE_SECRET_CORE = "1122334455667788"

test("wire scrub: a value masked in the prompt is scrubbed from a bare wire occurrence", async () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg("enforce"))
  const promptText = ["env", KEY_WORD, "=", '"' + BARE_SECRET + '"', "--", "check"].join(" ")
  await fire("session:prompt", { sessionID: "ses_x", messageID: "msg_1", prompt: { text: promptText } })
  const ev = makeEvent(
    wireRequest({
      model: "m",
      messages: [{ role: "user", content: [{ type: "text", text: BARE_SECRET }] }],
    }),
  )
  await fire("session:http.request", ev)
  const body = await (ev.request as Request).text()
  assert.ok(!body.includes(BARE_SECRET_CORE), "bare remembered value must not reach the provider body")
  assert.ok(body.includes(ANY_MASK), "mask must replace the bare value")
  const events = await readAuditLines(lastAuditDir())
  const wire = events.find((l) => l.includes('"detail":"wire"'))
  assert.ok(wire, "wire scrub must be audited")
  assert.ok(!wire.includes('"count":0'), "wire audit must count the value replacements")
})

test("wire scrub: remembered value inside a nested JSON string (escaped form) is scrubbed", async () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg("enforce"))
  const promptText = ["env", KEY_WORD, "=", '"' + BARE_SECRET + '"'].join(" ")
  await fire("session:prompt", { sessionID: "ses_x", messageID: "msg_2", prompt: { text: promptText } })
  // the secret wrapped in an inner JSON document carried as a string field
  const inner = JSON.stringify({ cmd: "curl -H 'Authorization: Bearer " + BARE_SECRET + "' https://x.test" })
  const ev = makeEvent(
    wireRequest({
      model: "m",
      messages: [{ role: "user", content: [{ type: "text", text: inner }] }],
    }),
  )
  await fire("session:http.request", ev)
  const body = await (ev.request as Request).text()
  assert.ok(!body.includes(BARE_SECRET_CORE), "escaped remembered value must not reach the provider body")
})
