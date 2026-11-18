import { test } from "node:test"
import assert from "node:assert/strict"
import { registerGuard } from "../src/guard.ts"
import { resolveConfig } from "../src/config.ts"

// Outbound context scrub coverage (GUARD-9 follow-up): every string that can
// reach the provider request must be scrubbed at the context layer, regardless
// of the part type — assistant "reasoning" parts (thinking replayed to the
// provider) and system metadata.experimental.instructions copies (the runtime
// keeps raw instruction texts there; it does not re-derive them from the
// edited part text). DB-restored messages pass through the same hook.

function makeCtx() {
  const handlers = new Map<string, Array<(e: unknown) => void>>()
  const reg = (name: string, fn: (e: unknown) => void) => {
    const list = handlers.get(name) ?? []
    list.push(fn)
    handlers.set(name, list)
    return Promise.resolve({ dispose: async () => {} })
  }
  const ctx = {
    location: { directory: "C:\\proj" },
    session: { hook: (name: string, fn: (e: unknown) => void) => reg("session:" + name, fn) },
    tool: { hook: (name: string, fn: (e: unknown) => void) => reg("tool:" + name, fn) },
    shell: { hook: (name: string, fn: (e: unknown) => void) => reg("shell:" + name, fn) },
  }
  const fire = (name: string, event: unknown) => {
    for (const fn of handlers.get(name) ?? []) fn(event)
  }
  return { ctx: ctx as never, fire }
}

let auditSeq = 0
function makeCfg() {
  auditSeq += 1
  const cfg = resolveConfig({ mode: "enforce", scanSkillsOnLoad: false, audit: { dir: "./.tmp-audit-ctx-" + auditSeq } })
  return cfg
}

// secret assembled at runtime; bare form matches no pattern, kv form does
const SECRET = ["9f2c", "d41e", "77aa", "03b8", "5c61", "e9f0"].join("-")
const SECRET_CORE = "d41e-77aa"
const KEY_WORD = ["api", "key"].join("_")

test("context scrub masks secrets in assistant reasoning parts", () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg())
  const msg = {
    id: "msg_a",
    role: "assistant",
    content: [
      { type: "reasoning", text: "thinking about " + KEY_WORD + " = " + SECRET },
      { type: "text", text: "done" },
    ],
  }
  fire("session:context", { system: [], messages: [msg] })
  const reasoning = msg.content[0] as { text: string }
  assert.ok(!reasoning.text.includes(SECRET_CORE), "reasoning part must be scrubbed")
  assert.ok(reasoning.text.includes("<REDACTED:credential>"), "mask must replace the secret in reasoning")
  const text = msg.content[1] as { text: string }
  assert.equal(text.text, "done", "clean text part must stay untouched")
})

test("context scrub masks secrets in system metadata.experimental.instructions copies", () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg())
  const part = {
    type: "text",
    text: "deploy uses " + KEY_WORD + '="' + SECRET + '"',
    metadata: { experimental: { instructions: [{ key: "agents.md", text: "raw copy: " + KEY_WORD + "=" + SECRET }] } },
  }
  fire("session:context", { system: [part], messages: [] })
  assert.ok(!part.text.includes(SECRET_CORE), "system part text must be scrubbed")
  const ins = part.metadata.experimental.instructions[0]
  assert.ok(!ins.text.includes(SECRET_CORE), "instructions metadata copy must be scrubbed too")
})

test("context scrub covers DB-restored message shapes (string content and parts)", () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg())
  // admission first: the kv form is masked and its value remembered per session
  const SID = "ses_ctx"
  fire("session:prompt", { sessionID: SID, messageID: "msg_0", prompt: { text: "deploy " + KEY_WORD + '="' + SECRET + '"' } })
  // next turn: the runtime restores the history from the DB, including an
  // assistant echo that persisted the value bare (patterns cannot mask it at rest)
  const m1 = { id: "msg_b", role: "user", content: KEY_WORD + "=" + SECRET }
  const m2 = { id: "msg_c", role: "assistant", content: [{ type: "reasoning", text: "echo " + SECRET }] }
  fire("session:context", { sessionID: SID, system: [], messages: [m1, m2] })
  assert.ok(!(m1.content as string).includes(SECRET_CORE), "string content must be scrubbed")
  const p = (m2.content as { text: string }[])[0]
  assert.ok(!p.text.includes(SECRET_CORE), "restored bare occurrence must be scrubbed via the remembered value")
})
