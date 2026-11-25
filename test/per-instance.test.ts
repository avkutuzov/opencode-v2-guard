import { test } from "node:test"
import assert from "node:assert/strict"
import { registerGuard } from "../src/guard.ts"
import { resolveConfig } from "../src/config.ts"

// GUARD-13 regression (upstream anomalyco/opencode#66299): the plugin module is
// loaded once per server process and every location runs setup against that same
// module. Hook registrations used to live in a module-level array, so any
// location's cleanup (idle eviction of project A) disposed every other loaded
// location's hooks (project B kept serving prompts with the plugin silently
// gone). Registrations must be per instance; cleanup must dispose only its own.

function makeCtx() {
  const handlers = new Map<string, Array<(e: unknown) => void>>()
  let disposables = 0
  let disposed = 0
  const reg = (name: string, fn: (e: unknown) => void) => {
    const list = handlers.get(name) ?? []
    list.push(fn)
    handlers.set(name, list)
    disposables += 1
    return Promise.resolve({
      dispose: async () => {
        disposed += 1
      },
    })
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
  return { ctx: ctx as never, fire, counts: () => ({ disposables, disposed }) }
}

let auditSeq = 900
function makeCfg() {
  auditSeq += 1
  return resolveConfig({ mode: "enforce", scanSkillsOnLoad: false, audit: { dir: "./.tmp-audit-perinstance-" + auditSeq } })
}

const flush = () => new Promise<void>((r) => setImmediate(r))

test("cleanup of one location's guard instance disposes only its own hooks", async () => {
  const a = makeCtx()
  const b = makeCtx()
  const cleanupA = registerGuard(a.ctx, makeCfg())
  const cleanupB = registerGuard(b.ctx, makeCfg())

  // trackHook registers asynchronously; let the microtasks land
  await flush()
  await flush()

  const beforeA = a.counts()
  const beforeB = b.counts()
  assert.equal(beforeA.disposables, beforeB.disposables)
  assert.ok(beforeA.disposables > 0, "guard must register hooks")

  await cleanupA()
  assert.equal(a.counts().disposed, beforeA.disposables, "cleanupA disposes all of A's registrations")
  assert.equal(b.counts().disposed, 0, "cleanupA must not dispose B's registrations (GUARD-13)")

  await cleanupB()
  assert.equal(b.counts().disposed, beforeB.disposables, "cleanupB disposes B's own registrations")
})
