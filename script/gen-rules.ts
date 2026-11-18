// Regenerate the gitleaks-derived rules inside index.ts.
//
//   bun script/gen-rules.ts          rewrite the generated block
//   bun script/gen-rules.ts --check  fail when the block is out of date
//
// Only ids on the allowlist are taken: rules whose token format is self-identifying, so the
// regex alone is high precision. Rules that depend on entropy scoring, keyword proximity or
// per-repo allowlists are skipped — porting them without those guards turns ordinary prose
// into false positives, and in this plugin a false positive silently corrupts a request.

import { readFileSync, writeFileSync } from "node:fs"

const BEGIN = "// BEGIN GENERATED RULES"
const END = "// END GENERATED RULES"
const TOML = "vendor/gitleaks.toml"
const TARGET = "index.ts"

const ALLOW = new Set([
  "1password-service-account-token",
  "age-secret-key",
  "clojars-api-token",
  "databricks-api-token",
  "digitalocean-pat",
  "doppler-api-token",
  "flyio-access-token",
  "gcp-api-key",
  "github-fine-grained-pat",
  "huggingface-access-token",
  "linear-api-key",
  "notion-api-token",
  "perplexity-api-key",
  "planetscale-api-token",
  "postman-api-token",
  "pulumi-api-token",
  "pypi-upload-token",
  "rubygems-api-token",
  "sendgrid-api-token",
  "shopify-access-token",
  "square-access-token",
  "twilio-api-key",
  "vault-service-token",
])

type Rule = { id: string; source: string; flags: string; group: number }

function blocks(toml: string): string[] {
  return toml.split("[[rules]]").slice(1)
}

function field(block: string, name: string): string | undefined {
  const raw = new RegExp(`${name}\\s*=\\s*'''([\\s\\S]*?)'''`).exec(block)
  if (raw) return raw[1].trim()
  const quoted = new RegExp(`${name}\\s*=\\s*"((?:[^"\\\\]|\\\\.)*)"`).exec(block)
  return quoted?.[1]
}

function countGroups(source: string): number {
  let count = 0
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] !== "(") continue
    if (source[index - 1] === "\\") continue
    if (source[index + 1] !== "?") count += 1
  }
  return count
}

function translate(raw: string): { source: string; flags: string } {
  let source = raw
  let flags = "g"

  // JS has no scoped inline flags: widening the whole pattern to /i keeps these prefixed
  // token formats correct.
  if (source.includes("(?i:") || source.includes("(?i)")) flags += "i"
  source = source.replace(/\(\?i:/g, "(").replace(/\(\?i\)/g, "")

  // Common TOML-regex idioms that JavaScript spells differently.
  source = source.replace(/\\z/g, "$")

  return { source, flags }
}

function parse(): { rules: Rule[]; skipped: string[] } {
  const rules: Rule[] = []
  const skipped: string[] = []

  for (const block of blocks(readFileSync(TOML, "utf8"))) {
    const id = /id\s*=\s*"([^"]+)"/.exec(block)?.[1]
    if (!id || !ALLOW.has(id)) continue

    const raw = field(block, "regex")
    if (!raw) {
      skipped.push(`${id}: no regex`)
      continue
    }

    const { source, flags } = translate(raw)
    try {
      new RegExp(source, flags)
    } catch (error) {
      skipped.push(`${id}: ${String(error)}`)
      continue
    }

    const secretGroup = Number(field(block, "secretGroup") ?? 0)
    const group = secretGroup > 0 ? secretGroup : countGroups(source) > 0 ? 1 : 0
    rules.push({ id, source, flags, group })
  }

  rules.sort((a, b) => a.id.localeCompare(b.id))
  return { rules, skipped }
}

function render(rules: Rule[]): string {
  const lines = [
    BEGIN,
    "// Generated from vendor/gitleaks.toml by script/gen-rules.ts — do not edit by hand.",
    "// Only self-identifying token formats; entropy and keyword-dependent rules are excluded.",
    "const GITLEAKS_RULES: { id: string; regex: RegExp; group: number }[] = [",
  ]
  for (const rule of rules) {
    lines.push(
      `  { id: ${JSON.stringify(rule.id)}, regex: new RegExp(${JSON.stringify(rule.source)}, ${JSON.stringify(rule.flags)}), group: ${rule.group} },`,
    )
  }
  lines.push("]", END)
  return lines.join("\n")
}

const { rules, skipped } = parse()
if (skipped.length > 0) {
  for (const line of skipped) console.error(`skipped ${line}`)
}

const index = readFileSync(TARGET, "utf8")
const start = index.indexOf(BEGIN)
const end = index.indexOf(END)
if (start < 0 || end < 0) {
  console.error(`ERROR: ${TARGET} is missing the generated-rules markers`)
  process.exit(1)
}

const next = index.slice(0, start) + render(rules) + index.slice(end + END.length)
const check = process.argv.includes("--check")

if (check) {
  if (next !== index) {
    console.error("ERROR: generated rules are out of date — run: bun script/gen-rules.ts")
    process.exit(1)
  }
  console.log(`generated rules up to date (${rules.length} rules)`)
} else {
  writeFileSync(TARGET, next)
  console.log(`wrote ${rules.length} gitleaks rules into ${TARGET}`)
}
