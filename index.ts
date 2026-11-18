import { Plugin } from "@opencode/plugin"

// Secret and PII masking for OpenCode, with no service, no model and no extra process.
//
// `/mask` toggles, `/mask on|off` sets, `/mask status` reports. Off by default; the flag is
// stored in plugin storage and survives restarts. Masking runs on outgoing JSON request
// bodies only, and only while the flag is on.
//
// Catches provider token formats (AWS, GitHub, GitLab, npm, Slack, Stripe, JWT, PEM,
// Discord, Telegram), URL credentials, bearer tokens, emails, quoted
// password/secret/token assignments, and the exact values of secret-looking env vars.
// It does not catch context PII (names, phones, addresses in prose).

const BINARY_KEYS = new Set(["data", "media", "base64", "image"])

// Fields that identify the request itself. Masking any of these breaks the call:
// a masked top-level `model` produced "Specified model not found: [REDACTED:...]".
const STRUCTURAL_KEYS = new Set([
  "model",
  "modelID",
  "providerID",
  "provider",
  "variant",
  "agent",
  "id",
  "sessionID",
  "messageID",
  "callID",
  "tool",
  "toolName",
  "name",
  "role",
  "type",
  "mime",
  "filename",
  "filePath",
  "path",
  "directory",
  "worktree",
  "version",
  "baseURL",
])

const MIN_LENGTH = 4
const MAX_LENGTH = 20_000

const ENV_EXCLUDE = new Set([
  "PWD",
  "SECRETS_DIR",
  "SSH_AUTH_SOCK",
  "SSH_ASKPASS",
  "GPG_TTY",
  "GNUPGHOME",
  "XDG_RUNTIME_DIR",
  "HYPRLAND_INSTANCE_SIGNATURE",
  "DBUS_SESSION_BUS_ADDRESS",
  "STARSHIP_SESSION_KEY",
  "OPENCODE_SESSION_ID",
  "OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX",
  "MANAGERPID",
  "MANAGERPIDFDID",
])

const SECRET_NAME = /(TOKEN|KEY|SECRET|PASSWORD|PASSWD|PWD|API_KEY|APIKEY|AUTH|CREDENTIAL|DSN|WEBHOOK|PRIVATE)/i

const ENV_VALUES = Object.entries(process.env)
  .filter(
    ([name, value]) =>
      !!value && value.length >= 8 && SECRET_NAME.test(name) && !ENV_EXCLUDE.has(name),
  )
  .map(([, value]) => value)
  .sort((a, b) => b.length - a.length)

const RULES: [string, RegExp][] = [
  ["aws", /AKIA[0-9A-Z]{16}/g],
  ["github", /gh[pousr]_[A-Za-z0-9]{36,}/g],
  ["openai", /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g],
  ["anthropic", /sk-ant-[A-Za-z0-9_-]{20,}/g],
  ["slack", /xox[baprs]-[A-Za-z0-9-]{10,}/g],
  ["stripe", /sk_live_[A-Za-z0-9]{20,}/g],
  ["jwt", /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g],
  ["pem", /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----/g],
  ["npm", /npm_[A-Za-z0-9]{30,}/g],
  ["gitlab", /glpat-[A-Za-z0-9_-]{20,}/g],
  ["discord", /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g],
  ["telegram", /\d{8,10}:[A-Za-z0-9_-]{35}/g],
  ["urlcreds", /:\/\/[^:\s/]+:[^@\s/]+@/g],
  ["bearer", /bearer\s+[A-Za-z0-9._-]{16,}/gi],
  ["email", /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi],
]

/** Mask every recognised secret or PII pattern in a single string. */
export function maskText(value: string): string {
  let out = value
  for (const secret of ENV_VALUES) out = out.split(secret).join("[REDACTED:env]")
  for (const [label, rule] of RULES) out = out.replace(rule, `[REDACTED:${label}]`)
  out = out.replace(
    /((?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*["'])([^"']{6,})(["'])/gi,
    "$1[REDACTED:secret]$3",
  )
  return out
}

export type Command = "on" | "off" | "toggle" | "status"

const ON_WORDS = new Set(["on", "enable", "true", "start"])
const OFF_WORDS = new Set(["off", "disable", "false", "stop"])

/** Parse a user message for a mask toggle. Returns null when it is not a command. */
export function parseCommand(text: string): Command | null {
  const normalized = (text ?? "").trim().toLowerCase().replace(/\s+/g, " ")
  if (!normalized) return null

  // A markdown command body arrives as "Secrets masking: <arg>".
  const template = /^secrets masking:[ \t]*(\S*)/.exec(normalized)
  if (template) {
    const argument = template[1]
    if (!argument) return "toggle"
    if (argument === "status") return "status"
    if (ON_WORDS.has(argument)) return "on"
    if (OFF_WORDS.has(argument)) return "off"
    return null
  }

  const parts = normalized.replace(/^\//, "").split(" ")
  if (parts[0] !== "mask") return null

  const argument = parts[1]
  if (!argument) return "toggle"
  if (argument === "status") return "status"
  if (ON_WORDS.has(argument)) return "on"
  if (OFF_WORDS.has(argument)) return "off"
  return null
}

/** Collect every maskable string in a request body, deduplicated and in order. */
export function collectStrings(value: unknown): string[] {
  const found: string[] = []
  const seen = new Set<string>()

  const walk = (node: unknown): void => {
    if (typeof node === "string") {
      if (node.length >= MIN_LENGTH && node.length <= MAX_LENGTH && !seen.has(node)) {
        seen.add(node)
        found.push(node)
      }
      return
    }
    if (Array.isArray(node)) {
      for (const item of node) walk(item)
      return
    }
    if (node && typeof node === "object") {
      for (const [key, item] of Object.entries(node)) {
        if (BINARY_KEYS.has(key) || STRUCTURAL_KEYS.has(key)) continue
        walk(item)
      }
    }
  }

  walk(value)
  return found
}

/** Return a copy of the payload with every exact match in `map` replaced. */
export function applyStrings(value: unknown, map: Map<string, string>): unknown {
  if (typeof value === "string") return map.get(value) ?? value
  if (Array.isArray(value)) return value.map((item) => applyStrings(item, map))
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value)) {
      out[key] = BINARY_KEYS.has(key) || STRUCTURAL_KEYS.has(key) ? item : applyStrings(item, map)
    }
    return out
  }
  return value
}

/** Mask an outgoing JSON request body. Returns the rewritten body, or null when unchanged. */
export async function redactBody(
  body: string,
  redact: (texts: string[]) => Promise<string[] | null>,
): Promise<string | null> {
  let payload: unknown
  try {
    payload = JSON.parse(body)
  } catch {
    return null
  }

  const texts = collectStrings(payload)
  if (texts.length === 0) return null

  const redacted = await redact(texts)
  if (!redacted || redacted.length !== texts.length) return null

  const map = new Map<string, string>()
  for (let index = 0; index < texts.length; index += 1) {
    if (redacted[index] !== texts[index]) map.set(texts[index], redacted[index])
  }
  if (map.size === 0) return null

  return JSON.stringify(applyStrings(payload, map))
}

const STORAGE_KEY = "secrets.enabled"

let enabled = false

export default Plugin.define({
  id: "local.secrets-filter",
  async setup(ctx) {
    enabled = (await ctx.storage.get(STORAGE_KEY)) === true

    const setEnabled = async (next: boolean) => {
      enabled = next
      await ctx.storage.set(STORAGE_KEY, enabled)
    }

    const statusLine = () => `Secrets masking is ${enabled ? "on" : "off"}.`

    try {
      await ctx.command.transform((editor) => {
        editor.add({
          name: "mask",
          description: "Toggle secret and PII masking (on|off|status)",
          execute: async ({ sessionID, prompt }) => {
            const argument = (prompt?.text ?? "").trim()
            const command =
              parseCommand(argument) ?? parseCommand(`/mask ${argument}`) ?? "toggle"

            if (command !== "status") {
              await setEnabled(command === "toggle" ? !enabled : command === "on")
            }

            try {
              await ctx.session.synthetic({
                sessionID,
                payload: { text: statusLine() },
                delivery: "queue",
              } as any)
            } catch {
              // Feedback is best-effort; the flag change is the part that matters.
            }
          },
        })
      })
    } catch {
      // Older server without the command API: the prompt hook still handles text commands.
    }

    // Natural language and markdown command bodies.
    await ctx.session.hook("prompt", async (event) => {
      const command = parseCommand(event.prompt.text)
      if (!command) return

      if (command !== "status") await setEnabled(command === "toggle" ? !enabled : command === "on")

      event.prompt.text = `${statusLine()} Reply with that one line and nothing else.`
    })

    await ctx.session.hook("http.request", async (event) => {
      if (!enabled) return

      const contentType = event.request.headers.get("content-type") ?? ""
      if (!contentType.includes("json")) return

      const body = await event.request.clone().text()
      const masked = await redactBody(body, async (texts) => texts.map(maskText))
      if (!masked) return

      const headers = new Headers(event.request.headers)
      headers.delete("content-length")
      event.request = new Request(event.request, { headers, body: masked })
    })
  },
})
