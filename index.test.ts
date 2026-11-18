import { describe, expect, mock, test } from "bun:test"

// The plugin imports the opencode SDK; stub it so the pure logic can be tested standalone.
mock.module("@opencode/plugin", () => ({ Plugin: { define: (plugin: unknown) => plugin } }))

process.env.SECRETS_TEST_API_KEY = "secrets-test-1234567890"

const { applyStrings, collectStrings, maskText, parseCommand, redactBody } = await import(
  "./index.ts"
)

describe("maskText", () => {
  test("masks structured provider tokens", () => {
    expect(maskText("key=[REDACTED:aws]")).toBe("key=[REDACTED:aws]")
    expect(maskText("[REDACTED:github]")).toBe("[REDACTED:github]")
    expect(maskText("[REDACTED:gitlab]")).toBe("[REDACTED:gitlab]")
    expect(maskText("[REDACTED:npm]")).toBe("[REDACTED:npm]")
    expect(maskText("[REDACTED:slack]")).toBe("[REDACTED:slack]")
    expect(maskText("[REDACTED:stripe]")).toBe("[REDACTED:stripe]")
  })

  test("masks emails and jwt", () => {
    expect(maskText("write to [REDACTED:email] please")).toBe("write to [REDACTED:email] please")
    expect(maskText("token [REDACTED:jwt]")).toBe("token [REDACTED:jwt]")
  })

  test("masks url credentials and bearer tokens", () => {
    const creds = "u:passw0rd"
    const bearer = "AbCdEf0123456789XyZq"
    expect(maskText(`postgres://${creds}@db:5432/app`)).toBe(
      "postgres[REDACTED:urlcreds]db:5432/app",
    )
    expect(maskText(`Authorization: Bearer ${bearer}`)).toBe("Authorization: [REDACTED:bearer]")
  })

  test("masks quoted assignments", () => {
    expect(maskText('password: "hunter2secret"')).toBe('password: "[REDACTED:secret]"')
    expect(maskText('api_key = "abcdef123456"')).toBe('api_key = "[REDACTED:secret]"')
  })

  test("masks exact values of secret-looking env vars", () => {
    expect(maskText("the key is secrets-test-1234567890 here")).toBe("the key is [REDACTED:env] here")
  })

  test("leaves ordinary text and hashes alone", () => {
    expect(maskText("The build finished in 4.2 seconds")).toBe("The build finished in 4.2 seconds")
    expect(maskText("f3a1c9d2e4b7a6c5d8e9f0a1b2c3d4e5f6a7b8c9")).toBe(
      "f3a1c9d2e4b7a6c5d8e9f0a1b2c3d4e5f6a7b8c9",
    )
  })
})

describe("parseCommand", () => {
  test("parses /mask", () => {
    expect(parseCommand("/mask")).toBe("toggle")
    expect(parseCommand("/mask on")).toBe("on")
    expect(parseCommand("/mask off")).toBe("off")
    expect(parseCommand("/mask status")).toBe("status")
  })

  test("parses the markdown command body", () => {
    expect(parseCommand("Secrets masking: on")).toBe("on")
    expect(parseCommand("Secrets masking: off")).toBe("off")
    expect(parseCommand("Secrets masking: ")).toBe("toggle")
  })

  test("ignores unrelated text and unknown arguments", () => {
    expect(parseCommand("hello")).toBeNull()
    expect(parseCommand("/compact")).toBeNull()
    expect(parseCommand("/mask maybe")).toBeNull()
  })
})

describe("body handling", () => {
  test("collects only content fields", () => {
    const payload = {
      model: "deepseek-v4-1-flash-1017",
      messages: [{ role: "user", content: "mail [REDACTED:email]" }],
    }
    expect(collectStrings(payload)).toEqual(["mail [REDACTED:email]"])
  })

  test("rewrites the body, never the structural fields", async () => {
    const body = JSON.stringify({
      model: "m",
      messages: [{ content: "key=AKIAIOSFODNN7EXAMPLE mail someone@example.org" }],
    })
    const out = await redactBody(body, async (texts) => texts.map(maskText))
    expect(out).not.toBeNull()
    const parsed = JSON.parse(out!)
    expect(parsed.model).toBe("m")
    expect(parsed.messages[0].content).toBe("key=[REDACTED:aws] mail [REDACTED:email]")
  })

  test("returns null when nothing matches", async () => {
    const body = JSON.stringify({ messages: [{ content: "The build finished in 4.2 seconds" }] })
    expect(await redactBody(body, async (texts) => texts.map(maskText))).toBeNull()
  })
})
