# opencode-secrets

Toggleable secret and PII masking for [OpenCode](https://opencode.ai). One TypeScript file,
no service, no model, no extra process — masking is local regex plus exact env-value matching,
sub-millisecond per request.

## What it masks

Outgoing JSON request bodies only, and only while the toggle is on:

- provider token formats: AWS, GitHub, GitLab, npm, Slack, Stripe, JWT, PEM private keys,
  Discord, Telegram
- URL credentials (`postgres://user:pass@…`), bearer tokens, emails
- quoted `password` / `secret` / `token` / `api_key` assignments
- the exact values of secret-looking environment variables (`*_TOKEN`, `*_KEY`, `*_SECRET`,
  `*_PASSWORD`, …) from the process that runs OpenCode

It does **not** catch context PII in prose (names, phone numbers, addresses). That needs a NER
model — see [`atomic-235/kiji-pii-flake`](https://github.com/atomic-235/kiji-pii-flake) for the
model-backed variant.

Structural fields (`model`, `providerID`, `id`, `role`, `tool`, paths) and binary payloads
(`data`, `image`, `media`) are never touched.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/atomic-235/opencode-secrets/main/install.sh | sh
```

That copies one file to `${XDG_CONFIG_HOME:-~/.config}/opencode/plugins/secrets.ts`. No config
edits, no build, no package manager.

Then:

```bash
opencode service restart
opencode plugin list     # should list local.secrets-filter
```

Other options:

```bash
# npm, once published
opencode plugin add opencode-secrets

# from a checkout
./install.sh

# uninstall
./install.sh uninstall
```

## Usage

```
/mask            toggle
/mask on         enable masking
/mask off        disable masking
/mask status     report the current state
```

Off by default. The state is stored in plugin storage and survives restarts.

## Development

```bash
bun test        # 12 tests: mask rules, command parsing, body rewriting
```

## Layout

```
index.ts     the plugin (also the whole npm package)
install.sh   one-file installer, remote or from a checkout
```
