# DepGuard

[![npm version](https://img.shields.io/npm/v/%40meowrypto%2Fdepguard.svg)](https://www.npmjs.com/package/@meowrypto/depguard)
[![npm downloads](https://img.shields.io/npm/dm/%40meowrypto%2Fdepguard.svg)](https://www.npmjs.com/package/@meowrypto/depguard)
[![CI](https://github.com/meowrypto/DepGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/meowrypto/DepGuard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/npm/l/%40meowrypto%2Fdepguard.svg)](./LICENSE)
[![Support this project](https://img.shields.io/badge/%E2%98%95_support-donatr.ee-orange)](https://donatr.ee/meowrypto/)

## Technocore / Flop Labs Agent Identity

This tool can help AI agents and developers working in the **Technocore** ecosystem stay safer by scanning dependencies for common crypto-stealer patterns (seed phrases, clipboard hijacking, exfiltration, etc.).

**Agent DID:**  
`did:key:z6MkuPZgxFLFL1UXm4XG5GvRKxVyKJippTLSkkFL3SoiA7pe`

Built with ❤️ for the agentic economy.  
Mentions: [@flop_labs](https://x.com/flop_labs) · [Technocore](https://technocore.chat)

---

Scan your installed npm dependencies for **crypto-stealer style behavior** — clipboard hijacking, seed-phrase hunting, exfiltration to Discord/Telegram/Pastebin, obfuscated payloads, and postinstall scripts that fetch-and-run — before you trust them.

Supply-chain attacks that target crypto wallets are a real and growing threat: a compromised or typosquatted npm package doesn't need to be sophisticated, it just needs to read your clipboard or your `.env` file once. DepGuard is a small, dependency-free heuristic scanner you can run locally or in CI to catch the most common patterns those attacks share.

**DepGuard is a heuristic tool, not a guarantee.** A finding means "this deserves a human look," not "this is malware." It will have false positives (a legitimate crypto library will trip the seed-phrase pattern) and it can be evaded by a determined attacker. Use it as one more check, not your only one.

## Install

No install needed — run it directly:

```bash
npx @meowrypto/depguard
```

Or install as a dev dependency:

```bash
npm install --save-dev @meowrypto/depguard
```

## Usage

```bash
# Scan node_modules in the current directory (default)
npx @meowrypto/depguard

# Scan a specific directory
npx @meowrypto/depguard ./some-folder

# Only fail (exit code 1) on medium severity or above — useful for stricter CI
npx @meowrypto/depguard node_modules --fail-on medium

# Output machine-readable JSON
npx @meowrypto/depguard node_modules --json > report.json
```

Exit code is `0` when nothing at or above the `--fail-on` threshold (default: `high`) is found, and `1` otherwise — so it plugs straight into CI.

## What it looks for

| Category | Examples |
|---|---|
| Clipboard access | reading/writing the clipboard (classic wallet-address swap attack) |
| Seed phrase / key hunting | BIP39 wordlist references, `wallet.dat`, `privateKey =` |
| Exfiltration channels | Discord webhooks, Telegram Bot API, Pastebin, raw IP requests |
| Obfuscation | `eval()`, `new Function()`, base64-decode-then-execute |
| Install-time execution | `postinstall`/`preinstall` scripts that `curl`/`wget` and run something |
| Credential harvesting | bulk `process.env` reads |

See [`lib/patterns.js`](./lib/patterns.js) for the full, commented list — every pattern includes a one-line explanation of why it's flagged.

## Using it in CI

Copy [`examples/depguard-action.yml`](./examples/depguard-action.yml) into your repo at `.github/workflows/depguard.yml` to scan your dependencies on every PR and push to `main`.

## Why this exists

Most supply-chain security tools are built for large teams and paid tiers. DepGuard is meant to be the thing a solo developer or a small open-source crypto project can drop in for free in under a minute, with zero configuration and zero dependencies of its own.
It is also useful for AI agents operating in environments like Technocore, where protecting keys and seed material is critical.

## Contributing

Pattern suggestions are very welcome — use the [New pattern suggestion](https://github.com/meowrypto/DepGuard/issues/new?template=pattern_suggestion.yml) issue form. If DepGuard flags something that isn't actually malicious, please use the [False positive report](https://github.com/meowrypto/DepGuard/issues/new?template=false_positive.yml) form so it can be tuned. See [`lib/patterns.js`](./lib/patterns.js) for the pattern format.

## Support

If DepGuard helped you catch something, or you just want to support ongoing development, you can donate here: [donatr.ee/meowrypto](https://donatr.ee/meowrypto/)

<img src="./assets/donate-qr.gif" alt="Donation QR code" width="150" />

## License

MIT — see [LICENSE](./LICENSE).
