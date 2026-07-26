# DepGuard

Scan your installed npm dependencies for **crypto-stealer style behavior** — clipboard hijacking, seed-phrase hunting, exfiltration to Discord/Telegram/Pastebin, obfuscated payloads, and postinstall scripts that fetch-and-run — before you trust them.

Supply-chain attacks that target crypto wallets are a real and growing threat: a compromised or typosquatted npm package doesn't need to be sophisticated, it just needs to read your clipboard or your `.env` file once. DepGuard is a small, dependency-free heuristic scanner you can run locally or in CI to catch the most common patterns those attacks share.

**DepGuard is a heuristic tool, not a guarantee.** A finding means "this deserves a human look," not "this is malware." It will have false positives (a legitimate crypto library will trip the seed-phrase pattern) and it can be evaded by a determined attacker. Use it as one more check, not your only one.

## Install

No install needed — run it directly:

```bash
npx depguard
```

Or install as a dev dependency:

```bash
npm install --save-dev depguard
```

## Usage

```bash
# Scan node_modules in the current directory (default)
npx depguard

# Scan a specific directory
npx depguard ./some-folder

# Only fail (exit code 1) on medium severity or above — useful for stricter CI
npx depguard node_modules --fail-on medium

# Output machine-readable JSON
npx depguard node_modules --json > report.json
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

## Contributing

Pattern suggestions are very welcome — if you've seen a real attack use a technique not covered here, please open an issue or PR with a (sanitized, non-functional) example. See [`lib/patterns.js`](./lib/patterns.js) for the pattern format.

## License

MIT — see [LICENSE](./LICENSE).
