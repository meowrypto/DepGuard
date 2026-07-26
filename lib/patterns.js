'use strict';

/**
 * Each pattern:
 *  - id: short unique key
 *  - label: human description
 *  - severity: 'high' | 'medium' | 'low'
 *  - regex: what to look for in file contents
 *  - why: short explanation shown in the report
 */

const PATTERNS = [
  // --- Clipboard access (classic wallet-address-swap malware) ---
  {
    id: 'clipboard-read',
    label: 'Reads the system clipboard',
    severity: 'high',
    regex: /navigator\.clipboard\.readText|clipboardy\.read|clipboard-read/gi,
    why: 'Malware often reads the clipboard to detect and swap copied crypto wallet addresses.',
  },
  {
    id: 'clipboard-write',
    label: 'Writes to the system clipboard',
    severity: 'medium',
    regex: /navigator\.clipboard\.writeText|clipboardy\.write/gi,
    why: 'Used to silently replace a copied wallet address with an attacker-controlled one.',
  },

  // --- Seed phrase / private key hunting ---
  {
    id: 'seed-phrase-regex',
    label: 'Contains a BIP39 seed-phrase-like word list or matcher',
    severity: 'high',
    regex: /mnemonic|seed\s*phrase|bip39|wordlist/gi,
    why: 'Legit crypto libraries use these terms too, but in an unrelated package this is a red flag.',
  },
  {
    id: 'private-key-pattern',
    label: 'Matches private-key / wallet-file patterns',
    severity: 'high',
    regex: /wallet\.dat|\.env\b.*key|privateKey\s*[:=]|keystore/gi,
    why: 'Code that searches for wallet files or private keys on disk.',
  },

  // --- Exfiltration channels ---
  {
    id: 'discord-webhook',
    label: 'Sends data to a Discord webhook',
    severity: 'high',
    regex: /discord(app)?\.com\/api\/webhooks/gi,
    why: 'A very common, hard-to-block exfiltration channel used by info-stealers.',
  },
  {
    id: 'telegram-bot-api',
    label: 'Talks to the Telegram Bot API',
    severity: 'medium',
    regex: /api\.telegram\.org\/bot/gi,
    why: 'Telegram bots are frequently used as a covert command-and-control / exfiltration channel.',
  },
  {
    id: 'pastebin',
    label: 'References Pastebin or similar paste sites',
    severity: 'medium',
    regex: /pastebin\.com|paste\.ee|hastebin\.com/gi,
    why: 'Sometimes used to fetch a second-stage payload after install.',
  },
  {
    id: 'raw-ip-request',
    label: 'Makes a network request to a raw IP address',
    severity: 'medium',
    regex: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/g,
    why: 'Legitimate packages almost always talk to named domains, not bare IPs.',
  },

  // --- Obfuscation / dynamic execution ---
  {
    id: 'eval-usage',
    label: 'Uses eval()',
    severity: 'medium',
    regex: /\beval\s*\(/g,
    why: 'eval() can run dynamically-decoded code, hiding the real payload from a static read.',
  },
  {
    id: 'function-constructor',
    label: 'Builds code via the Function constructor',
    severity: 'medium',
    regex: /new\s+Function\s*\(/g,
    why: 'Another way to execute obfuscated or remotely-fetched code.',
  },
  {
    id: 'base64-decode-exec',
    label: 'Decodes base64 and immediately executes it',
    severity: 'high',
    regex: /Buffer\.from\([^)]*['"]base64['"]\)[^;]{0,40}(eval|exec|Function)/gi,
    why: 'A common obfuscation trick: hide the payload as base64, decode and run it at install time.',
  },

  // --- Install-time execution ---
  {
    id: 'postinstall-curl',
    label: 'A lifecycle script downloads and runs something',
    severity: 'high',
    regex: /(postinstall|preinstall)[\s\S]{0,120}(curl|wget|Invoke-WebRequest)/gi,
    why: 'npm install/postinstall scripts that fetch and run remote code can install anything, silently.',
  },

  // --- Process / env scraping ---
  {
    id: 'env-dump',
    label: 'Reads and could exfiltrate the full environment',
    severity: 'medium',
    regex: /process\.env(?!\.[A-Z_]+\b)/g,
    why: 'Reading all of process.env (rather than one named variable) can be a sign of credential harvesting.',
  },
];

module.exports = { PATTERNS };
