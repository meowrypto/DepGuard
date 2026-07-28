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

  // --- Known wallet targeting ---
  {
    id: 'metamask-extension-id',
    label: 'References a known browser wallet extension ID',
    severity: 'high',
    regex: /nkbihfbeogaeaoehlefnkodbefgpgknn|ejbalbakoplchlghecdalmeeeajnimhm|bfnaelmomeimhlpmgjnjophhpkkoljpa/gi,
    why: 'These are the Chrome extension IDs for MetaMask, Trust Wallet, and Phantom. An unrelated package referencing them is a strong sign it is targeting a browser wallet.',
  },
  {
    id: 'wallet-provider-hook',
    label: 'Hooks or overrides the injected wallet provider',
    severity: 'high',
    regex: /window\.ethereum\s*=|Object\.defineProperty\s*\(\s*window\s*,\s*['"]ethereum['"]/g,
    why: 'Overwriting window.ethereum can intercept or redirect transactions from a legitimate wallet extension.',
  },

  // --- Address-swap clippers ---
  {
    id: 'eth-address-regex',
    label: 'Contains a hardcoded Ethereum address pattern',
    severity: 'medium',
    regex: /0x\[a-fA-F0-9\]\{40\}/g,
    why: 'Building a regex that matches Ethereum addresses is a step used by clipboard-hijacking clippers to detect and swap addresses.',
  },
  {
    id: 'btc-address-regex',
    label: 'Contains a hardcoded Bitcoin address or WIF key pattern',
    severity: 'medium',
    regex: /\[13\]\[a-km-zA-HJ-NP-Z1-9\]\{25,34\}|bc1\[a-z0-9\]\{25,90\}/g,
    why: 'A regex built to match Bitcoin addresses is a common building block for address-swap clipper malware.',
  },
  {
    id: 'clipboard-poll-loop',
    label: 'Polls on a timer while touching the clipboard',
    severity: 'high',
    regex: /setInterval\s*\([^)]{0,80}\)[\s\S]{0,150}clipboard/gi,
    why: 'A recurring timer combined with clipboard access is the shape of a background clipper that watches for copied wallet addresses.',
  },

  // --- Remote-payload execution ---
  {
    id: 'fetch-then-eval',
    label: 'Fetches remote content and executes it dynamically',
    severity: 'high',
    regex: /fetch\([^)]*\)[\s\S]{0,120}\.then\([^)]*=>[^)]{0,80}(eval|Function)\s*\(/gi,
    why: 'Downloading code at runtime and immediately executing it hides the real payload from a static review of the package.',
  },

  // --- Windows LOLBins / persistence ---
  {
    id: 'powershell-encoded-command',
    label: 'Runs an encoded/obfuscated PowerShell command',
    severity: 'high',
    regex: /powershell[^\n]{0,40}(-enc|-EncodedCommand|-e\s)/gi,
    why: 'Base64-encoded PowerShell commands are a common way to hide a malicious payload from casual inspection.',
  },
  {
    id: 'certutil-decode',
    label: 'Uses certutil to decode a payload',
    severity: 'high',
    regex: /certutil[^\n]{0,30}-decode/gi,
    why: 'certutil is a legitimate Windows tool sometimes abused ("living off the land") to decode a hidden payload without downloading extra software.',
  },
  {
    id: 'windows-persistence',
    label: 'Adds a Windows startup/persistence entry',
    severity: 'high',
    regex: /reg(\.exe)?\s+add[^\n]{0,60}\\Run\b|schtasks[^\n]{0,20}\/create/gi,
    why: 'Writing to the Registry Run key or creating a scheduled task are common ways malware survives a reboot.',
  },
];

module.exports = { PATTERNS };
