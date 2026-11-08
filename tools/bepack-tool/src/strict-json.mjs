import { open } from 'node:fs/promises';

export function parseStrictJSON(bytes, { maxBytes = 4 * 1024 * 1024, maxDepth = 128 } = {}) {
  if (bytes.length > maxBytes) throw new Error('JSON exceeds byte limit');
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new Error('UTF-8 BOM is forbidden');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let i = 0;
  const ws = () => { while (/[\x20\x09\x0a\x0d]/.test(text[i] ?? '\0')) i++; };
  const fail = message => { throw new Error(`${message} at offset ${i}`); };
  function string() {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === '"') {
        const parsed = JSON.parse(text.slice(start, i));
        if (!parsed.isWellFormed()) fail('Unpaired Unicode surrogate');
        return parsed;
      }
      if (c === '\\') i++;
    }
    fail('Unterminated string');
  }
  function value(depth) {
    if (depth > maxDepth) fail('JSON nesting limit exceeded');
    ws();
    if (text[i] === '{') {
      i++; ws(); const keys = new Set();
      if (text[i] === '}') { i++; return; }
      while (i < text.length) {
        if (text[i] !== '"') fail('Object key expected');
        const key = string();
        if (keys.has(key)) fail(`Duplicate key ${JSON.stringify(key)}`);
        keys.add(key); ws(); if (text[i++] !== ':') fail('Colon expected');
        value(depth + 1); ws();
        if (text[i] === '}') { i++; return; }
        if (text[i++] !== ',') fail('Comma expected'); ws();
      }
      fail('Unterminated object');
    }
    if (text[i] === '[') {
      i++; ws(); if (text[i] === ']') { i++; return; }
      while (i < text.length) {
        value(depth + 1); ws(); if (text[i] === ']') { i++; return; }
        if (text[i++] !== ',') fail('Comma expected');
      }
      fail('Unterminated array');
    }
    if (text[i] === '"') { string(); return; }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
    if (!match) fail('JSON value expected');
    i += match[0].length;
  }
  value(0); ws(); if (i !== text.length) fail('Trailing JSON bytes');
  const result = JSON.parse(text);
  if (!result || typeof result !== 'object' || Array.isArray(result)) fail('Root must be an object');
  return result;
}

export async function readStrictJSON(file, options = {}) {
  const maxBytes = options.maxBytes ?? 4 * 1024 * 1024;
  const handle = await open(file, 'r');
  try {
    if ((await handle.stat()).size > maxBytes) throw new Error('JSON exceeds byte limit');
    const buffer = Buffer.alloc(maxBytes + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, null);
      if (!bytesRead) break;
      size += bytesRead;
    }
    return parseStrictJSON(buffer.subarray(0, size), options);
  } finally { await handle.close(); }
}