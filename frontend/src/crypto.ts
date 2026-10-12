import { ctr, gcm } from '@noble/ciphers/aes.js';
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha.js';

export const REGISTRY = {
  1: { name: 'AES-256-GCM', nonceBytes: 12, support: 'Web Crypto' },
  2: { name: 'ChaCha20-Poly1305', nonceBytes: 12, support: '@noble/ciphers' },
  3: { name: 'XChaCha20-Poly1305', nonceBytes: 24, support: '@noble/ciphers' },
  4: { name: 'AES-256-CTR + HMAC-SHA-256', nonceBytes: 16, support: 'Web Crypto' },
  5: { name: 'AES-256-GCM (independent implementation)', nonceBytes: 12, support: '@noble/ciphers' },
} as const;
const PROTOCOL_VERSION = 2 as const;
const REGISTRY_VERSION = 2 as const;
export type AlgorithmId = keyof typeof REGISTRY;
export type Packet = {
  protocol_version: 2; registry_version: 2; conversation_id: string; sender_id: string;
  message_number: number; algorithm_sequence: AlgorithmId[];
  layers: { algorithm_id: AlgorithmId; nonce: string; ciphertext: string; tag?: string }[];
};
const MAX_PACKET_BYTES = 1_048_576;
const te = new TextEncoder();
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const toB64 = (bytes: Uint8Array) => {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
};
const fromB64 = (value: string) => {
  if (typeof value !== 'string' || value.length > 1_500_000) throw new Error('invalid encoding');
  const raw = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(raw, c => c.charCodeAt(0));
};
const stable = (v: any): any => Array.isArray(v) ? v.map(stable) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, stable(v[k])])) : v;
export const canonical = (v: unknown) => te.encode(JSON.stringify(stable(v)));

// Uniform selection using rejection sampling over the CSPRNG's 32-bit output.
function secureIndex(length: number): number {
  const ceiling = Math.floor(0x1_0000_0000 / length) * length;
  const word = new Uint32Array(1);
  let n: number;
  do { crypto.getRandomValues(word); n = word[0]; } while (n >= ceiling);
  return n % length;
}
export function randomSequence(): AlgorithmId[] {
  const ids = [1, 2, 3, 4, 5] as const;
  const length = secureIndex(5) + 1;
  return Array.from({ length }, () => ids[secureIndex(ids.length)]);
}

async function layerKey(secret: string, cid: string, sender: string, n: number, index: number, aid: AlgorithmId) {
  const ikm = await crypto.subtle.importKey('raw', te.encode(secret), 'HKDF', false, ['deriveBits']);
  const info = canonical(['CipherCascade', PROTOCOL_VERSION, cid, sender, n, index, aid]);
  const length = aid === 4 ? 512 : 256;
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info }, ikm, length);
  return new Uint8Array(bits);
}
async function hmacKey(raw: Uint8Array, usage: KeyUsage[]) {
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, usage);
}
function aadFor(header: Omit<Packet, 'layers'>, index: number, aid: AlgorithmId) {
  return canonical({ header, layer_index: index, algorithm_id: aid });
}
async function encryptLayer(aid: AlgorithmId, keyMaterial: Uint8Array, nonce: Uint8Array, input: Uint8Array, aad: Uint8Array) {
  if (aid === 1) {
    const key = await crypto.subtle.importKey('raw', keyMaterial, 'AES-GCM', false, ['encrypt']);
    return { ciphertext: new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, input)) };
  }
  if (aid === 2) return { ciphertext: chacha20poly1305(keyMaterial, nonce, aad).encrypt(input) };
  if (aid === 3) return { ciphertext: xchacha20poly1305(keyMaterial, nonce, aad).encrypt(input) };
  if (aid === 4) {
    const cipher = ctr(keyMaterial.subarray(0, 32), nonce).encrypt(input);
    const macKey = await hmacKey(keyMaterial.subarray(32), ['sign']);
    const frame = concat(te.encode('CipherCascade-v2-ID4-ETM\0'), new Uint8Array([aad.length >>> 24, aad.length >>> 16, aad.length >>> 8, aad.length]), aad, nonce, cipher);
    return { ciphertext: cipher, tag: new Uint8Array(await crypto.subtle.sign('HMAC', macKey, frame)) };
  }
  return { ciphertext: gcm(keyMaterial, nonce, aad).encrypt(input) };
}
async function decryptLayer(aid: AlgorithmId, keyMaterial: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array | undefined, aad: Uint8Array) {
  if (aid === 1) {
    const key = await crypto.subtle.importKey('raw', keyMaterial, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, ciphertext));
  }
  if (aid === 2) return chacha20poly1305(keyMaterial, nonce, aad).decrypt(ciphertext);
  if (aid === 3) return xchacha20poly1305(keyMaterial, nonce, aad).decrypt(ciphertext);
  if (aid === 4) {
    if (!tag || tag.length !== 32) throw new Error('invalid authentication tag');
    const macKey = await hmacKey(keyMaterial.subarray(32), ['verify']);
    const frame = concat(te.encode('CipherCascade-v2-ID4-ETM\0'), new Uint8Array([aad.length >>> 24, aad.length >>> 16, aad.length >>> 8, aad.length]), aad, nonce, ciphertext);
    if (!await crypto.subtle.verify('HMAC', macKey, tag, frame)) throw new Error('authentication failed');
    return ctr(keyMaterial.subarray(0, 32), nonce).decrypt(ciphertext);
  }
  return gcm(keyMaterial, nonce, aad).decrypt(ciphertext);
}
export async function encryptMessage(plaintext: string, sequence: AlgorithmId[], cid: string, sender: string, number: number, secret: string): Promise<Packet> {
  if (!Array.isArray(sequence) || sequence.length < 1 || sequence.length > 5 || sequence.some(id => !Object.hasOwn(REGISTRY, id))) throw new Error('unsupported sequence');
  const header = { protocol_version: PROTOCOL_VERSION, registry_version: REGISTRY_VERSION, conversation_id: cid, sender_id: sender, message_number: number, algorithm_sequence: sequence };
  let data = te.encode(plaintext);
  const layers: Packet['layers'] = [];
  for (let i = 0; i < sequence.length; i++) {
    const aid = sequence[i];
    const nonce = crypto.getRandomValues(new Uint8Array(REGISTRY[aid].nonceBytes));
    const result = await encryptLayer(aid, await layerKey(secret, cid, sender, number, i, aid), nonce, data, aadFor(header, i, aid));
    data = result.ciphertext;
    layers.push({ algorithm_id: aid, nonce: toB64(nonce), ciphertext: toB64(result.ciphertext), ...(result.tag ? { tag: toB64(result.tag) } : {}) });
  }
  const packet = { ...header, layers };
  if (te.encode(JSON.stringify(packet)).length > MAX_PACKET_BYTES) throw new Error('message exceeds packet limit');
  return packet;
}
export async function decryptMessage(packet: Packet, cid: string, sender: string, secret: string): Promise<string> {
  if (!packet || typeof packet !== 'object') throw new Error('invalid packet: missing packet object');
  if (JSON.stringify(packet).length > MAX_PACKET_BYTES) throw new Error('invalid packet: exceeds size limit');
  if (packet.protocol_version !== PROTOCOL_VERSION || packet.registry_version !== REGISTRY_VERSION) throw new Error(`unsupported packet version (protocol ${String(packet.protocol_version)}, registry ${String(packet.registry_version)}; expected ${PROTOCOL_VERSION}/${REGISTRY_VERSION})`);
  if (packet.conversation_id !== cid) throw new Error('packet conversation does not match the open conversation');
  if (packet.sender_id !== sender) throw new Error('packet sender does not match relay sender');
  if (!Number.isSafeInteger(packet.message_number) || packet.message_number < 0) throw new Error('invalid packet message number');
  const seq = packet.algorithm_sequence;
  if (!Array.isArray(seq) || seq.length < 1 || seq.length > 5 || !Array.isArray(packet.layers) || packet.layers.length !== seq.length) throw new Error('invalid packet sequence');
  const header = { protocol_version: packet.protocol_version, registry_version: packet.registry_version, conversation_id: packet.conversation_id, sender_id: packet.sender_id, message_number: packet.message_number, algorithm_sequence: seq };
  let data: Uint8Array | undefined;
  for (let i = seq.length - 1; i >= 0; i--) {
    const aid = seq[i]; const layer = packet.layers[i];
    if (!Object.hasOwn(REGISTRY, aid) || layer.algorithm_id !== aid) throw new Error('unsupported or inconsistent algorithm');
    const nonce = fromB64(layer.nonce); const ciphertext = fromB64(layer.ciphertext); const tag = layer.tag ? fromB64(layer.tag) : undefined;
    if (nonce.length !== REGISTRY[aid].nonceBytes) throw new Error('invalid nonce length');
    data = await decryptLayer(aid, await layerKey(secret, cid, sender, packet.message_number, i, aid), nonce, ciphertext, tag, aadFor(header, i, aid));
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(data!);
}
