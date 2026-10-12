# Protocol v2 (experimental)

## Registry v2

| ID | Exact construction | Key / nonce | Authentication | Browser / reference implementation |
|---|---|---|---|---|
| 1 | AES-256-GCM | 32 / 12 bytes | 16-byte AEAD tag | Web Crypto / `cryptography` |
| 2 | IETF ChaCha20-Poly1305 | 32 / 12 bytes | 16-byte Poly1305 tag | `@noble/ciphers` 2.4.0 / `cryptography` |
| 3 | XChaCha20-Poly1305 | 32 / 24 bytes | 16-byte Poly1305 tag | `@noble/ciphers` 2.4.0 / PyNaCl libsodium |
| 4 | AES-256-CTR + HMAC-SHA-256, encrypt-then-MAC | 64 derived bytes split into separate 32-byte AES and HMAC keys / 16-byte counter block | 32-byte HMAC, verified before CTR decryption | Web Crypto / `cryptography` |
| 5 | AES-256-GCM, implementation comparison (same cipher as ID 1) | 32 / 12 bytes | 16-byte AEAD tag | `@noble/ciphers` 2.4.0 / PyCryptodome 3.24.0 |

IDs 6–8 remain disabled. The registry is fixed code; incoming IDs select only among these explicit implementations and never load executable code. Both clients must use protocol and registry version 2. Older v1 packets are rejected.

## Key context and sequence generation

The UI asks each participant to enter the same manual phrase locally. It is the HKDF input key material; no phrase or derived key is sent to the relay. For each layer, HKDF-SHA-256 derives 32 bytes (IDs 1, 2, 3, 5) or 64 bytes (ID 4) using empty salt and canonical JSON info `["CipherCascade", 2, conversation_id, sender_id, message_number, layer_index, algorithm_id]`. ID 4 splits its output into AES and HMAC keys.

For each outgoing message, Web Crypto's CSPRNG supplies unbiased choices: sequence length is uniform from 1 through 5, and each position is selected uniformly from IDs 1 through 5. Repeats are allowed. Random sequence selection is not a security guarantee and does not make the cascade stronger by itself.

## Packet, AAD, and cascade

Packets contain protocol/registry versions, conversation ID, sender ID, message number, the algorithm sequence, and one ordered layer per sequence entry. Each layer includes algorithm ID, URL-safe base64 nonce, and ciphertext; ID 4 additionally has a separate HMAC tag. For AEAD entries the tag is appended to ciphertext as defined by the implementation API.

Canonical authenticated data is UTF-8 compact JSON with recursively sorted object keys and preserved array order, encoding `{header, layer_index, algorithm_id}`. The full header includes the sequence. ID 4 computes HMAC-SHA-256 over `CipherCascade-v2-ID4-ETM\0 || uint32be(aad_length) || aad || nonce || ciphertext`, using its independent HMAC key. The receiver validates metadata, sequence, layer count/IDs, nonce sizes, and version, then authenticates and decrypts in reverse order. Any failure aborts; plaintext is returned only after all layers pass.

Maximum packet size is 1 MiB; maximum sequence length is five. The relay checks the authenticated sender, conversation, version, supported ID range, and sequence/layer correspondence. It does not decrypt packets or prove sender identity cryptographically to the recipient because both participants know the shared phrase.

## Replay and key evolution

The relay rejects duplicate `(conversation, message_id)` storage. This is storage idempotency, not cryptographic replay defense. The message number is a timestamp in the client; counters, skipped-message keys, out-of-order handling, stale packet rejection, reconnect recovery, and a send/receive ratchet are not implemented. Current phrase compromise exposes messages encrypted with it.

This custom protocol has not received independent cryptographic review and is not a replacement for an established secure messaging protocol.
