# Security notes

## Implemented properties

- Five explicit client and Python constructions: AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-CTR plus encrypt-then-HMAC, and a second AES-GCM implementation. ID 5 repeats the cipher in ID 1 and is an implementation comparison.
- Web Crypto CSPRNG sampling produces random sequence lengths 1–5 and ID selections 1–5. Layer keys are separately derived by HKDF-SHA-256 with conversation, sender, message number, layer position, and algorithm ID in context.
- Protocol/registry versions, conversation, sender, message number, sequence, layer order, and algorithm ID are authenticated. Decryption stops on any invalid layer and does not return partial plaintext.
- The relay persists opaque packets and does not possess the message phrase or derived keys.
- Passwords use PBKDF2-HMAC-SHA-256 with random 128-bit salts and 310,000 rounds. Relay tokens are HMAC-SHA-256 signed and expire after 24 hours. Room membership is checked, invitation codes are stored hashed, and rooms cap membership at two.

## Important limitations

No independent protocol review has occurred. Manual phrase entry is not authenticated key exchange and HKDF is not a password-hardening KDF; phrase strength and out-of-band verification matter. No X25519 identity check, safety number, ratchet, forward secrecy, or post-compromise security exists. Randomly varying the sequence does not add a security guarantee; ID 5 is a duplicate AES cipher. Live WebSocket delivery, replay defense, migrations, rate limiting, production TLS setup, dependency audit automation, and comprehensive end-to-end attack tests are absent. The demo bearer token is in localStorage. Do not use for sensitive communications.

Nonces come from the browser/Python CSPRNG. Keys are derived per message/layer and IDs use the nonce sizes in the registry. The prototype has no persistent ratchet state or collision tracking. Default development secrets are unsafe outside local use.

## Logging and incident handling

The client logs only a rejected-packet error name, never message text or keys. Do not log plaintext, passwords, tokens, private keys, session secrets, or message keys. If a shared phrase is exposed, both participants must choose and exchange a new phrase out-of-band; previously captured messages do not gain forward secrecy.
