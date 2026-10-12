# Architecture

## Components

- `frontend/src/ui.tsx`: React account UI, two-person conversation list, composer, packet inspector, and five-second encrypted-history polling.
- `frontend/src/crypto.ts`: browser registry, unbiased CSPRNG sequence selection, canonical packet/AAD encoding, HKDF layer keys, and encrypt/decrypt dispatch.
- `backend/app/main.py`: FastAPI authentication, invitation, membership, packet persistence, and health endpoints. SQLAlchemy uses PostgreSQL in Compose and SQLite locally.
- `backend/app/crypto.py`: Python reference implementation for the same five constructions, independently tested from the client implementation.
- `docker-compose.yml`: local PostgreSQL, relay, and Vite services.

## Message flow

The sender chooses a uniformly random sequence length from 1–5 and chooses each ID from 1–5 using the browser CSPRNG. The sequence is included in the JSON packet. The browser derives a separate HKDF-SHA-256 key for every message layer, authenticates the full packet header plus layer index and ID, and encrypts left-to-right. The receiver reads the authenticated sequence and decrypts right-to-left, showing text only if every layer verifies. The relay stores opaque JSON and serves history; it does not decrypt.

The five entries are AES-256-GCM (Web Crypto), ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-CTR with encrypt-then-HMAC-SHA-256, and AES-256-GCM using an independent implementation. ID 5 is the same cipher as ID 1, included for implementation comparison. IDs 6–8 remain disabled.

## Trust and storage

The relay learns accounts, membership, packet sizes, timing, and senders. It stores password hashes, usernames, room membership, hashed invitation codes, and encrypted packets, but no message keys or client private keys. The manually shared phrase does not authenticate identity. There are no client key backups or recovery.

## Incomplete boundaries

Authenticated X25519 establishment, safety numbers, a reviewed ratchet, live WebSocket fanout/acknowledgement, replay protection, migration management, rate limiting, TLS termination, and a hardened production deployment are not implemented.
