# Testing

## Commands

```powershell
cd backend
python -m pytest -q
cd ..\frontend
npm test
npm run build
```

The Python suite covers round-trips across each enabled ID, cascades through five layers, Unicode/empty input, metadata and ciphertext mutations, ID 4 MAC rejection, unsupported IDs, layer key separation, registry status, and generated sequence bounds. The Vitest suite covers browser round-trips for every ID, representative multi-layer sequences, random sequence limits, and rejection of sequence/counter/nonce/ciphertext/MAC tampering.

## Gaps

Official per-algorithm known-answer fixtures, browser-to-Python fixed packet interoperability vectors, two real browser clients, X25519/safety-number checks, ratchet/replay/out-of-order tests, and comprehensive packet fuzzing are still missing. Test success is not evidence of protocol security. The protocol has not been independently reviewed.
