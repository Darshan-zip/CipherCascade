# Threat model

## Assets and adversaries

Assets: plaintext at endpoints, manually shared phrase, account credentials/tokens, room membership, encrypted packets, and participant identity. Consider network observers, readers/modifiers of relay storage, packet replayers/injectors, unauthorized room joiners, and disconnect/reconnect attackers.

## Trust boundaries and mitigations

The browser is intended to encrypt before sending; the FastAPI relay enforces account/room membership and stores opaque packets. TLS is required for real deployments but is not configured by this local Compose stack. AEAD in the Python protocol core detects ciphertext, nonce, sequence, and bound-header modification. Room authorization and two-member limits resist casual unauthorized joins. Unique packet IDs reject duplicate storage.

These mitigations are partial: the browser's shared phrase does not authenticate the peer, the relay has no actual WebSocket packet forwarding, and duplicate IDs are not ratchet replay protection. The backend can validate a sender claim only against the logged-in relay identity, not prove it to the other client.

## Known exposure and out-of-scope

The relay sees usernames, membership, packet sizes/timing, sender, and conversation activity. It can drop, delay, reorder, or withhold packets. The implementation does not provide forward secrecy, post-compromise security, out-of-order ratchet support, or identity safety numbers.

Out of scope: compromised devices, keyloggers, malicious browser code/web hosting, stolen credentials, a participant disclosing messages, traffic analysis, and coercion. An active attacker able to substitute the shared phrase or compromise the web origin can defeat confidentiality. This experimental protocol is not independently reviewed and is not production secure.
