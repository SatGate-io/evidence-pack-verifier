# SatGate Evidence Pack Verifier

Open verifier for SatGate Evidence Packs and signed receipts.

It verifies the part that matters to a third party:

1. Fetch an Evidence Pack URL.
2. Discover the issuer JWKS from the receipt issuer origin.
3. RFC8785/JCS canonicalize the receipt while excluding `signature` and `receipt_hash`.
4. Recompute `receipt_hash` with SHA-256.
5. Verify the Ed25519 signature against the issuer public key.
6. Return machine-readable verification output.

## Quick start

```bash
python -m pip install 'satgate-evidence-pack-verifier'

satgate-verify-evidence-pack \
  --discover-jwks \
  --require-trusted-issuer \
  https://api.satgate.io/v1/evidence/evid_LrlgUSR1R3SEYtxy0npX7mgneWZFa5ek
```

Expected output from the live SatGate archive:

```json
{
  "evidence_pack_id": "ep_KTRbpu22e0ZRDSkpJb5KSg",
  "evidence_url": "https://api.satgate.io/v1/evidence/evid_LrlgUSR1R3SEYtxy0npX7mgneWZFa5ek",
  "http_status": 200,
  "issuer": "https://api.satgate.io",
  "issuer_kid": "satgate-gateway-ed25519-2026-05",
  "protocol_profile": "issuer_jwks",
  "reason_codes": [
    "ok"
  ],
  "receipt_hash": "sha256:qz1t4Jt56ncP1CupRxt4PvzGeVh12Na4MEyuOdbjaD4",
  "receipt_id": "rcpt_KTRbpu22e0ZRDSkpJb5KSg",
  "trust_anchor": "issuer_jwks_anchored",
  "trusted_issuer_valid": true,
  "valid": true
}
```

## One-liner curl + verify

```bash
curl -fsS https://api.satgate.io/v1/evidence/evid_LrlgUSR1R3SEYtxy0npX7mgneWZFa5ek >/tmp/satgate-evidence-pack.json \
  && satgate-verify-evidence-pack --discover-jwks --require-trusted-issuer \
    https://api.satgate.io/v1/evidence/evid_LrlgUSR1R3SEYtxy0npX7mgneWZFa5ek
```

The verifier intentionally verifies from the URL, not from local SatGate services. The `curl` line is there so reviewers can inspect the exact artifact before verification.

## Trust model

By default the CLI trusts `https://api.satgate.io` as a known issuer. Add additional trusted issuers with `--trusted-issuer`:

```bash
satgate-verify-evidence-pack --discover-jwks --require-trusted-issuer \
  --trusted-issuer https://issuer.example \
  https://issuer.example/v1/evidence/evid_123
```

If you omit `--require-trusted-issuer`, the verifier can still prove the receipt hash and signature match the issuer key, but it will not fail solely because the issuer is not on your allow-list.

## Output fields

- `valid`: receipt hash and Ed25519 signature verified, and trusted issuer requirement passed if requested.
- `trusted_issuer_valid`: issuer matched the trusted issuer allow-list.
- `protocol_profile`: verification profile used, usually `issuer_jwks`.
- `trust_anchor`: trust anchor used, usually `issuer_jwks_anchored`.
- `http_status`: HTTP status returned by the Evidence Pack URL.
- `reason_codes`: `ok` or failure reasons such as `receipt_hash_mismatch`, `signature_invalid`, or `issuer_not_trusted`.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest -q
```

## License

Apache-2.0.
