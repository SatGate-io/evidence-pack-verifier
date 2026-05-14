from __future__ import annotations

import json
from pathlib import Path

import responses

from evidence_pack_verifier.verifier import verify_evidence_pack

FIXTURES = Path(__file__).parent / "fixtures"
EVIDENCE_URL = "https://api.satgate.io/v1/evidence/evid_LrlgUSR1R3SEYtxy0npX7mgneWZFa5ek"
JWKS_URL = "https://api.satgate.io/.well-known/jwks.json"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


@responses.activate
def test_verify_live_fixture_with_jwks_discovery() -> None:
    responses.get(EVIDENCE_URL, body=fixture("evidence-pack.json"), status=200)
    responses.get(JWKS_URL, body=fixture("jwks.json"), status=200)

    result = verify_evidence_pack(
        EVIDENCE_URL,
        discover_jwks=True,
        require_trusted_issuer=True,
    )

    assert result.valid is True
    assert result.trusted_issuer_valid is True
    assert result.protocol_profile == "issuer_jwks"
    assert result.trust_anchor == "issuer_jwks_anchored"
    assert result.http_status == 200
    assert result.reason_codes == ["ok"]
    assert result.receipt_hash == "sha256:qz1t4Jt56ncP1CupRxt4PvzGeVh12Na4MEyuOdbjaD4"


@responses.activate
def test_tampered_receipt_hash_fails() -> None:
    pack = json.loads(fixture("evidence-pack.json"))
    pack["receipts"][0]["decision_reason"] = "tampered"
    responses.get(EVIDENCE_URL, json=pack, status=200)
    responses.get(JWKS_URL, body=fixture("jwks.json"), status=200)

    result = verify_evidence_pack(EVIDENCE_URL, discover_jwks=True)

    assert result.valid is False
    assert "receipt_hash_mismatch" in result.reason_codes


@responses.activate
def test_require_trusted_issuer_fails_when_issuer_not_allowed() -> None:
    responses.get(EVIDENCE_URL, body=fixture("evidence-pack.json"), status=200)

    result = verify_evidence_pack(
        EVIDENCE_URL,
        discover_jwks=False,
        require_trusted_issuer=True,
        trusted_issuers={"https://issuer.example"},
    )

    assert result.valid is False
    assert result.trusted_issuer_valid is False
    assert "issuer_not_trusted" in result.reason_codes
