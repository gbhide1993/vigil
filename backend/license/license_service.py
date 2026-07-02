"""RSA-2048 signed local license validation. Fully offline — no phone
home, no network calls. The license file is a JSON payload plus a
base64 RSA-PSS/SHA-256 signature, verified against a public key baked
into the app. If no license file is found, the service falls back to a
14-day trial (1 agent, 24h retention) starting from first run.

License file format (.vlaw-license), JSON:
{
  "payload": {
    "product": "vlaw",
    "plan": "trial" | "team_node" | "sovereign_node" | "enterprise",
    "node_count": <int>,
    "issued_at": "<ISO8601>",
    "expires_at": "<ISO8601>" | null
  },
  "signature": "<base64>"
}
"""

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

LICENSE_FILE = Path(os.environ.get("VLAW_LICENSE_FILE", "./.vlaw-license"))

# Public key used to verify license files. The matching private key is
# held offline by V-LAW's license issuer — never shipped with the app.
VLAW_PUBLIC_KEY_PEM = os.environ.get("VLAW_PUBLIC_KEY_PEM", "")

TRIAL_DAYS = 14
TRIAL_AGENT_LIMIT = 1
TRIAL_RETENTION_HOURS = 24

VALID_PLANS = {"trial", "team_node", "sovereign_node", "enterprise"}


@dataclass
class LicenseStatus:
    valid: bool
    plan: str
    node_count: int
    expires_at: datetime | None
    is_trial: bool
    trial_started_at: datetime | None = None
    agent_limit: int | None = None
    retention_hours: int | None = None
    reason: str = ""

    @property
    def expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


class LicenseService:
    def __init__(self):
        self._trial_marker_path = LICENSE_FILE.parent / ".vlaw-trial-started"

    def get_status(self) -> LicenseStatus:
        if LICENSE_FILE.exists():
            status = self._validate_license_file()
            if status is not None:
                return status
            # invalid/corrupt license file — fall through to trial so
            # the app still starts, but the reason is preserved for /health

        return self._get_trial_status()

    def _validate_license_file(self) -> LicenseStatus | None:
        try:
            raw = json.loads(LICENSE_FILE.read_text())
            payload = raw["payload"]
            signature = base64.b64decode(raw["signature"])
        except (json.JSONDecodeError, KeyError, ValueError):
            return LicenseStatus(
                valid=False, plan="trial", node_count=0, expires_at=None,
                is_trial=True, reason="license_file_malformed",
            )

        if not self._verify_signature(payload, signature):
            return LicenseStatus(
                valid=False, plan="trial", node_count=0, expires_at=None,
                is_trial=True, reason="signature_invalid",
            )

        if payload.get("product") != "vlaw":
            return LicenseStatus(
                valid=False, plan="trial", node_count=0, expires_at=None,
                is_trial=True, reason="wrong_product",
            )

        plan = payload.get("plan")
        if plan not in VALID_PLANS:
            return LicenseStatus(
                valid=False, plan="trial", node_count=0, expires_at=None,
                is_trial=True, reason="invalid_plan",
            )

        expires_at = None
        if payload.get("expires_at"):
            expires_at = datetime.fromisoformat(payload["expires_at"])
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

        node_count = int(payload.get("node_count", 1))

        status = LicenseStatus(
            valid=True, plan=plan, node_count=node_count, expires_at=expires_at,
            is_trial=(plan == "trial"), reason="ok",
        )
        return status

    def _verify_signature(self, payload: dict, signature: bytes) -> bool:
        if not VLAW_PUBLIC_KEY_PEM:
            return False

        try:
            public_key = serialization.load_pem_public_key(VLAW_PUBLIC_KEY_PEM.encode())
            message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    def _get_trial_status(self) -> LicenseStatus:
        trial_started_at = self._get_or_set_trial_start()
        expires_at = trial_started_at + timedelta(days=TRIAL_DAYS)

        return LicenseStatus(
            valid=True,
            plan="trial",
            node_count=1,
            expires_at=expires_at,
            is_trial=True,
            trial_started_at=trial_started_at,
            agent_limit=TRIAL_AGENT_LIMIT,
            retention_hours=TRIAL_RETENTION_HOURS,
            reason="no_license_file" if not LICENSE_FILE.exists() else "fallback_after_invalid",
        )

    def _get_or_set_trial_start(self) -> datetime:
        """Trial start is persisted to a marker file on first run so the
        14-day window survives restarts and can't be reset by deleting
        just the DB."""
        if self._trial_marker_path.exists():
            iso = self._trial_marker_path.read_text().strip()
            return datetime.fromisoformat(iso)

        now = datetime.now(timezone.utc)
        self._trial_marker_path.parent.mkdir(parents=True, exist_ok=True)
        self._trial_marker_path.write_text(now.isoformat())
        return now
