from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_COMPOSE = ROOT / "compose.yaml"
PRODUCTION_COMPOSE = ROOT / "infra" / "vps" / "central.compose.yaml"
DEPLOY = ROOT / "infra" / "vps" / "scripts" / "deploy_central_stack.sh"
ROLLBACK = ROOT / "infra" / "vps" / "scripts" / "rollback_central_stack.sh"
TAILSCALE = ROOT / "infra" / "vps" / "scripts" / "configure_tailscale_serve.sh"
DEPLOY_MISP = ROOT / "infra" / "vps" / "scripts" / "deploy_misp.sh"


def render_production() -> dict:
    environment = os.environ.copy()
    environment.update(
        {
            "POSTGRES_DB": "synthetic_db",
            "POSTGRES_USER": "synthetic_user",
            "POSTGRES_PASSWORD": "synthetic_password",
            "JWT_SECRET": "synthetic_jwt_secret",
            "BOOTSTRAP_ADMIN_PASSWORD": "synthetic_admin_password",
            "CTI_COMPOSE_PROJECT_NAME": "cti-test",
            "CTI_NER_MODEL_DIR": str(ROOT / "ml" / "models" / "dnrti_bert_ner"),
            "CTI_NER_REPORT_DIR": str(ROOT / "ml" / "reports"),
        }
    )
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(BASE_COMPOSE),
            "-f",
            str(PRODUCTION_COMPOSE),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(completed.stdout)


class VPSProductionDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = render_production()
        cls.deploy = DEPLOY.read_text(encoding="utf-8")
        cls.rollback = ROLLBACK.read_text(encoding="utf-8")
        cls.tailscale = TAILSCALE.read_text(encoding="utf-8")
        cls.deploy_misp = DEPLOY_MISP.read_text(encoding="utf-8")

    def test_production_images_and_ports_are_stable_and_loopback_only(self) -> None:
        self.assertEqual(self.compose["name"], "cti-test")
        self.assertEqual(self.compose["services"]["backend"]["image"], "cti-central-backend:current")
        self.assertEqual(self.compose["services"]["frontend"]["image"], "cti-central-frontend:current")
        self.assertEqual(self.compose["services"]["backend"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(self.compose["services"]["frontend"]["ports"][0]["host_ip"], "127.0.0.1")

    def test_backend_model_mounts_are_read_only_and_runtime_is_hardened(self) -> None:
        backend = self.compose["services"]["backend"]
        targets = {item["target"]: item for item in backend["volumes"]}
        self.assertTrue(targets["/app/ml/models/dnrti_bert_ner"]["read_only"])
        self.assertTrue(targets["/app/ml/reports"]["read_only"])
        self.assertTrue(backend["read_only"])
        self.assertEqual(backend["cap_drop"], ["ALL"])
        self.assertEqual(backend["environment"]["CTI_APP_ENV"], "production")

    def test_deploy_backs_up_and_validates_database_before_runtime_cutover(self) -> None:
        backup = self.deploy.index("pg_dump -Fc")
        validate = self.deploy.index("pg_restore --list")
        build = self.deploy.index('"${compose[@]}" build backend frontend')
        cutover = self.deploy.index('"${compose[@]}" up -d --no-deps backend')
        self.assertLess(backup, validate)
        self.assertLess(validate, build)
        self.assertLess(build, cutover)
        self.assertNotIn(" down", self.deploy)
        self.assertNotIn("volume rm", self.deploy)
        self.assertNotIn("POSTGRES_PASSWORD", self.deploy)

    def test_rollback_never_restores_or_replaces_postgresql(self) -> None:
        self.assertIn("PostgreSQL was not replaced", self.rollback)
        self.assertNotIn("pg_restore", self.rollback)
        self.assertNotIn(" service=db", self.rollback)
        self.assertNotIn("volume", self.rollback.lower())

    def test_tailscale_serve_exposes_frontend_and_never_enables_funnel(self) -> None:
        self.assertIn('--https=443 "http://127.0.0.1:${frontend_port}"', self.tailscale)
        self.assertIn("--https=8445 http://127.0.0.1:8088", self.tailscale)
        self.assertNotIn("tailscale funnel", self.tailscale)
        self.assertNotIn("serve reset", self.tailscale)

    def test_misp_client_fragment_uses_only_the_pairwise_alias(self) -> None:
        self.assertIn("MISP_URL=http://cti-misp", self.deploy_misp)
        self.assertIn("MISP_ALLOW_HTTP=true", self.deploy_misp)
        self.assertIn("MISP_VERIFY_TLS=true", self.deploy_misp)
        self.assertNotIn("MISP_VERIFY_TLS=false", self.deploy_misp)


if __name__ == "__main__":
    unittest.main()
