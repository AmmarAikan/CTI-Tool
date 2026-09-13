from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile.external"


class ExternalImagePermissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    def test_immutable_application_tree_has_deterministic_permissions(self) -> None:
        paths = "/app/backend /app/contracts /app/config"
        self.assertIn(
            f"chown -R --no-dereference 0:0 {paths}",
            self.dockerfile,
        )
        self.assertIn(
            f"find {paths} -xdev -type d -exec chmod 0755 {{}} +",
            self.dockerfile,
        )
        self.assertIn(
            f"find {paths} -xdev -type f -exec chmod 0644 {{}} +",
            self.dockerfile,
        )

    def test_runtime_user_can_import_but_cannot_write_application_code(self) -> None:
        self.assertIn("USER 10001:10001", self.dockerfile)
        self.assertNotIn("USER root", self.dockerfile)
        self.assertIn('test "$(id -u)" = 10001', self.dockerfile)
        self.assertIn('test "$(id -g)" = 10001', self.dockerfile)
        for path in (
            "/app/backend/app",
            "/app/backend/app/pipeline/ingestion/external",
        ):
            self.assertIn(f"test -r {path}", self.dockerfile)
            self.assertIn(f"test -x {path}", self.dockerfile)
            self.assertIn(f"test ! -w {path}", self.dockerfile)
        module = "/app/backend/app/pipeline/ingestion/external/application/dark_web_discovery.py"
        self.assertIn(f"test -r {module}", self.dockerfile)
        self.assertIn(f"test ! -w {module}", self.dockerfile)
        self.assertIn(
            "from backend.app.pipeline.ingestion.external.application.dark_web_discovery "
            "import load_discovery_providers",
            self.dockerfile,
        )
        self.assertIn(
            "from backend.app.pipeline.ingestion.external.dark_web_connector "
            "import load_dark_web_config",
            self.dockerfile,
        )

    def test_writable_runtime_paths_remain_scoped_to_state_and_logs(self) -> None:
        self.assertIn("chown -R 10001:10001 /app/data/external /app/logs", self.dockerfile)
        self.assertNotIn("chown -R 10001:10001 /app/backend", self.dockerfile)


if __name__ == "__main__":
    unittest.main()
