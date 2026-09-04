from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from backend.app.pipeline.ingestion.external.dark_web_connector import DarkWebConfigurationError, load_dark_web_config


class DarkWebReadinessTests(unittest.TestCase):
    def test_dark_web_config_allows_env_override_for_tor_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dark_web_sources.local.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "proxy": {"host": "127.0.0.1", "port": 9150},
                        "sources": [
                            {
                                "id": "example-dark-source",
                                "name": "Example dark source",
                                "url": "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/advisories/",
                                "enabled": True,
                                "category": "dark_web_cti",
                                "allowed_paths": ["/advisories/"],
                                "max_items": 5,
                                "rate_limit_seconds": 0.1,
                                "trusted_curated": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            proxy, sources = load_dark_web_config(path, environ={"TOR_PROXY_HOST": "tor", "TOR_PROXY_PORT": "9050"})

        self.assertEqual(proxy.host, "tor")
        self.assertEqual(proxy.port, 9050)
        self.assertEqual(sources[0].source_id, "example-dark-source")
        self.assertTrue(sources[0].enabled)

    def test_missing_runtime_dark_web_config_raises_clear_error(self) -> None:
        missing = Path("/this/path/does/not/exist/dark_web_sources.local.json")
        with self.assertRaises(DarkWebConfigurationError):
            load_dark_web_config(missing)

    def test_dark_web_feature_flag_allows_non_dark_sources_without_local_config(self) -> None:
        from backend.app.pipeline.ingestion.external.integration import local

        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "missing-dark-web-config.json"
            self.assertFalse(config.exists())
            with mock.patch.dict("os.environ", {"EXTERNAL_API_TOKEN": "test-token", "EXTERNAL_API_ROLES": "operator"}, clear=False):
                enabled = local.build_local_app(
                    dark_web_config_path=config,
                    dark_web_client=None,
                    state_directory=Path(directory) / "state",
                    processed_directory=Path(directory) / "processed",
                    review_directory=Path(directory) / "review",
                    exports_directory=Path(directory) / "exports",
                    export_state_path=Path(directory) / "state" / "export_runs.json",
                    manual_state_path=Path(directory) / "state" / "manual_sources.json",
                    manual_checkpoint_path=Path(directory) / "state" / "manual_checkpoints.json",
                )
        self.assertIsNotNone(enabled)

    def test_vps_compose_declares_tor_service_health_and_proxy_env(self) -> None:
        compose_path = Path(__file__).resolve().parents[1] / "infra" / "vps" / "compose.yaml"
        with compose_path.open("r", encoding="utf-8") as handle:
            compose = yaml.safe_load(handle)

        services = compose.get("services", {})
        tor = services["tor"]
        external = services["external-sources"]

        self.assertIn("tor", services)
        self.assertNotIn("ports", tor)
        self.assertNotIn("command", tor)
        self.assertEqual(tor["image"], "dperson/torproxy@sha256:d161ddddd47b4d2a91b8fe93d61e81b0760c0452ab6983a35ed37452e24004f6")
        self.assertEqual(tor["cap_drop"], ["ALL"])
        self.assertEqual(tor["cap_add"], ["CHOWN", "SETUID", "SETGID"])
        self.assertIn("healthcheck", tor)
        self.assertEqual(external["environment"]["TOR_PROXY_HOST"], "tor")
        self.assertEqual(external["environment"]["TOR_PROXY_PORT"], "9050")
        self.assertEqual(external["environment"]["EXTERNAL_DARK_WEB_ENABLED"], "${EXTERNAL_DARK_WEB_ENABLED:-false}")
        self.assertEqual(external["environment"]["EXTERNAL_DARK_WEB_CONFIG_PATH"], "/app/config/dark_web_sources.local.json")
        self.assertEqual(external["depends_on"]["tor"]["condition"], "service_healthy")
        self.assertEqual(
            external["networks"],
            {
                "external_egress": {},
                "cti_backend_external": {"aliases": ["cti-external-control"]},
            },
        )
        self.assertEqual(tor["networks"], ["external_egress"])


if __name__ == "__main__":
    unittest.main()
