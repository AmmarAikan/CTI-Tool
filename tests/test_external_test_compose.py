from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "compose.external-test.yml"
SOURCES_PATH = ROOT / "config" / "sources.external-test.json"
APPROVED_SOURCES_PATH = ROOT / "config" / "sources.json"


class ExternalTestComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = COMPOSE_PATH.read_text(encoding="utf-8")
        cls.compose = json.loads(cls.raw)

    def test_only_frontend_is_published_on_loopback(self) -> None:
        self.assertEqual(self.compose["name"], "${COMPOSE_PROJECT_NAME:-cti-ext-readiness}")
        self.assertEqual(
            self.compose["services"]["frontend"]["ports"],
            ["127.0.0.1:19080:8080"],
        )
        for service in ("db", "backend", "external-sources", "tor"):
            with self.subTest(service=service):
                self.assertNotIn("ports", self.compose["services"][service])
        self.assertNotIn("19000", self.raw)
        self.assertNotIn("19090", self.raw)

    def test_contains_only_test_services_and_no_fixed_container_names(self) -> None:
        self.assertEqual(
            set(self.compose["services"]),
            {"db", "backend", "external-sources", "tor", "frontend"},
        )
        for service in self.compose["services"].values():
            self.assertNotIn("container_name", service)

    def test_service_networks_are_internal_and_special_networks_are_single_service(self) -> None:
        self.assertEqual(
            set(self.compose["networks"]),
            {"test_database", "test_backend_external", "test_frontend_backend", "test_ingress", "test_external_egress"},
        )
        for name in ("test_database", "test_backend_external", "test_frontend_backend"):
            network = self.compose["networks"][name]
            self.assertIs(network.get("internal"), True)
            self.assertNotIn("external", network)
            self.assertNotIn("name", network)
        for name in ("test_ingress", "test_external_egress"):
            network = self.compose["networks"][name]
            self.assertIsNot(network.get("internal"), True)
            self.assertNotIn("external", network)
            self.assertNotIn("name", network)
        self.assertIn("test_ingress", self.compose["services"]["frontend"]["networks"])
        for service in ("db", "backend", "external-sources", "tor"):
            with self.subTest(service=service):
                self.assertNotIn("test_ingress", self.compose["services"][service]["networks"])
        self.assertIn("test_external_egress", self.compose["services"]["external-sources"]["networks"])
        for service in ("db", "backend", "frontend"):
            with self.subTest(service=service):
                self.assertNotIn("test_external_egress", self.compose["services"][service]["networks"])

    def test_volumes_are_test_only_project_resources(self) -> None:
        self.assertEqual(
            set(self.compose["volumes"]),
            {"test_postgres", "test_uploads", "test_external_data", "test_external_logs"},
        )
        for volume in self.compose["volumes"].values():
            self.assertNotIn("external", volume)
            self.assertNotIn("name", volume)

    def test_has_no_production_paths_or_resource_names(self) -> None:
        forbidden = (
            "/etc/cti-platform",
            "cti-backend-gateway",
            "cti-backend-external",
            "cti-backend-misp",
            "gateway_data",
            "dionaea_data",
            "cti_postgres_data",
            "tailscale",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, self.raw.lower())

    def test_backend_uses_the_test_external_service_url(self) -> None:
        environment = self.compose["services"]["backend"]["environment"]
        self.assertEqual(
            environment["EXTERNAL_CONTROL_API_URL"],
            "http://cti-external-control:8000/api/v1/external-sources",
        )
        self.assertEqual(environment["EXTERNAL_CONTROL_ALLOW_HTTP"], "true")
        aliases = self.compose["services"]["external-sources"]["networks"][
            "test_backend_external"
        ]["aliases"]
        self.assertEqual(aliases, ["cti-external-control"])

    def test_live_registry_is_exactly_the_approved_public_configuration(self) -> None:
        registry = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        approved = json.loads(APPROVED_SOURCES_PATH.read_text(encoding="utf-8"))
        self.assertEqual(registry["schema_version"], "1.0")
        self.assertEqual(registry, approved)
        for section, sources in registry.items():
            if section in {"schema_version", "github_sources"}:
                continue
            self.assertTrue(sources, section)
            self.assertTrue(all(source["enabled"] is True for source in sources), section)
        self.assertTrue(all(source["transport"] == "rss_with_browser_fallback"
                            for source in registry["social_media_sources"]))
        self.assertTrue(all(source["transport"] == "telegram_public_preview"
                            for source in registry["telegram_sources"]))
        mounts = self.compose["services"]["external-sources"]["volumes"]
        self.assertIn(
            "./config/sources.external-test.json:/app/config/sources.json:ro",
            mounts,
        )

    def test_runtime_services_preserve_security_controls(self) -> None:
        for name in ("backend", "external-sources", "frontend"):
            service = self.compose["services"][name]
            with self.subTest(service=name):
                self.assertIs(service["read_only"], True)
                self.assertEqual(service["cap_drop"], ["ALL"])
                self.assertIn("no-new-privileges:true", service["security_opt"])

    def test_tor_is_digest_pinned_internal_only_and_external_depends_on_health(self) -> None:
        tor = self.compose["services"]["tor"]
        self.assertRegex(tor["image"], r"@sha256:[0-9a-f]{64}$")
        self.assertNotIn("ports", tor)
        self.assertNotIn("init", tor)
        self.assertNotIn("read_only", tor)
        self.assertNotIn("user", tor)
        self.assertEqual(tor["cap_drop"], ["ALL"])
        self.assertEqual(tor["cap_add"], ["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE"])
        self.assertNotIn("NET_ADMIN", tor["cap_add"])
        self.assertIn("no-new-privileges:true", tor["security_opt"])
        self.assertEqual(set(tor["networks"]), {"test_external_egress"})
        self.assertEqual(tor["networks"]["test_external_egress"]["aliases"], ["tor"])
        external = self.compose["services"]["external-sources"]
        self.assertEqual(external["environment"]["TOR_PROXY_HOST"], "tor")
        self.assertEqual(external["environment"]["TOR_PROXY_PORT"], "9050")
        self.assertEqual(external["depends_on"]["tor"]["condition"], "service_healthy")
        self.assertNotIn("5353", json.dumps(tor.get("command")))

    def test_dark_web_test_configs_are_read_only_empty_templates(self) -> None:
        mounts = self.compose["services"]["external-sources"]["volumes"]
        for name in ("dark_web_sources.external-test.json", "dark_web_discovery_providers.external-test.json"):
            self.assertTrue(any(name in mount and mount.endswith(":ro") for mount in mounts))
            value = json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], "1.0")
            self.assertNotIn(".onion", json.dumps(value).lower())


if __name__ == "__main__":
    unittest.main()
