from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CENTRAL_COMPOSE = ROOT / "compose.yaml"
VPS_COMPOSE = ROOT / "infra" / "vps" / "compose.yaml"
MISP_OVERRIDE = ROOT / "infra" / "vps" / "misp" / "compose.override.yaml"
BOOTSTRAP = ROOT / "infra" / "vps" / "scripts" / "bootstrap_host.sh"
PROVISIONER = ROOT / "infra" / "vps" / "scripts" / "provision_backend_networks.sh"
GENERATOR = ROOT / "infra" / "vps" / "scripts" / "generate_backend_client_fragment.sh"
DEPLOY_STACK = ROOT / "infra" / "vps" / "scripts" / "deploy_stack.sh"
NETWORKS = {
    "cti_backend_gateway": "cti-backend-gateway",
    "cti_backend_external": "cti-backend-external",
}
SYNTHETIC = {
    "POSTGRES_DB": "synthetic_db",
    "POSTGRES_USER": "synthetic_user",
    "POSTGRES_PASSWORD": "synthetic_password",
    "JWT_SECRET": "synthetic_jwt_secret",
    "BOOTSTRAP_ADMIN_PASSWORD": "synthetic_admin_password",
    "FEED_PUBLISH_TOKEN": "synthetic_publish_token",
    "FEED_READ_TOKEN": "synthetic_read_token",
    "FEED_RESPONSE_HMAC_SECRET": "synthetic_feed_hmac",
    "SENSOR_READ_TOKEN": "synthetic_sensor_token",
    "SENSOR_RESPONSE_HMAC_SECRET": "synthetic_sensor_hmac",
    "CURSOR_HMAC_SECRET": "synthetic_cursor_hmac",
    "EXTERNAL_CONTROL_TOKEN": "synthetic_external_token",
}


def render_compose(path: Path) -> dict:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("MISP_") or name.startswith("WAZUH_"):
            environment.pop(name)
    environment.pop("COMPOSE_PROJECT_NAME", None)
    environment.update(SYNTHETIC)
    completed = subprocess.run(
        ["docker", "compose", "-f", str(path), "config", "--format", "json"],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(completed.stdout)


def service_networks(compose: dict, service: str) -> dict:
    return compose["services"][service].get("networks", {})


def published_ports(compose: dict, service: str) -> set[tuple[str, str, int, str]]:
    return {
        (
            str(item.get("host_ip", "")),
            str(item.get("published", "")),
            int(item["target"]),
            str(item.get("protocol", "tcp")),
        )
        for item in compose["services"][service].get("ports", [])
    }


class VPSLocalNetworkTopologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.central = render_compose(CENTRAL_COMPOSE)
        cls.vps = render_compose(VPS_COMPOSE)
        cls.bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        cls.provisioner = PROVISIONER.read_text(encoding="utf-8")
        cls.generator = GENERATOR.read_text(encoding="utf-8")
        cls.deploy_stack = DEPLOY_STACK.read_text(encoding="utf-8")
        cls.misp_override = MISP_OVERRIDE.read_text(encoding="utf-8")

    def test_pairwise_networks_render_as_stable_external_networks(self) -> None:
        for key, stable_name in NETWORKS.items():
            for compose in (self.central, self.vps):
                with self.subTest(network=stable_name):
                    definition = compose["networks"][key]
                    self.assertIs(definition["external"], True)
                    self.assertEqual(definition["name"], stable_name)

    def test_rendered_membership_is_exactly_pairwise(self) -> None:
        membership: dict[str, set[str]] = {key: set() for key in NETWORKS}
        for deployment, compose in (("central", self.central), ("vps", self.vps)):
            for service in compose["services"]:
                for network in service_networks(compose, service):
                    if network in membership:
                        membership[network].add(f"{deployment}:{service}")
        self.assertEqual(membership["cti_backend_gateway"], {"central:backend", "vps:gateway"})
        self.assertEqual(
            membership["cti_backend_external"],
            {"central:backend", "vps:external-sources"},
        )

    def test_rendered_aliases_are_exact(self) -> None:
        backend = service_networks(self.central, "backend")
        gateway = service_networks(self.vps, "gateway")
        external = service_networks(self.vps, "external-sources")
        self.assertEqual(backend["cti_backend_gateway"]["aliases"], ["cti-backend"])
        self.assertEqual(backend["cti_backend_external"]["aliases"], ["cti-backend"])
        self.assertEqual(gateway["cti_backend_gateway"]["aliases"], ["cti-gateway"])
        self.assertEqual(external["cti_backend_external"]["aliases"], ["cti-external-control"])

    def test_rendered_published_ports_are_unchanged_and_pairwise_ports_are_internal(self) -> None:
        self.assertEqual(
            published_ports(self.central, "backend"),
            {("127.0.0.1", "8000", 8000, "tcp")},
        )
        self.assertEqual(
            published_ports(self.vps, "gateway"),
            {("127.0.0.1", "8088", 8080, "tcp")},
        )
        self.assertEqual(
            published_ports(self.vps, "external-sources"),
            {("127.0.0.1", "8090", 8000, "tcp")},
        )

    def test_rendered_forbidden_services_are_not_members(self) -> None:
        forbidden = {"db", "adminer", "dionaea", "tor", "redis", "misp", "misp-core", "misp-modules"}
        for compose in (self.central, self.vps):
            for service in forbidden.intersection(compose["services"]):
                self.assertTrue(NETWORKS.keys().isdisjoint(service_networks(compose, service)))

    def test_rendered_misp_and_wazuh_defaults_remain_unchanged(self) -> None:
        environment = self.central["services"]["backend"]["environment"]
        self.assertEqual(environment["MISP_URL"], "")
        self.assertEqual(environment["MISP_API_KEY"], "")
        self.assertEqual(environment["MISP_VERIFY_TLS"], "true")
        self.assertEqual(environment["MISP_ALLOW_HTTP"], "false")
        self.assertEqual(environment["WAZUH_INDEXER_URL"], "")
        self.assertEqual(environment["WAZUH_INDEXER_USERNAME"], "")
        self.assertEqual(environment["WAZUH_INDEXER_PASSWORD"], "")
        self.assertEqual(environment["WAZUH_INDEXER_TOKEN"], "")

    def test_provisioner_is_internal_idempotent_and_non_destructive(self) -> None:
        self.assertIn("docker network create --driver bridge --internal", self.provisioner)
        self.assertIn('docker network ls --filter "name=^${network_name}$"', self.provisioner)
        self.assertIn("Unable to list Docker networks", self.provisioner)
        self.assertIn("unauthorized attached container", self.provisioner)
        self.assertIn("more than one ${service} container", self.provisioner)
        self.assertNotIn("docker network rm", self.provisioner)
        self.assertNotIn("docker network disconnect", self.provisioner)
        for stable_name in NETWORKS.values():
            self.assertEqual(self.provisioner.count(f"ensure_network {stable_name}"), 1)
        self.assertIn('"${script_dir}/provision_backend_networks.sh"', self.bootstrap)

    def test_generator_is_atomic_exactly_scoped_and_uses_local_targets(self) -> None:
        self.assertIn('mktemp "${client_dir}/.backend-integrations.env.XXXXXX"', self.generator)
        self.assertIn("trap cleanup EXIT", self.generator)
        self.assertIn("trap 'exit 130' INT", self.generator)
        self.assertIn("trap 'exit 143' TERM", self.generator)
        self.assertIn('chown root:root "${temporary}"', self.generator)
        self.assertIn('chmod 0600 "${temporary}"', self.generator)
        self.assertIn('mv -f -- "${temporary}" "${target}"', self.generator)
        self.assertNotIn("*.env", self.generator)
        expected = {
            "EXTERNAL_FEED_URL=http://cti-gateway:8080/api/v1/external-feed",
            "DIONAEA_API_URL=http://cti-gateway:8080/api/v1/sensors/dionaea",
            "HOST_AUTH_API_URL=http://cti-gateway:8080/api/v1/sensors/host-auth",
            "WEB_ACCESS_API_URL=http://cti-gateway:8080/api/v1/sensors/web-access",
            "EXTERNAL_CONTROL_API_URL=http://cti-external-control:8000/api/v1/external-sources",
        }
        for target in expected:
            self.assertIn(target, self.generator)
        self.assertNotIn("host.docker.internal:18088", self.generator)
        self.assertNotIn("host.docker.internal:18090", self.generator)
        self.assertIn('generate_backend_client_fragment.sh" "${secret_file}"', self.deploy_stack)

    def test_misp_uses_a_dedicated_pairwise_internal_network(self) -> None:
        backend_network = self.central["networks"]["cti_backend_misp"]
        self.assertIs(backend_network["external"], True)
        self.assertEqual(backend_network["name"], "cti-backend-misp")
        self.assertIn("cti_backend_misp", service_networks(self.central, "backend"))
        self.assertIn("default: {}", self.misp_override)
        self.assertIn("cti_backend_misp:", self.misp_override)
        self.assertIn("name: cti-backend-misp", self.misp_override)
        self.assertIn("- cti-misp", self.misp_override)
        self.assertIn("ensure_network cti-backend-misp backend misp-core", self.provisioner)

    def test_frontend_is_loopback_only_and_pairwise_with_backend(self) -> None:
        self.assertEqual(
            published_ports(self.central, "frontend"),
            {("127.0.0.1", "18080", 8080, "tcp")},
        )
        self.assertIs(self.central["networks"]["frontend_backend"]["internal"], True)
        members = {
            service
            for service in self.central["services"]
            if "frontend_backend" in service_networks(self.central, service)
        }
        self.assertEqual(members, {"backend", "frontend"})
        frontend = self.central["services"]["frontend"]
        self.assertTrue(frontend["read_only"])
        self.assertEqual(frontend["cap_drop"], ["ALL"])


    def test_internal_http_is_allowed_only_for_approved_aliases(self) -> None:
        expected = {
            "EXTERNAL_CONTROL": (
                "http://cti-external-control:8000/api/v1/external-sources",
                "EXTERNAL_CONTROL_ALLOW_HTTP=true",
            ),
            "EXTERNAL_FEED": (
                "http://cti-gateway:8080/api/v1/external-feed",
                "EXTERNAL_FEED_ALLOW_HTTP=true",
            ),
            "DIONAEA": (
                "http://cti-gateway:8080/api/v1/sensors/dionaea",
                "DIONAEA_API_ALLOW_HTTP=true",
            ),
            "INTERNAL_SENSOR": (
                "http://cti-gateway:8080/api/v1/sensors/host-auth",
                "INTERNAL_SENSOR_ALLOW_HTTP=true",
            ),
        }
        for name, (url, flag) in expected.items():
            with self.subTest(integration=name):
                self.assertIn(url, self.generator)
                self.assertEqual(self.generator.count(flag), 1)
        self.assertNotIn("EXTERNAL_CONTROL_API_URL=http://host.docker.internal", self.generator)
        self.assertNotIn("EXTERNAL_FEED_URL=http://host.docker.internal", self.generator)
        self.assertNotIn("DIONAEA_API_URL=http://host.docker.internal", self.generator)
        self.assertIn(
            "WEB_ACCESS_API_URL=http://cti-gateway:8080/api/v1/sensors/web-access",
            self.generator,
        )
        self.assertNotIn("HOST_AUTH_API_URL=http://host.docker.internal", self.generator)
        self.assertNotIn("WEB_ACCESS_API_URL=http://host.docker.internal", self.generator)

if __name__ == "__main__":
    unittest.main()
