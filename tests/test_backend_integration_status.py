from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from backend.app.services.pipeline_service import PipelineService


class BackendIntegrationStatusTests(unittest.TestCase):
    def test_internal_external_control_is_not_reported_as_an_ssh_tunnel(self) -> None:
        settings = SimpleNamespace(
            external_feed_configured=True,
            external_feed_verify_tls=False,
            external_feed_hmac_secret="set",
            external_control_api_url="http://cti-external-control:8000/api/v1/external-sources",
            external_control_configured=True,
            external_control_verify_tls=False,
            external_control_allow_http=True,
            wazuh_indexer_configured=False,
            wazuh_indexer_verify_tls=True,
            wazuh_indexer_token=None,
            dionaea_api_configured=True,
            dionaea_api_verify_tls=False,
            dionaea_api_hmac_secret="set",
            host_auth_api_configured=True,
            web_access_api_configured=True,
            internal_sensor_verify_tls=False,
            internal_sensor_api_hmac_secret="set",
            misp_configured=True,
            misp_verify_tls=True,
        )
        with patch(
            "backend.app.services.pipeline_service.get_settings",
            return_value=settings,
        ):
            status = PipelineService.integration_status()

        self.assertEqual(
            status["external_control_api"]["deployment_status"],
            "vps_internal",
        )
        self.assertEqual(
            status["external_control_api"]["transport"],
            "docker_internal_http",
        )


if __name__ == "__main__":
    unittest.main()
