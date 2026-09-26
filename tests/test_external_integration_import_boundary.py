from __future__ import annotations

import subprocess
import sys
import textwrap
import unittest


class ExternalIntegrationImportBoundaryTests(unittest.TestCase):
    def run_isolated(self, source: str) -> None:
        completed = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(source)],
            cwd=".",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_central_backend_main_imports_without_external_only_dependencies(self) -> None:
        self.run_isolated(
            """
            import importlib.abc
            import sys

            forbidden = (
                "bs4", "feedparser", "playwright",
                "backend.app.pipeline.ingestion.external.integration.api",
                "backend.app.pipeline.ingestion.external.application",
            )

            class BlockExternalOnly(importlib.abc.MetaPathFinder):
                def find_spec(self, fullname, path=None, target=None):
                    if fullname == forbidden[0] or any(
                        fullname == prefix or fullname.startswith(prefix + ".")
                        for prefix in forbidden
                    ):
                        raise ImportError("blocked external-only dependency: " + fullname)
                    return None

            sys.meta_path.insert(0, BlockExternalOnly())
            import backend.app.main
            """
        )

    def test_diagnostics_import_does_not_load_external_runtime_graph(self) -> None:
        self.run_isolated(
            """
            import sys
            from backend.app.pipeline.ingestion.external.integration import diagnostics

            forbidden = (
                "backend.app.pipeline.ingestion.external.integration.api",
                "backend.app.pipeline.ingestion.external.application",
                "bs4", "feedparser", "playwright",
            )
            loaded = [name for name in sys.modules if any(
                name == prefix or name.startswith(prefix + ".") for prefix in forbidden
            )]
            assert not loaded, loaded
            assert diagnostics.EXTERNAL_COLLECTION_METHODS
            """
        )

    def test_documented_exports_remain_lazy_and_compatible(self) -> None:
        import backend.app.pipeline.ingestion.external.integration as integration

        self.assertNotIn("AdapterServices", integration.__dict__)
        self.assertNotIn("create_app", integration.__dict__)
        from backend.app.pipeline.ingestion.external.integration import AdapterServices, create_app
        from backend.app.pipeline.ingestion.external.integration.api import (
            AdapterServices as APIAdapterServices,
            create_app as api_create_app,
        )

        self.assertIs(AdapterServices, APIAdapterServices)
        self.assertIs(create_app, api_create_app)

    def test_diagnostic_methods_and_bounds_are_one_shared_contract(self) -> None:
        from backend.app.integrations import external_control_client
        from backend.app.pipeline.ingestion.external.integration import diagnostics

        self.assertIs(
            external_control_client.EXTERNAL_COLLECTION_METHODS,
            diagnostics.EXTERNAL_COLLECTION_METHODS,
        )
        self.assertIs(
            external_control_client.DIAGNOSTIC_IDENTIFIER_PATTERN,
            diagnostics.DIAGNOSTIC_IDENTIFIER_PATTERN,
        )
        self.assertIs(
            external_control_client.COLLECTION_STAGE_PATTERN,
            diagnostics.COLLECTION_STAGE_PATTERN,
        )
        self.assertEqual(len(diagnostics.EXTERNAL_COLLECTION_METHODS), 14)
        self.assertEqual(diagnostics.DIAGNOSTIC_IDENTIFIER_PATTERN, r"^[A-Za-z][A-Za-z0-9_]{0,99}$")
        self.assertEqual(diagnostics.COLLECTION_STAGE_PATTERN, r"^[a-z][a-z0-9_]{0,63}$")


if __name__ == "__main__":
    unittest.main()
