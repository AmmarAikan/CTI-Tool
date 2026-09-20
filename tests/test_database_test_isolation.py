from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from sqlalchemy import inspect

from backend.app.db import database


class DatabaseTestIsolationTests(unittest.TestCase):
    def tearDown(self) -> None:
        configured = database._test_database_url
        if configured is not None:
            database.dispose_test_database(configured)

    def test_environment_first_and_database_first_import_orders(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="cti_order_test_") as folder:
            target = Path(folder) / "test.db"
            scripts = (
                "import os; URL=os.environ['URL']; os.environ['DATABASE_URL']=URL; "
                "from backend.app.db import database; "
                "assert str(database.engine.url)==URL",
                "from backend.app.db import database; import os; URL=os.environ['URL']; "
                "os.environ['DATABASE_URL']=URL; database.configure_test_database(URL); "
                "assert str(database.engine.url)==URL; database.dispose_test_database(URL)",
            )
            for script in scripts:
                environment = dict(os.environ, URL=f"sqlite:///{target.as_posix()}")
                result = subprocess.run(
                    [sys.executable, "-c", script], cwd=repository, env=environment,
                    check=False, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_repeated_configuration_isolated_bootstrap_and_cleanup(self) -> None:
        from backend.app.db.models import User
        from backend.app.main import create_app
        from fastapi.testclient import TestClient

        for index in range(2):
            with tempfile.TemporaryDirectory(prefix=f"cti_bootstrap_test_{index}_") as folder:
                url = f"sqlite:///{(Path(folder) / 'test.db').as_posix()}"
                database.configure_test_database(url)
                with TestClient(create_app()) as client:
                    response = client.post(
                        "/api/v1/auth/bootstrap",
                        json={"username": "admin", "password": "StrongTestPassword123!"},
                    )
                    self.assertEqual(response.status_code, 201)
                    self.assertIn(User.__tablename__, inspect(database.engine).get_table_names())
                database.dispose_test_database(url)
                self.assertIsNone(database.engine)
                self.assertIsNone(database.SessionLocal.kw.get("bind"))

    def test_refuses_non_test_database_reset_without_changing_binding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cti_guard_test_") as folder:
            url = f"sqlite:///{(Path(folder) / 'test.db').as_posix()}"
            database.configure_test_database(url)
            current = database.engine
            for unsafe in (
                "postgresql+psycopg://user:password@db/production",
                "sqlite:////var/lib/cti/production.db",
                "sqlite:////tmp/production.db",
            ):
                with self.assertRaises(ValueError):
                    database.configure_test_database(unsafe)
                self.assertIs(database.engine, current)


if __name__ == "__main__":
    unittest.main()
