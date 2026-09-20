import contextlib
import io
import unittest
from unittest.mock import patch

from scripts.validate_dark_web_control import main,validated_base_url


class DarkWebValidatorURLPolicyTests(unittest.TestCase):
    def test_allows_only_exact_isolated_loopback_http_proxy(self):
        for value in ("http://127.0.0.1:19080","http://localhost:19080"):
            with self.subTest(value=value):self.assertEqual(validated_base_url(value),value)

    def test_rejects_other_plain_http_and_ambiguous_authorities(self):
        rejected=("http://127.0.0.1","http://127.0.0.1:19081","http://localhost:19080/path",
                  "http://localhost:19080?x=1","http://localhost:19080/#x","http://user@localhost:19080",
                  "http://localhost.example:19080","http://[::1]:19080","http://example.test:19080")
        for value in rejected:
            with self.subTest(value=value),self.assertRaises(ValueError):validated_base_url(value)

    def test_non_loopback_requires_https_and_clean_base_url(self):
        self.assertEqual(validated_base_url("https://central.example.test"),"https://central.example.test")
        self.assertEqual(validated_base_url("https://central.example.test:8443"),"https://central.example.test:8443")
        for value in ("https://user@central.example.test","https://central.example.test/","https://central.example.test/api","https://central.example.test?q=1"):
            with self.subTest(value=value),self.assertRaises(ValueError):validated_base_url(value)

    def test_help_exits_before_any_interactive_prompt(self):
        output=io.StringIO()
        with patch("builtins.input",side_effect=AssertionError("prompted")),patch("getpass.getpass",side_effect=AssertionError("prompted")),contextlib.redirect_stdout(output),self.assertRaises(SystemExit) as raised:
            main(["--help"])
        self.assertEqual(raised.exception.code,0)
        self.assertIn("usage:",output.getvalue())


if __name__=="__main__":unittest.main()
