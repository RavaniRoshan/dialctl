import pathlib
import unittest


class TestReleaseGateArtifacts(unittest.TestCase):
    def test_oss_release_files_and_required_sections_exist(self) -> None:
        root = pathlib.Path(".")
        for fname in ("LICENSE", "SECURITY.md", "pyproject.toml", "README.md"):
            self.assertTrue((root / fname).exists(), f"Missing required release file: {fname}")

        self.assertIn("MIT License", (root / "LICENSE").read_text(encoding="utf-8"))
        self.assertIn("HMAC_SECRET_KEY", (root / "SECURITY.md").read_text(encoding="utf-8"))

        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "dialctl"', pyproject)
        self.assertIn("hydrate_and_verify:main", pyproject)

        readme = (root / "README.md").read_text(encoding="utf-8")
        for token in (
            "dialctl",
            "python3 hydrate_and_verify.py --self-test",
            "python3 hydrate_and_verify.py --benchmark",
            "Why Not",
            "Not legal advice",
        ):
            self.assertIn(token, readme)


if __name__ == "__main__":
    unittest.main()