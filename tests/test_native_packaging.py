from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NativePackagingContractTests(unittest.TestCase):
    def test_project_is_one_locked_maturin_mixed_distribution(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as stream:
            project = tomllib.load(stream)

        self.assertEqual(project["build-system"]["build-backend"], "maturin")
        self.assertEqual(project["build-system"]["requires"], ["maturin==1.11.5"])
        self.assertNotIn("hatch", project["tool"])
        self.assertEqual(
            project["tool"]["maturin"],
            {
                "manifest-path": "native/msc7-python/Cargo.toml",
                "python-source": "src",
                "module-name": "mosaic_archive._native",
                "bindings": "pyo3",
                "locked": True,
                "strip": True,
            },
        )

    def test_binding_crate_is_versioned_and_abi3_from_python_311(self) -> None:
        with (ROOT / "Cargo.toml").open("rb") as stream:
            workspace = tomllib.load(stream)
        with (ROOT / "native" / "msc7-python" / "Cargo.toml").open("rb") as stream:
            binding = tomllib.load(stream)
        with (ROOT / "pyproject.toml").open("rb") as stream:
            project = tomllib.load(stream)

        self.assertIn("native/msc7-python", workspace["workspace"]["members"])
        self.assertEqual(binding["package"]["version"], project["project"]["version"])
        self.assertEqual(binding["lib"]["name"], "_native")
        self.assertEqual(binding["lib"]["crate-type"], ["cdylib"])
        pyo3 = binding["dependencies"]["pyo3"]
        self.assertEqual(pyo3["version"], "=0.29.0")
        self.assertEqual(pyo3["features"], ["abi3-py311"])
        self.assertNotIn("extension-module", pyo3["features"])

    def test_ci_builds_and_smoke_tests_the_installed_native_wheel(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

        self.assertIn("native Python wheel", workflow)
        self.assertIn("native/msc7-python", workflow)
        self.assertIn("maturin", workflow)
        self.assertIn("--release --locked", workflow)
        self.assertIn("scripts/smoke_native_preview.py", workflow)
        self.assertIn("ubuntu-latest", workflow)
        self.assertIn("windows-latest", workflow)
        self.assertIn("macos-15", workflow)

    def test_release_binary_build_includes_and_exercises_native_extension(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('"native/**"', workflow)
        self.assertIn('"Cargo.toml"', workflow)
        self.assertIn('"Cargo.lock"', workflow)
        self.assertIn("mosaic_archive._native", workflow)
        self.assertIn("scripts/smoke_native_preview.py", workflow)
        self.assertNotIn("--no-install-project pyinstaller", workflow)


if __name__ == "__main__":
    unittest.main()
