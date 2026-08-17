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
        self.assertEqual(project["project"]["license-files"], ["LICENSE"])
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
        self.assertIn("scripts/verify_python_artifact.py", workflow)
        self.assertIn("MOSAIC_REQUIRE_NATIVE_EXTENSION", workflow)
        self.assertIn("tests.test_native_extension", workflow)
        self.assertGreaterEqual(workflow.count("MOSAIC_REQUIRE_NATIVE_EXTENSION"), 3)
        self.assertIn("mosaic-sdist-smoke", workflow)
        self.assertIn("ubuntu-latest", workflow)
        self.assertIn("windows-latest", workflow)
        self.assertIn("macos-15", workflow)

        windows_rust_job = workflow.split("  native-supervisor-windows:\n", maxsplit=1)[1].split(
            "  native-core-macos:\n", maxsplit=1
        )[0]
        self.assertIn("actions/setup-python@", windows_rust_job)
        self.assertIn('python-version: "3.11"', windows_rust_job)
        self.assertIn("cargo +1.96.0 test --workspace --locked", windows_rust_job)

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

    def test_frozen_executable_smoke_is_isolated_and_bounded(self) -> None:
        smoke = (ROOT / "scripts" / "smoke_native_preview.py").read_text(encoding="utf-8")

        self.assertIn('environment.pop("PYTHONPATH", None)', smoke)
        self.assertIn('environment.pop("PYTHONHOME", None)', smoke)
        self.assertGreaterEqual(smoke.count("timeout=EXECUTABLE_TIMEOUT_SECONDS"), 2)
        self.assertGreaterEqual(smoke.count("cwd=directory"), 2)


if __name__ == "__main__":
    unittest.main()
