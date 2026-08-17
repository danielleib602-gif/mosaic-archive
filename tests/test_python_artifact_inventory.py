from __future__ import annotations

import unittest

from scripts.verify_python_artifact import _validate_names


class PythonArtifactInventoryTests(unittest.TestCase):
    def test_wheel_and_sdist_require_license_native_and_workspace_members(self) -> None:
        wheel_names = {
            "mosaic_archive/native_preview.py",
            "mosaic_archive/_native.pyi",
            "mosaic_archive/_native.cp311-win_amd64.pyd",
            "mosaic_archive/py.typed",
            "mosaic_archive-0.39.0.dist-info/licenses/LICENSE",
        }
        _validate_names(wheel_names, wheel=True)
        with self.assertRaisesRegex(ValueError, "LICENSE"):
            _validate_names(
                wheel_names - {"mosaic_archive-0.39.0.dist-info/licenses/LICENSE"},
                wheel=True,
            )

        prefix = "mosaic_archive-0.39.0/"
        sdist_names = {
            f"{prefix}Cargo.toml",
            f"{prefix}Cargo.lock",
            f"{prefix}LICENSE",
            f"{prefix}native/msc7-core/Cargo.toml",
            f"{prefix}native/msc7-python/Cargo.toml",
            f"{prefix}src/mosaic_archive/native_preview.py",
        }
        _validate_names(sdist_names, wheel=False)
        with self.assertRaisesRegex(ValueError, "LICENSE"):
            _validate_names(sdist_names - {f"{prefix}LICENSE"}, wheel=False)


if __name__ == "__main__":
    unittest.main()
