from __future__ import annotations

import runpy
import unittest
from unittest.mock import patch


class EntryPointTests(unittest.TestCase):
    def test_module_entrypoint_exits_with_main_result(self) -> None:
        with (
            patch("mosaic_archive.cli.main", return_value=23) as main,
            self.assertRaises(SystemExit) as raised,
        ):
            runpy.run_module("mosaic_archive", run_name="__main__")

        self.assertEqual(raised.exception.code, 23)
        main.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
