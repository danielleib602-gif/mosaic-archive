from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.coverage_fuzzing import fuzz_one_input, generate_seed_corpus


class CoverageGuidedFuzzingTests(unittest.TestCase):
    def test_seed_corpus_reaches_every_parser_and_decoder_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            seeds = generate_seed_corpus(Path(temp_dir))

            self.assertGreaterEqual(len(seeds), 11)
            self.assertEqual(len(seeds), len({path.read_bytes()[0] for path in seeds}))
            for seed in seeds:
                with self.subTest(seed=seed.name):
                    fuzz_one_input(seed.read_bytes())

    def test_random_inputs_fail_closed_without_escaping_domain_errors(self) -> None:
        rng = random.Random(20260630)
        fuzz_one_input(b"")
        for _ in range(250):
            fuzz_one_input(rng.randbytes(rng.randrange(1, 512)))

    def test_atheris_entrypoint_instruments_imports_before_fuzzing(self) -> None:
        entrypoint = Path("fuzz/atheris_mosaic.py").read_text(encoding="utf-8")

        self.assertIn("atheris.instrument_imports()", entrypoint)
        self.assertIn("atheris.Setup(", entrypoint)
        self.assertIn("atheris.Fuzz()", entrypoint)

    def test_coverage_fuzz_workflow_is_bounded_and_preserves_artifacts(self) -> None:
        workflow = Path(".github/workflows/coverage-fuzz.yml").read_text(encoding="utf-8")

        self.assertIn("pull_request:\n    paths:", workflow)
        self.assertIn("schedule:", workflow)
        self.assertIn("timeout-minutes:", workflow)
        self.assertIn("atheris==3.1.0", workflow)
        self.assertIn("-max_total_time=300", workflow)
        self.assertIn("-rss_limit_mb=2048", workflow)
        self.assertIn("actions/upload-artifact@", workflow)
        self.assertIn("if: always()", workflow)


if __name__ == "__main__":
    unittest.main()
