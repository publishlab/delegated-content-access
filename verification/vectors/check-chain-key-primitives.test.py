#!/usr/bin/env python3
"""Focused refusal proof for an unlisted chain-key vector member."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check-chain-key-primitives.py")
VECTOR = os.path.join(HERE, "v1", "profiles", "dca-profile-chain-keys", "chain-key-primitives.json")
FIXTURE = os.path.join(HERE, "..", "..", "js", "extensions", "chain-keys", "test", "fixtures",
                       "dca-profile-chain-keys.vectors.json")


class ReplayMembershipTest(unittest.TestCase):
    def test_empty_fixture_collections_are_rejected(self):
        with open(FIXTURE, encoding="utf-8") as source:
            original = json.load(source)
        for collection in ("cases", "separation", "edges"):
            with self.subTest(collection=collection), tempfile.TemporaryDirectory(prefix="dca-chain-fixture-") as scratch:
                broken = dict(original)
                broken[collection] = []
                fixture = os.path.join(scratch, "fixture.json")
                with open(fixture, "w", encoding="utf-8") as target:
                    json.dump(broken, target)
                result = subprocess.run([sys.executable, SCRIPT, "--fixture", fixture],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 1, (collection, result.stdout, result.stderr))
                self.assertIn(f"fixture {collection} present", result.stderr)

    def test_an_added_vector_cannot_sit_beside_the_replayed_member(self):
        with tempfile.TemporaryDirectory(prefix="dca-chain-vector-") as scratch:
            copied = os.path.join(scratch, "chain-key-primitives.json")
            shutil.copyfile(VECTOR, copied)
            command = [sys.executable, SCRIPT, "--neutral", copied]
            held = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(held.returncode, 0, held.stderr)

            with open(os.path.join(scratch, "unreplayed.json"), "w", encoding="utf-8") as extra:
                extra.write("{}\n")
            missed = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(missed.returncode, 1, missed.stderr)
            self.assertIn("chain-key set members", missed.stderr)


if __name__ == "__main__":
    unittest.main()
