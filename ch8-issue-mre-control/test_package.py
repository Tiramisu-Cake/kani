# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic/static package checks only."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import check_package as pkg

class PackageTests(unittest.TestCase):
    def test_frozen_static(self):
        self.assertEqual(pkg.static_check()['rows'], 10)

    def test_parent_refuses_nonupstream(self):
        with patch.object(pkg, 'git', return_value='wrong-parent'):
            with self.assertRaises(AssertionError): pkg.control_check(pkg.ROOT)

    def test_wrong_checkout_rejected(self):
        with self.assertRaises(AssertionError): pkg.control_check(Path('/tmp/other-checkout'))

    def test_source_matrix_diagnostics(self):
        rows = json.loads((pkg.HERE/'rows.json').read_text())
        self.assertEqual(sum(r['expected']=='COPY_UNSUPPORTED' for r in rows), 3)
        self.assertEqual(sum(r['expected']=='UNINIT_FAILURE' for r in rows), 2)
        self.assertEqual(sum(r['expected']=='SUCCESS' for r in rows), 5)
        self.assertEqual({tuple(r['flags']) for r in rows}, {('-Z','valid-value-checks'),('-Z','function-contracts','-Z','uninit-checks')})
