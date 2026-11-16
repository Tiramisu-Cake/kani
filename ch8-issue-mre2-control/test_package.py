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
        self.assertEqual(pkg.static_check()['rows'], 7)

    def test_parent_refuses_nonupstream(self):
        with patch.object(pkg, 'git', return_value='wrong-parent'):
            with self.assertRaises(AssertionError): pkg.control_check(pkg.ROOT)

    def test_wrong_checkout_rejected(self):
        with self.assertRaises(AssertionError): pkg.control_check(Path('/tmp/other-checkout'))

    def test_source_matrix_diagnostics(self):
        rows = json.loads((pkg.HERE/'rows.json').read_text())
        self.assertEqual(sum(r['expected']=='UNINIT_FAILURE' for r in rows), 2)
        self.assertEqual(sum(r['expected']=='SUCCESS' for r in rows), 5)
        self.assertEqual({tuple(r['flags']) for r in rows}, {('-Z','function-contracts','-Z','uninit-checks','-Z','stubbing')})

    def test_fixture_allocation_and_no_union(self):
        for p in (pkg.HERE/'fixtures').glob('*.rs'):
            text = p.read_text()
            self.assertIn('Layout::array::<u8>(2).unwrap()', text)
            self.assertIn('let p = alloc(layout);', text)
            self.assertNotIn('MaybeUninit', text)
            self.assertIn('dealloc(p, layout);', text)
        text = (pkg.HERE/'fixtures/actual_uninit_read.rs').read_text()
        self.assertIn('read_volatile(p.cast_const())', text)
        self.assertNotIn('assert_eq!', text)
