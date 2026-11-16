# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""OFF lane identity and shared 63-row contract checks; synthetic only."""
import unittest
import runner

class OffLaneTests(unittest.TestCase):
    def test_stock_tool_valid_value_off_and_common_rows(self):
        request = runner.load_request()
        self.assertEqual(runner.TOOL_SHA, '0aac16ef62da9e9d5645782d458593e5d78143ba')
        self.assertEqual(len(request['rows']), 63)
        self.assertNotIn('uninit-checks', runner.UNSTABLE)
        leaf = next(r for r in request['rows'] if r['id'] == 'profile_merge4_contract_u8_len4')
        consumer = next(r for r in request['rows'] if r['id'] == 'profile_merge_consumer_u8_len4')
        self.assertEqual(leaf['profile_mode'], 'PFC:merge4_profile')
        self.assertEqual(consumer['profile_mode'], 'Replace:profile_wrapper')
        self.assertEqual(consumer['leaf_companion'], leaf['id'])
        self.assertIn('reading_comparator::<u8> closure', next(r for r in request['rows'] if r['id'] == 'swap_safety_u8_backing4')['profile'])
        self.assertNotIn('uninit-checks', runner.build_argv.__code__.co_consts)

if __name__ == '__main__':
    unittest.main()
