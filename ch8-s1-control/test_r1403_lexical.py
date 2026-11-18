# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Gate-only R14-03 regressions; Rust strings are scanned, never executed."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import cfg_pfc as c
import lexical_bindings as l
import runner

HERE = Path(__file__).resolve().parent


def wrapped(path, depth):
    return '(' * depth + path + ')' * depth


class ExtractorTests(unittest.TestCase):
    def test_arbitrary_depth_paths_are_single_records(self):
        for depth in (0, 1, 2, 3, 8, 128, 2048):
            for path, expected in [('missing_static', ('missing_static',)),
                  ('super::super::sort4_stable', ('super','super','sort4_stable')),
                  ('::core::mem::size_of::<u8>', ('core','mem','size_of'))]:
                source = wrapped(path, depth) + '();'
                with self.subTest(depth=depth, path=path):
                    records = list(l.call_paths(c.tokens(source)))
                    self.assertEqual(len(records), 1)
                    self.assertEqual(records[0][:3], (expected, 1, 'STATIC'))
                    self.assertEqual(c.tokens(source)[records[0][3]][0], expected[0])

    def test_arguments_scopes_comments_and_literals(self):
        source = '((callee))(((argument)()), obj.method()); "((hidden))()"; /* ((hidden))() */'
        records = list(l.call_paths(c.tokens(source)))
        self.assertEqual([(r[0],r[2]) for r in records],
                         [(('callee',),'STATIC'), (('argument',),'STATIC'), (('method',),'METHOD')])
        self.assertEqual(list(l.call_paths(c.tokens('((callee)); (left, right);'))), [])
        self.assertEqual(list(l.call_paths(c.tokens('return ((callee))();')))[0][0], ('callee',))

    def test_unsupported_callable_expressions_fail_closed(self):
        for expression in ('(left,right)()', '(*pointer)()', '(obj.method)()',
              '(obj.method())()', 'factory()()', 'factory(argument)()', 'factory((argument))()',
              '((factory()))()', '((callee))()()', 'callbacks[0]()', '[callback]()',
              '{callback}()', '({callback})()', '(|| {})()', 'macro!()()'):
            with self.subTest(expression=expression), self.assertRaisesRegex(c.GateError, 'unsupported .*callable|unsupported call-result'):
                list(l.call_paths(c.tokens(expression)))

    def test_method_receivers_remain_dispatch_only(self):
        records = list(l.call_paths(c.tokens('((receiver)).method(); receiver.method::<u8>();')))
        self.assertEqual([(r[0],r[2]) for r in records], [(('method',),'METHOD'), (('method',),'METHOD')])


class ActualGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sources = json.loads((HERE/'S2-SOURCE.json').read_text())
        for rel,text in self.sources.items():
            p=self.root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
        self.exact_request = runner.load_request()
        self.request = copy.deepcopy(self.exact_request)
        self.removed = self.request.pop('lexical_source_sha256')
        self.assertEqual(set(self.exact_request)-set(self.request), {'lexical_source_sha256'})
        self.assertTrue(all(v == self.request[k] for k,v in self.exact_request.items() if k!='lexical_source_sha256'))

    def source(self, expression, imports=''):
        text=self.sources[l.BATCH]
        if imports:
            first, rest=text.split('\n',1);text=first+'\n'+imports+'\n'+rest
        text=text.replace('fn sort13_weak() {', 'fn sort13_weak() { '+expression, 1)
        (self.root/l.BATCH).write_text(text)

    def check(self):
        return l.check(self.root,self.request)

    def test_exact_frozen_source_acceptance(self):
        doc=l.check(self.root,self.exact_request)
        self.assertEqual(len(doc['functions']),8)
        self.assertEqual(sum(len(x['static_calls']) for x in doc['functions']),77)
        self.assertEqual(len(doc['contexts']),11)

    def test_exact_review_and_direct_single_deeper_unbound_reject(self):
        for depth in (0,1,2,8):
            self.source(wrapped('missing_static',depth)+'();')
            with self.subTest(depth=depth), self.assertRaisesRegex(c.GateError,'unresolved static path.*missing_static'):
                self.check()

    def test_bound_full_paths_aliases_local_functions_and_values(self):
        expressions=[]
        for depth in (0,1,2,8):
            for path in ('super::super::sort4_stable', 'four', 'sort13_fault_network', 'callable'):
                expressions.append(wrapped(path,depth)+'();')
        self.source('let callable = || {}; '+' '.join(expressions),
                    'use super::super::sort4_stable as four;')
        doc=self.check()
        record=next(x for x in doc['functions'] if x['function']=='sort13_weak')
        calls=record['static_calls'][:16]
        self.assertEqual(len(calls),16)
        for at,call in enumerate(calls):
            if at%4 in (0,1):self.assertEqual(call['identity'],'::'.join(c.SM+('sort4_stable',)))
            if at%4==2:self.assertEqual(call['binding']['kind'],'LOCAL_FN')
            if at%4==3:self.assertEqual(call['binding']['kind'],'LOCAL_VALUE_CALLABLE')

    def test_nested_callable_values_obey_scope_and_order(self):
        for expression in ('((callable))(); let callable = || {};',
                           '{ let callable = || {}; }; ((callable))();'):
            self.source(expression)
            with self.subTest(expression=expression),self.assertRaisesRegex(c.GateError,'unresolved static path.*callable'):
                self.check()

    def test_unsupported_expression_reaches_actual_gate_guard(self):
        for expression in ('((sort13_fault_network()))();','[sort13_fault_network][0]();'):
            self.source(expression)
            with self.subTest(expression=expression),self.assertRaisesRegex(c.GateError,'unsupported callable expression'):
                self.check()
