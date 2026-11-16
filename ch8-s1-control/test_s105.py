"""Real S1-04 rich-object fixture + synthetic service/error regressions."""
import copy
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import collect
import pack_evidence
import rich_evidence as rich
import runner
from test_runner import render_regular
import test_runner as runner_tests

FIXTURE = json.loads((Path(__file__).parent/'fixtures/s104-rich-fragment.json').read_text())


def stock_for(props):
    checks={'total':len(props),'success':sum(p['status']=='SUCCESS' for p in props)}
    for key in rich.CHECK_BUCKETS:
        checks[key]=[p['id'] for p in props if p['status']==key.upper()] if key!='other' else []
    covers={k:[] for k in rich.COVER_BUCKETS};covers['total']=0
    return {'harnesses':[{'name':FIXTURE['selector'],'checks':checks,'covers':covers,
                         'n_properties':len(props),'n_failed':len(checks['failure']),
                         'failed_properties':[p for p in props if p['status']=='FAILURE'],
                         'unsupported_constructs':[p for p in props if p['class']=='unsupported_construct']}]}


class RichTests(unittest.TestCase):
    def decode(self, data):
        parser=rich.RegularEvidence([FIXTURE['selector']],Path('/std'))
        for i in range(0,len(data),13):parser.feed(data[i:i+13])
        parser.finish();return parser

    def test_real_s104_rich_fragment_multiline_description(self):
        props=FIXTURE['properties'];self.assertEqual(len(props),4)
        parser=self.decode(render_regular([(FIXTURE['selector'],props)]))
        parser.validate(stock_for(props))
        for got, expected in zip(parser.records[FIXTURE['selector']],props):
            for key in ('id','class','description','file','line','status'):
                self.assertEqual(got[key],expected[key])
        self.assertEqual(parser.document()['state'],'COMPLETE')

    def test_every_property_requires_description_and_location(self):
        data=render_regular([(FIXTURE['selector'],FIXTURE['properties'])])
        lines=data.decode().splitlines(keepends=True)
        for field in ('Description', 'Location'):
            indexes=[i for i,line in enumerate(lines) if line.startswith('\t - '+field+': ')]
            self.assertEqual(len(indexes),len(FIXTURE['properties']))
            for i in indexes:
                mutated=lines.copy();mutated[i]=mutated[i].replace(field,'Missing'+field,1)
                parser=self.decode(''.join(mutated).encode())
                with self.assertRaises(ValueError):parser.validate(stock_for(FIXTURE['properties']))
                self.assertEqual(parser.document()['state'],'INCOMPLETE')


    def test_wrong_identity_status_count_partial_and_limits(self):
        data=render_regular([(FIXTURE['selector'],FIXTURE['properties'])]); stock=stock_for(FIXTURE['properties'])
        for value in (data.replace(b'Check 2:',b'Check 3:',1),data.replace(b'SUMMARY:',b'PARTIAL:',1),
                      data.replace(FIXTURE['selector'].encode(),b'wrong',1),
                      data.replace(b'Status: SUCCESS',b'Status: UNREACHABLE',1),data[:-80]):
            with self.assertRaises(ValueError):self.decode(value).validate(stock)
        with mock.patch.object(rich,'MAX_BYTES',16):
            parser=self.decode(data);self.assertIsNotNone(parser.error)
        parser=self.decode(data);bad=copy.deepcopy(stock);bad['harnesses'][0]['n_properties']+=1
        with self.assertRaises(ValueError):parser.validate(bad)

    def test_unknown_status_restored_by_exact_stock_id(self):
        p=dict(FIXTURE['properties'][0], status='UNDETERMINED', **{'class':'assertion'})
        parser=self.decode(render_regular([(FIXTURE['selector'],[p])]))
        h=stock_for([dict(p,status='UNKNOWN')]);h['harnesses'][0]['failed_properties']=[]
        parser.validate(h)
        self.assertEqual(parser.records[FIXTURE['selector']][0]['status'],'UNKNOWN')
        parser.validate(h)  # Saved normalized inventory must survive collector revalidation.

    def test_missing_site_keeps_suffix_and_next_harness_but_never_completes(self):
        props = FIXTURE['properties']
        name = FIXTURE['selector']
        other = name + '_second'
        data = render_regular([(name, props), (other, props)])
        original = ('\t - Location: '+props[0]['file']+':'+str(props[0]['line'])).encode()
        stock = stock_for(props)
        second = copy.deepcopy(stock['harnesses'][0]); second['name'] = other
        stock['harnesses'].append(second)
        for location in (b'\t - Location: Unknown file in function generated::check',
                         b'\t - Location: source.rs', b'\t - Location: source.rs:0:0', b''):
            with self.subTest(location=location):
                parser = rich.RegularEvidence([name, other], Path('/std'))
                parser.feed(data.replace(original, location, 1)); parser.finish()
                self.assertIsNone(parser.error)
                self.assertEqual(parser.closed, {name, other})
                self.assertEqual([len(v) for v in parser.records.values()], [len(props), len(props)])
                # This fixture's first property is an embedded failed/unsupported
                # property, so its stock nullable fields must match the display.
                changed = copy.deepcopy(stock)
                pid = props[0]['id']
                for p in changed['harnesses'][0]['failed_properties'] + changed['harnesses'][0]['unsupported_constructs']:
                    if p['id'] == pid: p.update(file=None, line=None)
                with self.assertRaises(ValueError): parser.validate(changed)
                self.assertEqual(parser.document()['state'], 'INCOMPLETE')
                self.assertEqual(len(parser.document()['missing_sites']), 1)
                self.assertIsNone(parser.records[name][0]['file'])
                # Rehydration, as performed by collect.py, cannot bless null sites.
                replay = rich.RegularEvidence([name, other], Path('/std'))
                replay.records = parser.records; replay.finished = True
                with self.assertRaises(ValueError): replay.validate(changed)
                self.assertFalse(replay.complete)

    def test_pack_preserves_exact_json_bytes_and_excludes_raw_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);raw=b'{"state": "SYNTHETIC", "original_exit_code": 1}\n'
            (root/'receipt.json').write_bytes(raw);(root/'stdout.log').write_bytes(b'not an artifact')
            result=pack_evidence.pack(root);first=(root/pack_evidence.NAME).read_bytes()
            pack_evidence.pack(root);self.assertEqual(first,(root/pack_evidence.NAME).read_bytes())
            doc=json.loads(gzip.decompress(first));self.assertEqual(set(doc['files']),{'receipt.json'})
            self.assertEqual(doc['files']['receipt.json']['text'].encode(),raw)
            (root/'receipt.json').unlink();self.assertEqual(collect.read(root/'receipt.json')['original_exit_code'],1)
            self.assertLess(result['compressed_bytes'],pack_evidence.COMPRESSED_CAP)

    def test_partial_json_and_overflow_never_pack_as_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'partial.json').write_text('{')
            self.assertEqual(pack_evidence.pack(root)['state'],'INCOMPLETE')
            (root/'partial.json').write_text('{"x":"large"}')
            with mock.patch.object(pack_evidence,'UNCOMPRESSED_CAP',1024):
                (root/'huge.json').write_text(json.dumps('x'*2048))
                self.assertEqual(pack_evidence.pack(root)['state'],'INCOMPLETE')

    def test_complete_matrix_survives_compact_collection(self):
        request=runner.load_request()
        helper=runner_tests.GroupTests('test_all35_rows_fourteen_invocations_record_only_without_oracle_classification')
        with tempfile.TemporaryDirectory() as tmp:
            code,summary,calls,root=helper.run_mock_batch(Path(tmp),request)
            self.assertEqual(code,0)
            source={k:request[k] for k in ('std_sha','std_tree','tool_sha','tool_tree','changed_file_sha256')}
            for group in request['execution_groups']:
                path=root/'groups'/group['id']/'receipt.json'
                receipt=json.loads(path.read_text());receipt.update(source_before=source,source_after=source)
                path.write_text(json.dumps(receipt))
            self.assertEqual(pack_evidence.pack(root)['state'],'PACKAGED')
            for path in root.rglob('*.json'):path.unlink()
            result=collect.collect([root],request)
            self.assertEqual(result['missing_groups'],[])
            self.assertEqual(len(result['rows']),35)
            self.assertTrue(all(r['outcome']=='RECORDED' for r in result['rows']))
            self.assertEqual(result['proof_credit'],'NONE')

    def test_frozen_attachment_oracles_and_companions(self):
        request=runner.load_request();rows={r['id']:r for r in request['rows']}
        for rid in ('activation-default','activation-override'):
            r=rows[rid];o=r['oracle'];p=o['proposal']['property']
            self.assertEqual(o['property_id'],p['id']);self.assertEqual(o['description'],p['description'])
            self.assertTrue(o['require_only_this_failure'])
            companion=rows[o['companion']];self.assertEqual(companion['selector'],r['selector'])
            self.assertEqual(companion['variant'],'production');self.assertEqual(companion['expected'],'SUCCESS')
            self.assertEqual(o['companion_required_cover_messages'],companion['required_cover_messages'])
            self.assertTrue(o['companion_required_cover_messages'])


if __name__=='__main__':unittest.main()
