"""Adverse classification/source-oracle checks for the explicitly open init boundary."""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest import mock
import runner as r
import s32_profile as p
import s32_policy as policy
import s32_campaign as campaign
import s3_policy as oldpolicy
import s3_profile as oldprofile
import test_s32 as f

class BoundaryTests(unittest.TestCase):
    def test_new_schema_does_not_relax_old_request(self):
        req=r.load_request()
        with self.assertRaises((AssertionError,KeyError)):oldprofile.validate(req)
        with self.assertRaises((AssertionError,KeyError)):oldpolicy.validate_request(req)
        self.assertEqual(len(r.load_request(r.HERE/'fixtures/s3-1-request.json')['rows']),9)
    def test_diagnostic_native_success_never_provider(self):
        for row in r.load_request()['rows'][6:]:
            parsed,props=f.inventory(row)
            self.assertTrue(policy.expected_observation(row,parsed,props))
            scope=row['scope_classification'];self.assertFalse(scope['qualification_eligible'])
            self.assertFalse(scope['eligible_as_init_leaf_or_provider_summary'])
            self.assertEqual(scope['actual_initialization_mask_and_dstinit'],'OPEN_UNPROVED')
            for field,value in [('qualification_eligible',True),('eligible_as_init_leaf_or_provider_summary',True),('actual_initialization_mask_and_dstinit','PROVED'),('qualification_eligible',0),('eligible_as_init_leaf_or_provider_summary',0)]:
                bad=copy.deepcopy(row);bad['scope_classification'][field]=value
                self.assertFalse(policy.expected_observation(bad,parsed,props))
                req=r.load_request();req['rows'][p.ORDER.index(row['id'])]=bad
                with self.assertRaises(AssertionError):p.validate(req)
    def test_no_diagnostic_init_mask_success_role_or_inventory_promotion(self):
        for label in ['S32_DST_INITIALIZED','S32_INIT_MASK','S32_DST_INIT','S32_MASK_PRESERVED']:
            req=r.load_request();row=req['rows'][6];row['roles'][0]['description']=label
            with self.subTest(label=label),self.assertRaises(AssertionError):p.validate(req)
        for field in ['qualification_inventory','diagnostic_only_inventory']:
            req=r.load_request();req[field]=list(p.ORDER[3:])
            with self.assertRaises(AssertionError):p.validate(req)
    def test_strict_diagnostic_evidence_not_waived(self):
        for row in r.load_request()['rows'][6:]:
            parsed,props=f.inventory(row)
            for mutate in [lambda a,b:a['harness'].update(unsupported_constructs=[{'status':'SUCCESS'}]),
                lambda a,b:b['properties'][0].update(status='UNREACHABLE'),lambda a,b:b['properties'][0].update(file=None),
                lambda a,b:b['properties'][0].update(line='0'),lambda a,b:b['properties'].pop(),lambda a,b:a.update(outcome='UNKNOWN')]:
                a,b=copy.deepcopy(parsed),copy.deepcopy(props);mutate(a,b);self.assertFalse(policy.expected_observation(row,a,b))
    def test_fallback_marks_diag_open_without_success_or_provider(self):
        req=r.load_request()
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);campaign.fallback(out,req);doc=campaign.read(out/'receipt.json')
            for row in doc['rows'][6:]:
                self.assertEqual(row['status'],'NOT_RUN');self.assertEqual(row['scope_classification'],p.classification(row['id']))
                self.assertEqual(row['proof_credit'],'NONE');self.assertNotIn('s3_expected_match',row)
    def test_exact_source_masks_and_no_fake_init_oracle(self):
        source=json.loads((r.HERE/'S32-SOURCE.json').read_text())[policy.LEAF]
        self.assertNotIn('is_initialized(',source);self.assertNotIn('ShadowMem',source)
        for expression in ['if 32 <= i && i < 40 { v[i].write(before[i]); }','if i < 8 || i >= 32 { v[i].write(before[i]); }']:
            self.assertIn(expression,source)
        self.assertIn('if (32 <= i && i < 40) && (i < dst || i >= dst + 8)',source)
        self.assertIn('if (i < 8 || i >= 32) && (i < dst || i >= dst + 8)',source)
