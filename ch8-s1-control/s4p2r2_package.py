# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""S3 workflow preparation gates; no submission/dispatch capability."""
from pathlib import Path
import copy
import s4p2r2_profile as p
VALIDATE_MINUTES=18
SOURCE_MINUTES=3
BRANCH='uninit-ci/ch8-s4p-'

def check_yaml(doc):
    from check_package import CHECKOUT_DEPTHS as LEGACY_CHECKOUT_DEPTHS
    CHECKOUT_DEPTHS={**LEGACY_CHECKOUT_DEPTHS,'control':8,'export':6}
    assert doc['on']=={'push':{'branches':[BRANCH+'*']}}
    assert doc['permissions']=={'contents':'read'} and doc['concurrency']=={'group':'ch8-s2-fork','cancel-in-progress':False}
    assert set(doc['jobs'])=={'s3_leaf'}
    job=doc['jobs']['s3_leaf']
    assert job['runs-on']=='ubuntu-24.04' and job['timeout-minutes']==180
    assert job['if']=="${{ github.repository == 'Tiramisu-Cake/kani' && github.event_name == 'push' }}"
    assert job['env']=={'S3_PROFILE':p.PROFILE} and 'strategy' not in job and 'needs' not in job
    expected=[('Begin setup budget',1),('Checkout CI control',2),('Validate control and synthetic wrapper',VALIDATE_MINUTES),
        ('Read immutable export pins',1),('Checkout production model export',5),('Checkout immutable upstream tool',2),
        ('Check all source identities',SOURCE_MINUTES),('Setup exact stock tool',15),('Build exact stock tool once',15),
        ('Run S3 actual leaves with bounded observations',126),('Materialize bounded fallback',2),('Upload bounded evidence',6)]
    assert [(s['name'],s['timeout-minutes']) for s in job['steps']]==expected
    steps={s['name']:s for s in job['steps']};cos={s['with']['path']:s for s in job['steps'] if s.get('uses')=='actions/checkout@v6'}
    assert set(cos)=={'control','export','tool'}
    assert {k:v['with']['fetch-depth'] for k,v in cos.items()}==CHECKOUT_DEPTHS
    assert all(s['with']['persist-credentials'] is False for s in cos.values())
    assert cos['control']['with']['ref']=='${{ github.sha }}'
    assert cos['export']['with']['ref']=='${{ steps.pins.outputs.std }}' and cos['export']['with']['submodules'] is True
    assert cos['tool']['with']['ref']=='${{ steps.pins.outputs.tool }}'
    assert cos['export']['with']['repository']=='Tiramisu-Cake/verify-rust-std' and cos['tool']['with']['repository']=='model-checking/kani'
    assert steps['Validate control and synthetic wrapper']['run']=='python3 check_package.py control --repo ..\npython3 s4p2r2_validate.py\n'
    assert steps['Check all source identities']['run']=='python3 control/ch8-s1-control/runner.py check-source --std export --tool tool'
    assert steps['Setup exact stock tool']['uses']=='./tool/.github/actions/setup'
    assert steps['Build exact stock tool once']['run']=='python3 ../control/ch8-s1-control/check_package.py build --tool . --epoch "$SETUP_EPOCH" --out "$RECEIPT_ROOT/setup"'
    assert steps['Run S3 actual leaves with bounded observations']['run']=='python3 control/ch8-s1-control/s4p2r2_campaign.py run --std export --tool tool --out "$RECEIPT_ROOT"\n'
    assert steps['Materialize bounded fallback']['run']=='python3 control/ch8-s1-control/s4p2r2_campaign.py finish --out "$RECEIPT_ROOT"\n'
    assert steps['Materialize bounded fallback']['if']=='always()' and steps['Upload bounded evidence']['if']=='always()'
    upload=steps['Upload bounded evidence'];assert upload['uses']=='actions/upload-artifact@v4'
    assert upload['with']['if-no-files-found']=='error' and upload['with']['retention-days']==7
    assert upload['with']['path']=='${{ env.RECEIPT_ROOT }}/group-evidence.json.gz'
    assert not any(s.get('continue-on-error') or s.get('if') for s in job['steps'][:-2])
    return {'jobs':1,'serial':True,'max_runner_minutes':180,'checkout_depths':CHECKOUT_DEPTHS,
            'step_timeout_sum_minutes':sum(s[1] for s in expected),'setup_aggregate_seconds':1800,
            'campaign_envelope_seconds':6180,'native_status':'NOT_RUN','proof_credit':'NONE'}
