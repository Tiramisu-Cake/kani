"""Validate-only memoization of the pure lexer by complete input text.

No gate reports, source reads, identities, test results or exceptions are cached.
Every caller gets a fresh token list; immutable (spelling,line) pairs are shared.
The context restores all lexers. Production/prebuild/runtime paths never use it.
"""
from contextlib import contextmanager,ExitStack
from functools import lru_cache
from importlib import import_module
from unittest.mock import patch

@contextmanager
def cached_tokens(names=('cfg_pfc','s3_cfg_pfc','s32_cfg_pfc','s34_cfg_pfc','s4p_cfg_pfc')):
    stats={}
    with ExitStack() as stack:
        for name in names:
            module=import_module(name);original=module.tokens
            def make(original):
                @lru_cache(maxsize=32)
                def cached(text):return tuple(original(text))
                def tokens(text):
                    if not isinstance(text,str):return original(text)
                    return list(cached(text))
                return cached,tokens
            cache,wrapper=make(original);stats[name]=cache
            stack.enter_context(patch.object(module,'tokens',wrapper))
        yield stats
