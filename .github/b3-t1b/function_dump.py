# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Strict CBMC 6.11.0 plain function display framing; no body normalization."""
import re

SEPARATOR = b'^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n'


def extract_functions(raw, model):
    """Keep raw stdout; split ONLY the exact get_goto_program status prefix.

    show_goto_functions.cpp prints one separator/header per available body;
    goto_program.cpp prints numbered source comments and END_FUNCTION.
    Unknown prefix, malformed body, missing terminator, duplicates fail closed.
    """
    banner = ("Reading GOTO program from '" + model + "'\n").encode('utf-8')
    if not raw.startswith(banner) or raw.count(banner) != 1:
        raise ValueError('missing, repeated or unexpected input-path status line')
    body = raw[len(banner):]
    if not body.startswith(SEPARATOR):
        raise ValueError('function dump has no available bodies or unknown prefix')
    names = set()
    instructions = 0
    for block in body.split(SEPARATOR)[1:]:
        header, newline, code = block.partition(b'\n')
        match = re.fullmatch(rb'.+ /\* (.+) \*/', header)
        if not newline or not match or match[1] in names:
            raise ValueError('missing/duplicate function header')
        names.add(match[1])
        locations = re.findall(rb'^        // [0-9]+ [^\n]+\n', code, re.M)
        ends = re.findall(rb'^(?:        | *[0-9]+: )END_FUNCTION\n', code, re.M)
        if not locations or len(ends) != 1 or not code.rstrip(b'\n').endswith(b'END_FUNCTION'):
            raise ValueError('missing instructions or complete END_FUNCTION body')
        instructions += len(locations)
    return body, banner, {'function_count': len(names), 'instruction_count': instructions}
