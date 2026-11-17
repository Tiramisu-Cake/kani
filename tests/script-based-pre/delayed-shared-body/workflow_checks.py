# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import re

def workflow_expressions(text):
    """Check the workflow's simple expressions against GitHub's context table."""
    # https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability
    job_env = set("github needs strategy matrix vars secrets inputs".split())
    step = job_env | {"job", "runner", "env", "steps"}
    status = {"always", "cancelled", "success", "failure"}
    stack = []
    block = None
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if block and indent > block[0]:
            path = block[1]
        else:
            block = None
            key = re.match(r"^( *)(- )?([A-Za-z_][\w-]*):(?:\s|$)", line)
            if key:
                depth = indent + (2 if key[2] else 0)
                while stack and stack[-1][0] >= depth:
                    stack.pop()
                stack.append((depth, key[3]))
                path = tuple(item[1] for item in stack)
                if line[key.end():].strip() in ("|", "|-", "|+", ">", ">-", ">+"):
                    block = (depth, path)
            else:
                path = ()
        expressions = re.findall(r"\$\{\{(.*?)\}\}", line)
        if line.count("${{") != len(expressions):
            raise ValueError(f"line {number}: malformed or multiline expression")
        for expression in expressions:
            if len(path) >= 4 and path[0] == "jobs" and path[2] == "env":
                contexts, functions = job_env, set()
            elif len(path) >= 4 and path[0] == "jobs" and path[2] == "steps":
                field = path[3]
                if field not in ("env", "with", "run", "name", "if"):
                    raise ValueError(f"line {number}: unreviewed step expression location")
                contexts = step - {"secrets"} if field == "if" else step
                functions = status if field == "if" else set()
            else:
                raise ValueError(f"line {number}: unreviewed expression location {path}")
            expression = expression.strip()
            lookup = re.fullmatch(r"([A-Za-z_]\w*)(?:\.[A-Za-z_][\w-]*)+", expression)
            call = re.fullmatch(r"([A-Za-z_]\w*)\(\)", expression)
            if lookup and lookup[1] in contexts:
                pass
            elif call and call[1] in functions:
                pass
            else:
                raise ValueError(f"line {number}: unavailable context/function or unreviewed syntax: {expression}")
            rows.append({"line": number, "key": ".".join(path), "expression": expression})
    return rows
