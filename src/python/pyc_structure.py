# Rebuilds the structure of compiled Python modules (.pyc) with the Python version that compiled them:
# imports, classes (with bases), functions with their exact parameter lists, docstrings and module constants,
# and the complete bytecode of every function body as comments, ready to be turned back into Python.
# Run by DropDecompiler as:  python -I pyc_structure.py  < jobs.json   ([{"pyc": path, "out": path}, ...])
import dis
import inspect
import json
import marshal
import sys
import types


def params(co, defaults=(), kwdefaults=None):
    names = list(co.co_varnames)
    n = co.co_argcount
    posonly = getattr(co, "co_posonlyargcount", 0)
    kwonly = co.co_kwonlyargcount
    kwdefaults = kwdefaults or {}
    out = []
    first_default = n - len(defaults)
    for i in range(n):
        out.append(names[i] + (f"={defaults[i - first_default]!r}" if i >= first_default else ""))
        if posonly and i == posonly - 1:
            out.append("/")
    idx = n
    if co.co_flags & inspect.CO_VARARGS:
        out.append("*" + names[n + kwonly])
    elif kwonly:
        out.append("*")
    out.extend(k + (f"={kwdefaults[k]!r}" if k in kwdefaults else "") for k in names[n:n + kwonly])
    idx = n + kwonly + (1 if co.co_flags & inspect.CO_VARARGS else 0)
    if co.co_flags & inspect.CO_VARKEYWORDS:
        out.append("**" + names[idx])
    return ", ".join(out)


CO_HAS_DOCSTRING = 0x4000000  # Python 3.14+


def is_class_body(co):
    return "__qualname__" in co.co_names and "__module__" in co.co_names


def docstring(co):
    if is_class_body(co) or co.co_name == "<module>":
        # Modules and class bodies store their docstring with STORE_NAME __doc__.
        ins = list(dis.get_instructions(co))
        for i, x in enumerate(ins):
            if x.opname == "STORE_NAME" and x.argval == "__doc__" and i and isinstance(ins[i - 1].argval, str):
                return ins[i - 1].argval
        return None
    if sys.version_info >= (3, 14) and not co.co_flags & CO_HAS_DOCSTRING:
        return None
    if co.co_consts and isinstance(co.co_consts[0], str) and co.co_name != "<module>":
        return co.co_consts[0]
    return None


def definition_info(parent, code):
    """Default values and decorators of a function, read from the code that defines it."""
    ins = list(dis.get_instructions(parent))
    at = next((i for i, x in enumerate(ins) if x.opname == "LOAD_CONST" and x.argval is code), None)
    if at is None:
        return (), {}, []
    defaults, kwdefaults = (), {}
    # Before the code object: the defaults tuple / kw-defaults dict, and the decorators being loaded.
    start = at
    while start > 0 and ins[start - 1].opname not in ("STORE_NAME", "STORE_GLOBAL", "STORE_FAST", "STORE_DEREF", "POP_TOP", "RESUME", "RETURN_VALUE", "NOP"):
        start -= 1
    before = ins[start:at]
    after = ins[at + 1:at + 8]
    flags = set()
    for x in after:
        if x.opname == "SET_FUNCTION_ATTRIBUTE":
            flags.add(str(x.argrepr))
        if x.opname == "MAKE_FUNCTION" and x.arg:
            if x.arg & 1:
                flags.add("defaults")
            if x.arg & 2:
                flags.add("kwdefaults")
    # Evaluate the instructions before the code object as expressions: decorators (possibly called with
    # arguments), then the defaults tuple and the keyword-defaults dict, in that order.
    stack = []
    for x in before:
        op = x.opname
        if op in ("LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF", "LOAD_FAST"):
            stack.append(("expr", str(x.argval)))
        elif op in ("LOAD_ATTR", "LOAD_METHOD") and stack:
            kind, v = stack.pop()
            stack.append(("expr", f"{v}.{x.argval}"))
        elif op == "LOAD_CONST":
            stack.append(("const", x.argval))
        elif op == "BUILD_CONST_KEY_MAP":
            keys = stack.pop()[1] if stack else ()
            vals = [stack.pop()[1] for _ in range(x.arg)][::-1] if len(stack) >= x.arg else []
            stack.append(("const", dict(zip(keys, vals))))
        elif op == "BUILD_MAP":
            items = [stack.pop()[1] for _ in range(2 * x.arg)][::-1] if len(stack) >= 2 * x.arg else []
            stack.append(("const", dict(zip(items[0::2], items[1::2]))))
        elif op == "BUILD_TUPLE":
            items = [stack.pop()[1] for _ in range(x.arg)][::-1] if len(stack) >= x.arg else []
            stack.append(("const", tuple(items)))
        elif op in ("CALL", "CALL_FUNCTION", "CALL_KW", "CALL_FUNCTION_KW", "PRECALL"):
            if op == "PRECALL":
                continue
            n = x.arg or 0
            kwnames = ()
            if op in ("CALL_KW", "CALL_FUNCTION_KW") and stack and stack[-1][0] == "const" and isinstance(stack[-1][1], tuple):
                kwnames = stack.pop()[1]
            args = [stack.pop() for _ in range(min(n, len(stack)))][::-1]
            fn = stack.pop()[1] if stack else "?"
            pos = args[:len(args) - len(kwnames)]
            kws = args[len(args) - len(kwnames):]
            text = ", ".join([a[1] if a[0] == "expr" else repr(a[1]) for a in pos] +
                             [f"{k}={a[1] if a[0] == 'expr' else repr(a[1])}" for k, a in zip(kwnames, kws)])
            stack.append(("expr", f"{fn}({text})"))
        elif op in ("PUSH_NULL", "KW_NAMES", "NOP", "CACHE"):
            if op == "KW_NAMES":
                stack.append(("const", x.argval))
    if "kwdefaults" in flags and stack and stack[-1][0] == "const" and isinstance(stack[-1][1], dict):
        kwdefaults = stack.pop()[1]
    if "defaults" in flags and stack and stack[-1][0] == "const" and isinstance(stack[-1][1], tuple):
        defaults = stack.pop()[1]
    decorators = [v if k == "expr" else repr(v) for k, v in stack]
    calls = 0
    for x in ins[at + 1:at + 20]:
        if x.opname.startswith("STORE_"):
            break
        if x.opname in ("CALL", "CALL_FUNCTION") and x.arg == 0:
            calls += 1
    return defaults, kwdefaults, decorators[-calls:] if calls else []


def class_bases(parent, code):
    """Base classes of a class: the arguments after its name in __build_class__(func, name, *bases)."""
    ins = list(dis.get_instructions(parent))
    at = next((i for i, x in enumerate(ins) if x.opname == "LOAD_CONST" and x.argval is code), None)
    if at is None:
        return []
    bases = []
    for x in ins[at + 1:at + 30]:
        if x.opname in ("CALL", "CALL_FUNCTION", "CALL_KW"):
            break
        if x.opname in ("LOAD_NAME", "LOAD_GLOBAL"):
            bases.append(str(x.argval))
        elif x.opname in ("LOAD_ATTR",) and bases:
            bases[-1] += "." + str(x.argval)
    return [b for b in bases if b != "object"]


def simple_assignments(co):
    """name = <constant> statements in a module or class body."""
    out = []
    ins = list(dis.get_instructions(co))
    for i, x in enumerate(ins[1:], 1):
        prev = ins[i - 1]
        if x.opname in ("STORE_NAME", "STORE_GLOBAL") and prev.opname == "LOAD_CONST" and not str(x.argval).startswith("__") \
                and not isinstance(prev.argval, types.CodeType):
            out.append(f"{x.argval} = {prev.argval!r}")
    return out


def bytecode(co, indent):
    lines = []
    for ins in dis.get_instructions(co):
        arg = ins.argrepr if ins.argrepr else ("" if ins.arg is None else str(ins.arg))
        line = f"{ins.opname} {arg}".rstrip()
        if ins.starts_line not in (None, False) and getattr(ins, "line_number", None):
            line = f"{line}    # line {ins.line_number}"
        lines.append(f"{indent}#   {ins.offset:>4}  {line}")
    return lines


def imports(co):
    out = []
    ins = list(dis.get_instructions(co))
    for i, x in enumerate(ins):
        if x.opname == "IMPORT_NAME":
            module = x.argval
            nxt = ins[i + 1] if i + 1 < len(ins) else None
            frm = []
            pairs = []
            for y in ins[i + 1:]:
                if y.opname == "IMPORT_FROM":
                    frm.append(y.argval)
                    pairs.append([y.argval, None])
                elif y.opname.startswith("STORE_") and pairs and pairs[-1][1] is None:
                    pairs[-1][1] = y.argval
                elif not y.opname.startswith("STORE_"):
                    break
            if len(pairs) == 1 and "." in module and pairs[0][0] == module.split(".")[-1] and len(frm) == 1 and pairs[0][1]:
                # "import a.b as c" compiles to IMPORT_NAME a.b, IMPORT_FROM b, STORE c
                out.append(f"import {module} as {pairs[0][1]}")
            elif frm:
                frm = [f"{n} as {s}" if s and s != n else n for n, s in pairs]
                out.append(f"from {module} import {', '.join(dict.fromkeys(frm))}")
            elif nxt is not None and nxt.opname in ("STORE_NAME", "STORE_GLOBAL") and nxt.argval != module.split(".")[0]:
                out.append(f"import {module} as {nxt.argval}")
            else:
                out.append(f"import {module}")
    return list(dict.fromkeys(out))


def emit(co, indent, out, with_code=True):
    for const in co.co_consts:
        if not isinstance(const, types.CodeType) or const.co_name.startswith("<"):
            continue
        doc = docstring(const)
        defaults, kwdefaults, decorators = definition_info(co, const)
        for d in decorators:
            out.append(f"{indent}@{d}")
        if is_class_body(const):
            bases = class_bases(co, const)
            out.append(f"{indent}class {const.co_name}{'(' + ', '.join(bases) + ')' if bases else ''}:")
            if doc:
                out.append(f'{indent}    """{doc}"""')
            for a in simple_assignments(const):
                out.append(f"{indent}    {a}")
            before = len(out)
            emit(const, indent + "    ", out, with_code)
            if len(out) == before and not doc:
                out.append(f"{indent}    pass")
            out.append("")
        else:
            kw = "async def" if const.co_flags & inspect.CO_COROUTINE else "def"
            out.append(f"{indent}{kw} {const.co_name}({params(const, defaults, kwdefaults)}):")
            if doc:
                out.append(f'{indent}    """{doc}"""')
            calls = sorted({x.argval for x in dis.get_instructions(const) if x.opname in ("LOAD_GLOBAL", "LOAD_ATTR", "LOAD_METHOD") and isinstance(x.argval, str)})
            if calls:
                out.append(f"{indent}    # uses: {', '.join(calls[:40])}")
            out.append(f"{indent}    ...  # body: bytecode below")
            if with_code:
                out.extend(bytecode(const, indent + "    "))
            nested = len(out)
            emit(const, indent + "    ", out, with_code)
            if len(out) == nested:
                pass
            out.append("")


def structure(path):
    data = open(path, "rb").read()
    co = marshal.loads(data[16:])
    out = [f"# Structure of {co.co_filename or path} rebuilt from Python {sys.version_info.major}.{sys.version_info.minor} bytecode by DropDecompiler.",
           "# Imports, classes, function signatures and docstrings are exact; function bodies are the bytecode in the comments.", ""]
    doc = docstring(co)
    if doc:
        out += [f'"""{doc}"""', ""]
    out += imports(co)
    out.append("")
    out += simple_assignments(co)
    out.append("")
    names = [c for c in co.co_names if not c.startswith("__")]
    emit(co, "", out)
    out.append("# --- module-level code ---")
    out.extend(bytecode(co, ""))
    return "\n".join(out) + "\n"


def main():
    jobs = json.load(sys.stdin)
    done = 0
    for job in jobs:
        try:
            text = structure(job["pyc"])
            with open(job["out"], "w", encoding="utf-8") as f:
                f.write(text)
            done += 1
        except Exception as e:  # noqa: BLE001 - report and continue with the next module
            print(f"FAILED {job['pyc']}: {e}", file=sys.stderr)
    print(json.dumps({"done": done}))


if __name__ == "__main__":
    main()
