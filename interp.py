"""A small evaluator for the code a model commits. Python never runs that code.

The reply is parsed with `ast` and walked by this evaluator, which knows only a
whitelist of node types, builtins and methods: enough for guard functions over
dicts, strings and numbers. Anything else raises Unreadable, and the trial is
scored as unreadable rather than guessed at. There is no attribute access
outside the listed methods, no import, no I/O, and a step limit.

  run(source, "is_authorized", (user, resource)) -> ("value", v) | ("raise", kind)
"""
import ast
import textwrap

STEPS = 20000


class Unreadable(Exception):
    """The code uses something the evaluator does not model."""


class _Raise(Exception):
    def __init__(self, kind):
        self.kind = kind


class _Return(Exception):
    def __init__(self, value):
        self.value = value


TYPES = {"dict": dict, "str": str, "int": int, "list": list, "tuple": tuple, "set": set, "bool": bool,
         "float": float, "frozenset": frozenset}
BUILTINS = {"len": len, "str": str, "int": int, "bool": bool, "set": set, "frozenset": frozenset,
            "tuple": tuple, "list": list, "min": min, "max": max, "abs": abs, "any": any, "all": all,
            "sorted": sorted, "sum": sum, "range": range, "enumerate": enumerate, "zip": zip, "reversed": reversed}
METHODS = {dict: {"get", "keys", "values", "items"},
           str: {"lower", "upper", "strip", "lstrip", "rstrip", "startswith", "endswith", "casefold", "split",
                 "rsplit", "partition", "rpartition", "replace", "find", "rfind", "count", "index", "isdigit",
                 "isalnum", "isalpha", "removeprefix", "removesuffix", "join"},
           list: {"count", "index"}, tuple: {"count", "index"}, set: set(), frozenset: set()}
NOOP_ROOTS = {"logging", "logger", "log", "warnings", "print"}
# pure string functions of os.path, read as posixpath: the stand has no file system,
# so abspath and realpath (which would touch it) are read as normpath of an absolute path
import posixpath
PATH_FUNCS = {name: getattr(posixpath, name) for name in ("normpath", "join", "basename", "dirname", "split",
                                                          "splitext", "commonpath", "commonprefix", "isabs", "relpath")}
PATH_FUNCS.update(abspath=posixpath.normpath, realpath=posixpath.normpath)
# other pure functions of the standard library a guard may reasonably call: parsing a URL,
# matching a regular expression, and getattr on a plain value (a dict has no attributes)
import re as _re
import urllib.parse as _urlparse


def _getattr(obj, name, *default):
    if isinstance(obj, (dict, list, tuple, set, str, int, float, bool)) or obj is None:
        if default:
            return default[0]
        raise _Raise("AttributeError")
    raise Unreadable("getattr")


URL_FUNCS = {name: getattr(_urlparse, name) for name in ("urlparse", "urlsplit", "unquote", "quote", "urljoin")}
RE_FUNCS = {name: getattr(_re, name) for name in ("match", "search", "fullmatch", "compile", "findall", "escape")}
MODULE_FUNCS = {"os.path": PATH_FUNCS, "posixpath": PATH_FUNCS, "ntpath": PATH_FUNCS, "urllib.parse": URL_FUNCS,
                "re": RE_FUNCS}
PATH_ROOTS = set(MODULE_FUNCS)
# attributes and methods of the objects those functions return
RESULT_ATTRS = {"scheme", "netloc", "hostname", "port", "path", "query", "fragment", "username", "password", "params"}
RESULT_METHODS = {_re.Pattern: {"match", "search", "fullmatch", "findall"}, _re.Match: {"group", "groups", "start", "end"}}
CMP = {ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b, ast.Lt: lambda a, b: a < b,
       ast.LtE: lambda a, b: a <= b, ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
       ast.Is: lambda a, b: a is b, ast.IsNot: lambda a, b: a is not b,
       ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b}
BIN = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
       ast.FloorDiv: lambda a, b: a // b, ast.Mod: lambda a, b: a % b, ast.Div: lambda a, b: a / b,
       ast.BitAnd: lambda a, b: a & b, ast.BitOr: lambda a, b: a | b}


class Machine:
    def __init__(self, tree):
        self.steps = 0
        self.funcs = {}
        self.globals = {}
        self.imported = {}  # `from os.path import normpath`: name -> the function
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                self.funcs[node.name] = node
            elif isinstance(node, ast.ImportFrom) and node.module in MODULE_FUNCS:
                for alias in node.names:
                    if alias.name in MODULE_FUNCS[node.module]:
                        self.imported[alias.asname or alias.name] = MODULE_FUNCS[node.module][alias.name]
            elif isinstance(node, (ast.Import, ast.ImportFrom, ast.ClassDef)):
                continue
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                continue
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self.stmt(node, self.globals)
            elif isinstance(node, ast.If):  # `if __name__ == "__main__":`
                continue
            else:
                raise Unreadable(type(node).__name__)

    def tick(self):
        self.steps += 1
        if self.steps > STEPS:
            raise Unreadable("step limit")

    # --- statements ---
    def call(self, name, args):
        fn = self.funcs.get(name)
        if fn is None:
            raise Unreadable(f"no function {name}")
        a = fn.args
        if a.vararg or a.kwarg or a.kwonlyargs or a.posonlyargs:
            raise Unreadable("signature")
        params = [p.arg for p in a.args]
        defaults = [self.expr(d, self.globals) for d in a.defaults]
        if len(args) > len(params) or len(args) < len(params) - len(defaults):
            raise _Raise("TypeError")
        env = dict(zip(params, args))
        for p, d in zip(params[len(params) - len(defaults):], defaults):
            env.setdefault(p, d)
        try:
            self.block(fn.body, env)
        except _Return as r:
            return r.value
        return None

    def block(self, body, env):
        for node in body:
            self.stmt(node, env)

    def stmt(self, node, env):
        self.tick()
        if isinstance(node, ast.Return):
            raise _Return(self.expr(node.value, env) if node.value else None)
        if isinstance(node, ast.If):
            return self.block(node.body if self.expr(node.test, env) else node.orelse, env)
        if isinstance(node, ast.Assign):
            value = self.expr(node.value, env)
            for target in node.targets:
                self.assign(target, value, env)
            return
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.assign(node.target, self.expr(node.value, env), env)
            return
        if isinstance(node, ast.Expr):
            if isinstance(node.value, ast.Constant):
                return
            if isinstance(node.value, ast.Call) and self.root(node.value.func) in NOOP_ROOTS:
                return
            if isinstance(node.value, ast.Call) and self.side_effect_only(node.value.func):
                return
            self.expr(node.value, env)
            return
        if isinstance(node, ast.Pass):
            return
        if isinstance(node, ast.AugAssign):
            if type(node.op) not in BIN:
                raise Unreadable("operator")
            self.assign(node.target, BIN[type(node.op)](self.expr(node.target, env), self.expr(node.value, env)), env)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):  # an import inside the function: the same whitelist
            if isinstance(node, ast.ImportFrom) and node.module in MODULE_FUNCS:
                for alias in node.names:
                    if alias.name in MODULE_FUNCS[node.module]:
                        self.imported[alias.asname or alias.name] = MODULE_FUNCS[node.module][alias.name]
            return
        if isinstance(node, ast.Raise):
            raise _Raise(self.exc_name(node.exc))
        if isinstance(node, ast.Assert):
            if not self.expr(node.test, env):
                raise _Raise("AssertionError")
            return
        if isinstance(node, ast.Try):
            try:
                self.block(node.body, env)
            except _Raise as e:
                for handler in node.handlers:
                    if self.catches(handler, e.kind):
                        self.block(handler.body, env)
                        break
                else:
                    raise
            else:
                self.block(node.orelse, env)
            finally:
                self.block(node.finalbody, env)
            return
        if isinstance(node, ast.For):
            for item in self.iterable(self.expr(node.iter, env)):
                self.assign(node.target, item, env)
                self.block(node.body, env)
            return self.block(node.orelse, env)
        raise Unreadable(type(node).__name__)

    def assign(self, target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            values = list(self.iterable(value))
            if len(values) != len(target.elts):
                raise _Raise("ValueError")
            for t, v in zip(target.elts, values):
                self.assign(t, v, env)
        else:
            raise Unreadable("assignment target")

    @staticmethod
    def root(node):
        while isinstance(node, ast.Attribute):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    def side_effect_only(self, func):
        """A call whose result is thrown away, to a function the reply did not define
        and whose name says it writes a log: it cannot change what is returned."""
        return (isinstance(func, ast.Name) and func.id not in self.funcs
                and func.id.split("_")[0] in ("log", "audit", "record", "emit", "write", "notify"))

    @staticmethod
    def exc_name(node):
        if node is None:
            return "Exception"
        if isinstance(node, ast.Call):
            node = node.func
        return node.id if isinstance(node, ast.Name) else "Exception"

    @staticmethod
    def catches(handler, kind):
        if handler.type is None:
            return True
        names = [n.id for n in (handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type])
                 if isinstance(n, ast.Name)]
        parents = {"KeyError": {"LookupError"}, "IndexError": {"LookupError"}}
        return any(n in ("Exception", "BaseException", kind) or n in parents.get(kind, ()) for n in names)

    @staticmethod
    def iterable(value):
        if isinstance(value, (list, tuple, set, frozenset, dict, str, range, enumerate, zip, reversed)):
            return list(value)
        raise _Raise("TypeError")

    # --- expressions ---
    def expr(self, node, env):
        self.tick()
        try:
            return self._expr(node, env)
        except (_Raise, _Return, Unreadable):
            raise
        except KeyError:
            raise _Raise("KeyError")
        except (TypeError, AttributeError):
            raise _Raise("TypeError")
        except (ValueError, IndexError) as e:
            raise _Raise(type(e).__name__)

    def _expr(self, node, env):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if node.id in self.globals:
                return self.globals[node.id]
            if node.id in TYPES:
                return TYPES[node.id]
            raise Unreadable(f"name {node.id}")
        if isinstance(node, ast.BoolOp):
            value = None
            for v in node.values:
                value = self.expr(v, env)
                if isinstance(node.op, ast.And) and not value or isinstance(node.op, ast.Or) and value:
                    return value
            return value
        if isinstance(node, ast.UnaryOp):
            v = self.expr(node.operand, env)
            if isinstance(node.op, ast.Not):
                return not v
            if isinstance(node.op, ast.USub):
                return -v
            raise Unreadable("unary")
        if isinstance(node, ast.BinOp):
            if type(node.op) not in BIN:
                raise Unreadable("operator")
            return BIN[type(node.op)](self.expr(node.left, env), self.expr(node.right, env))
        if isinstance(node, ast.Compare):
            left = self.expr(node.left, env)
            for op, right in zip(node.ops, node.comparators):
                right = self.expr(right, env)
                if not CMP[type(op)](left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.IfExp):
            return self.expr(node.body if self.expr(node.test, env) else node.orelse, env)
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Slice):
                lo, hi, step = (self.expr(x, env) if x is not None else None
                                for x in (node.slice.lower, node.slice.upper, node.slice.step))
                return self.expr(node.value, env)[lo:hi:step]
            return self.expr(node.value, env)[self.expr(node.slice, env)]
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            items = [self.expr(e, env) for e in node.elts]
            return {ast.Tuple: tuple, ast.List: list, ast.Set: set}[type(node)](items)
        if isinstance(node, ast.Dict):
            if any(k is None for k in node.keys):
                raise Unreadable("dict unpacking")
            return {self.expr(k, env): self.expr(v, env) for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.JoinedStr):
            return ""
        if isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            return self.comprehension(node, env)
        if isinstance(node, ast.Call):
            return self.call_expr(node, env)
        if isinstance(node, ast.Attribute):
            if ast.unparse(node) in ("os.sep", "posixpath.sep", "os.path.sep"):
                return "/"
            if self.root(node) in env or self.root(node) in self.globals:
                obj = self.expr(node.value, env)
                if isinstance(obj, (_urlparse.ParseResult, _urlparse.SplitResult)) and node.attr in RESULT_ATTRS:
                    return getattr(obj, node.attr)
                if isinstance(obj, (dict, list, tuple, set, str, int, float, bool)) or obj is None:
                    raise _Raise("AttributeError")  # an attribute of a plain value
        raise Unreadable(type(node).__name__)

    def comprehension(self, node, env):
        if len(node.generators) != 1 or node.generators[0].is_async:
            raise Unreadable("comprehension")
        gen = node.generators[0]
        out = []
        for item in self.iterable(self.expr(gen.iter, env)):
            local = dict(env)
            self.assign(gen.target, item, local)
            if all(self.expr(c, local) for c in gen.ifs):
                out.append(self.expr(node.elt, local))
        return set(out) if isinstance(node, ast.SetComp) else out

    def call_expr(self, node, env):
        if node.keywords:
            raise Unreadable("keyword arguments")
        args = [self.expr(a, env) for a in node.args]
        f = node.func
        if isinstance(f, ast.Name):
            if f.id in self.funcs:
                return self.call(f.id, args)
            if f.id in self.imported:
                return self.imported[f.id](*args)
            if f.id == "getattr":
                return _getattr(*args)
            if f.id == "isinstance":
                kinds = args[1] if isinstance(args[1], tuple) else (args[1],)
                return isinstance(args[0], tuple(type(None) if k is None else k for k in kinds))
            if f.id == "type" and len(args) == 1:
                return type(args[0])
            if f.id in BUILTINS:
                return BUILTINS[f.id](*args)
            raise Unreadable(f"call {f.id}")
        if isinstance(f, ast.Attribute):
            module = ast.unparse(f.value)
            if module in MODULE_FUNCS and f.attr in MODULE_FUNCS[module]:
                return MODULE_FUNCS[module][f.attr](*args)
            if module in MODULE_FUNCS:
                raise Unreadable(f"{module}.{f.attr}")  # exists, isdir, ...: a file system the stand does not have
            obj = self.expr(f.value, env)
            for kind, methods in RESULT_METHODS.items():
                if isinstance(obj, kind) and f.attr in methods:
                    return getattr(obj, f.attr)(*args)
            if f.attr in METHODS.get(type(obj), ()):
                result = getattr(obj, f.attr)(*args)
                return list(result) if f.attr in ("keys", "values", "items") else result
            if obj is None or isinstance(obj, (int, float, bool, str, dict, list, tuple, set)):
                raise _Raise("AttributeError")
        raise Unreadable("call")


def run(source, name, args):
    """Evaluate `name(*args)` in `source`. Raises Unreadable, SyntaxError."""
    tree = ast.parse(textwrap.dedent(source))
    m = Machine(tree)
    try:
        return "value", m.call(name, [_copy(a) for a in args])
    except _Raise as e:
        return "raise", e.kind


def _copy(v):
    return {k: _copy(x) for k, x in v.items()} if isinstance(v, dict) else v
