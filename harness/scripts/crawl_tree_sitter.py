"""
Deterministic replacement for the LLM-driven /crawl-tree-sitter skill.

Runs `tree-sitter parse -x <file>` per source file (same CLI call the LLM
skill used to make) and walks the resulting AST XML with real Python code
instead of LLM text-interpretation, so file counts, role classification, and
security_priority scores stop drifting run-to-run on an unchanged repo.

Output schema matches .claude/commands/crawl-tree-sitter.md's crawl-output.json
exactly, so no downstream skill (joern-parse, find-vulns-*) needs to change.

Node-type names below were confirmed against real `tree-sitter parse -x`
output for tree-sitter-typescript, tree-sitter-python, and tree-sitter-java
(checked directly, not assumed from docs) — see conversation history for the
sample files used.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

EXCLUDE_DIRS = {
    ".git", "node_modules", "dist", "build", ".next", "coverage", ".cache",
    "out", "target", "__pycache__", ".venv", "venv", "env", ".idea",
}
TEST_DIR_NAMES = {"__tests__", "test", "tests", "spec"}
TEST_FILE_SUFFIXES = (".test.ts", ".spec.ts", ".test.py", "_test.py", "Test.java")
MAX_LINES = 5000

LANG_GRAMMAR = {
    "typescript": (".ts", ".tsx", ".js", ".jsx"),
    "javascript": (".ts", ".tsx", ".js", ".jsx"),
    "python": (".py",),
    "java": (".java", ".kt"),
    "kotlin": (".java", ".kt"),
}
EXT_TO_LANG = {
    ".ts": "typescript", ".tsx": "typescript", ".js": "typescript", ".jsx": "typescript",
    ".py": "python",
    ".java": "java", ".kt": "java",
}

ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "use"}
_XML_INVALID_CONTROL_CHARS = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)
SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
EVAL_NAME = re.compile(r"eval", re.IGNORECASE)


# ── generic XML/AST helpers ─────────────────────────────────────────────────

def iter_descendants(elem):
    """Depth-first walk of every descendant element (not including elem itself)."""
    for child in list(elem):
        yield child
        yield from iter_descendants(child)


def child_by_field(elem, field_name):
    for child in list(elem):
        if child.get("field") == field_name:
            return child
    return None


def children_by_tag(elem, tag):
    return [c for c in list(elem) if c.tag == tag]


def line_of(elem) -> int:
    """1-indexed line number — tree-sitter's srow is 0-indexed."""
    return int(elem.get("srow", "0")) + 1


def source_text(lines, elem) -> str:
    """Reconstruct the exact original source substring for elem's span,
    rather than trusting XML .text (which mangles entities/whitespace)."""
    sr, sc = int(elem.get("srow")), int(elem.get("scol"))
    er, ec = int(elem.get("erow")), int(elem.get("ecol"))
    if sr == er:
        return lines[sr][sc:ec] if sr < len(lines) else ""
    parts = [lines[sr][sc:]] if sr < len(lines) else []
    for r in range(sr + 1, er):
        if r < len(lines):
            parts.append(lines[r])
    if er < len(lines):
        parts.append(lines[er][:ec])
    return "\n".join(parts)


def identifier_name(elem) -> Optional[str]:
    """For an `identifier`/`property_identifier`/`type_identifier` node, its
    display text is the element's own .text (leaf node, no children)."""
    if elem is None:
        return None
    return (elem.text or "").strip() or None


def trim_snippet(s: str, limit: int = 120) -> str:
    s = " ".join(s.split())
    return s if len(s) <= limit else s[:limit]


@dataclass
class FileFacts:
    path: str
    language: str
    lines: int
    functions: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    routes: list = field(default_factory=list)
    user_input_sources: list = field(default_factory=list)
    dangerous_patterns: list = field(default_factory=list)
    calls_to: list = field(default_factory=list)
    class_names: list = field(default_factory=list)
    has_jsx: bool = False
    has_interaction_handlers: bool = False
    is_middleware_shape: bool = False
    is_config_shape: bool = False


# ── TypeScript / JavaScript extraction ──────────────────────────────────────

def _member_chain_text(elem) -> Optional[str]:
    """member_expression -> 'a.b.c' textual chain, or None if not a plain
    identifier/member_expression chain (e.g. a call result)."""
    if elem.tag == "identifier":
        return identifier_name(elem)
    if elem.tag == "member_expression":
        obj = child_by_field(elem, "object")
        prop = child_by_field(elem, "property")
        obj_text = _member_chain_text(obj) if obj is not None else None
        prop_text = identifier_name(prop) if prop is not None else None
        if obj_text and prop_text:
            return f"{obj_text}.{prop_text}"
    return None


def extract_ts_js(root, lines) -> FileFacts:
    facts = FileFacts(path="", language="typescript", lines=len(lines))

    # A member_expression nested as another member_expression's `object` field
    # (e.g. the `req.body` inside `req.body.email`) is a sub-chain, not an
    # independent usage — only the outermost/maximal chain should be recorded,
    # otherwise every req.body.X access also emits a spurious bare req.body hit.
    consumed_as_object = {
        id(child_by_field(m, "object"))
        for m in iter_descendants(root)
        if m.tag == "member_expression" and child_by_field(m, "object") is not None
    }

    for imp in iter_descendants(root):
        if imp.tag == "import_statement":
            src = child_by_field(imp, "source")
            src_text = source_text(lines, src).strip("'\"") if src is not None else None
            names = [identifier_name(i) for i in iter_descendants(imp) if i.tag == "identifier" and i.get("field") == "name"]
            facts.imports.append({"source": src_text, "names": [n for n in names if n]})

    for node in iter_descendants(root):
        if node.tag in ("function_declaration", "arrow_function", "function_expression", "method_definition"):
            name_el = child_by_field(node, "name")
            name = identifier_name(name_el) if name_el is not None else None
            params_el = child_by_field(node, "parameters")
            params = []
            if params_el is not None:
                for p in list(params_el):
                    ident = p if p.tag == "identifier" else None
                    if ident is None:
                        for d in iter_descendants(p):
                            if d.tag == "identifier":
                                ident = d
                                break
                    if ident is not None:
                        params.append(identifier_name(ident))
            is_async = (node.text or "").strip().startswith("async")
            facts.functions.append({
                "name": name, "line": line_of(node), "params": params,
                "is_async": is_async, "exported": False,
            })

        if node.tag == "call_expression":
            fn = child_by_field(node, "function")
            args = child_by_field(node, "arguments")
            chain = _member_chain_text(fn) if fn is not None else None
            fn_name = identifier_name(fn) if fn is not None and fn.tag == "identifier" else None
            callee_display = chain or fn_name
            if callee_display:
                facts.calls_to.append(callee_display)

            # route registrations: X.get|post|put|delete|patch|use("<path>", handler)
            if fn is not None and fn.tag == "member_expression":
                prop = child_by_field(fn, "property")
                method_name = identifier_name(prop)
                if method_name in ROUTE_METHODS and args is not None:
                    arg_children = [c for c in list(args) if c.tag not in ("(", ")")]
                    # Require a string-literal first arg starting with "/" —
                    # an Express/Router route registration always has a URL
                    # path string. Without both checks, unrelated `.get`/
                    # `.use`/`.put` calls (a config library's `config.get(
                    # 'application.name')`, Cypress's `cy.get('selector')`,
                    # non-Express builder objects) got misdetected as routes —
                    # seen on real code: 195/356 Juice Shop files were
                    # wrongly flagged entry_point before this check existed.
                    if (arg_children and arg_children[0].tag == "string"
                            and source_text(lines, arg_children[0]).strip("'\"`").startswith("/")):
                        path_str = source_text(lines, arg_children[0]).strip("'\"`")
                        handler_name = None
                        for a in arg_children[1:]:
                            if a.tag == "identifier":
                                handler_name = identifier_name(a)
                        facts.routes.append({
                            "method": method_name.upper(), "path": path_str,
                            "handler": handler_name, "line": line_of(node),
                        })

            # dangerous: eval / *eval* wrappers / new Function
            if fn_name and (fn_name == "eval" or EVAL_NAME.search(fn_name)):
                facts.dangerous_patterns.append({
                    "type": "eval", "line": line_of(node),
                    "snippet": trim_snippet(source_text(lines, node)),
                })
            # dangerous: vm.runInContext / runInNewContext / createContext
            if chain and chain.startswith("vm.") and chain.split(".")[-1] in (
                "runInContext", "runInNewContext", "createContext", "Script"):
                facts.dangerous_patterns.append({
                    "type": "eval", "line": line_of(node),
                    "snippet": trim_snippet(source_text(lines, node)),
                })
            # dangerous: child_process exec/spawn family
            if chain and chain.split(".")[-1] in (
                "exec", "spawn", "execFile", "execSync", "spawnSync"):
                facts.dangerous_patterns.append({
                    "type": "command_injection", "line": line_of(node),
                    "snippet": trim_snippet(source_text(lines, node)),
                })
            # dangerous: fs.readFile*/writeFile* with non-constant path
            if chain and chain.split(".")[-1] in (
                "readFile", "readFileSync", "writeFile", "writeFileSync",
                "createReadStream", "sendFile"):
                arg_children = [c for c in list(args) if c.tag not in ("(", ")")] if args is not None else []
                if arg_children and arg_children[0].tag != "string":
                    facts.dangerous_patterns.append({
                        "type": "path_traversal", "line": line_of(node),
                        "snippet": trim_snippet(source_text(lines, node)),
                    })
            # dangerous: fetch/axios/got/request with dynamic first arg
            base_name = (chain.split(".")[0] if chain else fn_name) or ""
            if base_name in ("fetch", "axios", "got", "request") or chain in (
                "http.get", "https.get"):
                arg_children = [c for c in list(args) if c.tag not in ("(", ")")] if args is not None else []
                if arg_children and arg_children[0].tag != "string":
                    facts.dangerous_patterns.append({
                        "type": "ssrf", "line": line_of(node),
                        "snippet": trim_snippet(source_text(lines, node)),
                    })
            # dangerous: crypto.createHash('md5'|'sha1')
            if chain == "crypto.createHash" and args is not None:
                arg_children = [c for c in list(args) if c.tag not in ("(", ")")]
                if arg_children and arg_children[0].tag == "string":
                    alg = source_text(lines, arg_children[0]).strip("'\"").lower()
                    if alg in ("md5", "sha1"):
                        facts.dangerous_patterns.append({
                            "type": "weak_hash", "line": line_of(node),
                            "snippet": trim_snippet(source_text(lines, node)),
                        })
            # dangerous: jwt.sign / jws.sign
            if chain and chain.split(".")[-1] == "sign" and chain.split(".")[0] in ("jwt", "jws"):
                facts.dangerous_patterns.append({
                    "type": "jwt_sign", "line": line_of(node),
                    "snippet": trim_snippet(source_text(lines, node)),
                })

        if node.tag == "assignment_expression":
            left = child_by_field(node, "left")
            if left is not None and left.tag == "member_expression":
                prop = child_by_field(left, "property")
                prop_name = identifier_name(prop)
                if prop_name in ("innerHTML", "outerHTML"):
                    facts.dangerous_patterns.append({
                        "type": "xss_innerHTML", "line": line_of(node),
                        "snippet": trim_snippet(source_text(lines, node)),
                    })

        if node.tag == "jsx_attribute":
            name_el = list(node)[0] if list(node) else None
            if name_el is not None and identifier_name(name_el) == "dangerouslySetInnerHTML":
                facts.dangerous_patterns.append({
                    "type": "xss_dangerouslySetInnerHTML", "line": line_of(node),
                    "snippet": trim_snippet(source_text(lines, node)),
                })
            if identifier_name(name_el) in ("onClick", "onChange", "onSubmit"):
                facts.has_interaction_handlers = True

        if node.tag == "jsx_element":
            facts.has_jsx = True

        if node.tag == "template_string":
            text = source_text(lines, node)
            has_sub = any(c.tag == "template_substitution" for c in list(node))
            if has_sub and SQL_KEYWORDS.search(text):
                facts.dangerous_patterns.append({
                    "type": "sql_template_literal", "line": line_of(node),
                    "snippet": trim_snippet(text),
                })

        if node.tag == "member_expression" and id(node) not in consumed_as_object:
            chain = _member_chain_text(node)
            if chain:
                parts = chain.split(".")
                if parts[0] in ("req", "request") and len(parts) >= 2 and parts[1] in (
                    "body", "query", "params", "headers", "cookies"):
                    facts.user_input_sources.append({
                        "type": f"req.{parts[1]}",
                        "field": parts[2] if len(parts) > 2 else None,
                        "line": line_of(node),
                    })
                if parts[0] == "document" and len(parts) >= 2 and parts[1] in ("URL", "referrer", "cookie"):
                    facts.user_input_sources.append({
                        "type": "document", "field": parts[1], "line": line_of(node),
                    })
                if chain in ("window.location.href", "window.location.search", "window.location.hash"):
                    facts.user_input_sources.append({
                        "type": "window.location", "field": parts[-1], "line": line_of(node),
                    })

    facts.is_middleware_shape = any(
        f["params"][:3] == ["req", "res", "next"] for f in facts.functions if len(f.get("params", [])) >= 3
    )
    return facts


# ── Python extraction ────────────────────────────────────────────────────────

PY_FLASK_DECORATOR_METHODS = {"route", "get", "post", "put", "delete", "patch"}
PY_DANGEROUS_SUBPROCESS = {"system", "popen"}
PY_DANGEROUS_SUBPROCESS_MOD = {"run", "call", "Popen", "check_output"}


def _py_attr_chain(elem) -> Optional[str]:
    if elem.tag == "identifier":
        return identifier_name(elem)
    if elem.tag == "attribute":
        obj = child_by_field(elem, "object")
        attr = child_by_field(elem, "attribute")
        obj_text = _py_attr_chain(obj) if obj is not None else None
        attr_text = identifier_name(attr) if attr is not None else None
        if obj_text and attr_text:
            return f"{obj_text}.{attr_text}"
    return None


def extract_python(root, lines) -> FileFacts:
    facts = FileFacts(path="", language="python", lines=len(lines))

    # Same nested-chain issue as the TS/JS extractor: `request.form.get` embeds
    # `request.form` as its own `attribute` node's `object` field, so only the
    # outermost chain should be recorded as a user-input-source hit.
    consumed_as_object = {
        id(child_by_field(m, "object"))
        for m in iter_descendants(root)
        if m.tag == "attribute" and child_by_field(m, "object") is not None
    }

    for node in iter_descendants(root):
        if node.tag == "import_statement":
            for dn in children_by_tag(node, "dotted_name"):
                idents = [identifier_name(i) for i in iter_descendants(dn) if i.tag == "identifier"]
                facts.imports.append({"source": ".".join([i for i in idents if i]), "names": []})
        if node.tag == "import_from_statement":
            module_dn = child_by_field(node, "module_name")
            module = ".".join(i.strip() for i in [identifier_name(x) for x in iter_descendants(module_dn)] if i) if module_dn is not None else None
            names = [identifier_name(i) for i in iter_descendants(node) if i.tag == "identifier" and i.get("field") == "name"]
            facts.imports.append({"source": module, "names": [n for n in names if n]})

        if node.tag == "class_definition":
            name_el = child_by_field(node, "name")
            if name_el is not None:
                facts.class_names.append(identifier_name(name_el))

        if node.tag in ("function_definition",):
            name_el = child_by_field(node, "name")
            params_el = child_by_field(node, "parameters")
            params = []
            if params_el is not None:
                for p in list(params_el):
                    if p.tag == "identifier":
                        params.append(identifier_name(p))
                    else:
                        for d in iter_descendants(p):
                            if d.tag == "identifier":
                                params.append(identifier_name(d))
                                break
            facts.functions.append({
                "name": identifier_name(name_el) if name_el is not None else None,
                "line": line_of(node), "params": params,
                "is_async": (node.text or "").strip().startswith("async"),
                "exported": True,
            })

        if node.tag == "decorated_definition":
            for dec in children_by_tag(node, "decorator"):
                call = dec.find("call")
                if call is None:
                    continue
                fn = child_by_field(call, "function")
                chain = _py_attr_chain(fn) if fn is not None else None
                if chain:
                    method_part = chain.split(".")[-1]
                    if method_part in PY_FLASK_DECORATOR_METHODS:
                        args = child_by_field(call, "arguments")
                        path_str = None
                        if args is not None:
                            for a in list(args):
                                if a.tag == "string":
                                    path_str = "".join(
                                        c.text or "" for c in iter_descendants(a) if c.tag == "string_content"
                                    )
                                    break
                        http_method = method_part.upper() if method_part != "route" else "ROUTE"
                        facts.routes.append({
                            "method": http_method, "path": path_str,
                            "handler": None, "line": line_of(dec),
                        })

        if node.tag == "call":
            fn = child_by_field(node, "function")
            args = child_by_field(node, "arguments")
            chain = _py_attr_chain(fn) if fn is not None else None
            fn_name = identifier_name(fn) if fn is not None and fn.tag == "identifier" else None
            callee_display = chain or fn_name
            if callee_display:
                facts.calls_to.append(callee_display)

            if fn_name in ("eval", "exec"):
                facts.dangerous_patterns.append({
                    "type": "eval", "line": line_of(node),
                    "snippet": trim_snippet(source_text(lines, node)),
                })
            if chain in ("os.system", "os.popen") or (
                chain and chain.startswith("subprocess.") and chain.split(".")[-1] in
                ("run", "call", "Popen", "check_output")
            ):
                arg_children = [c for c in list(args) if c.tag not in ("(", ")")] if args is not None else []
                if arg_children and arg_children[0].tag != "string":
                    facts.dangerous_patterns.append({
                        "type": "command_injection", "line": line_of(node),
                        "snippet": trim_snippet(source_text(lines, node)),
                    })
            if fn_name == "open":
                arg_children = [c for c in list(args) if c.tag not in ("(", ")")] if args is not None else []
                if arg_children and arg_children[0].tag != "string":
                    facts.dangerous_patterns.append({
                        "type": "path_traversal", "line": line_of(node),
                        "snippet": trim_snippet(source_text(lines, node)),
                    })
            if chain == "yaml.load":
                text = source_text(lines, node)
                if "SafeLoader" not in text:
                    facts.dangerous_patterns.append({
                        "type": "deserialization", "line": line_of(node),
                        "snippet": trim_snippet(text),
                    })
            if chain in ("pickle.loads", "marshal.loads"):
                facts.dangerous_patterns.append({
                    "type": "deserialization", "line": line_of(node),
                    "snippet": trim_snippet(source_text(lines, node)),
                })
            if chain and chain.split(".")[-1] in ("execute", "executemany"):
                text = source_text(lines, node)
                if "%" in text or ".format(" in text or re.search(r"f['\"]", text):
                    facts.dangerous_patterns.append({
                        "type": "sql_injection", "line": line_of(node),
                        "snippet": trim_snippet(text),
                    })

        if node.tag == "attribute" and id(node) not in consumed_as_object:
            chain = _py_attr_chain(node)
            if chain:
                parts = chain.split(".")
                if parts[0] == "request" and len(parts) >= 2 and parts[1] in (
                    "form", "args", "json", "data", "headers", "cookies"):
                    facts.user_input_sources.append({
                        "type": f"request.{parts[1]}",
                        "field": parts[2] if len(parts) > 2 else None,
                        "line": line_of(node),
                    })

    return facts


# ── Java extraction ──────────────────────────────────────────────────────────

SPRING_ANNOTATIONS = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "DeleteMapping": "DELETE", "PatchMapping": "PATCH",
}


def extract_java(root, lines) -> FileFacts:
    facts = FileFacts(path="", language="java", lines=len(lines))

    for node in iter_descendants(root):
        if node.tag == "import_declaration":
            idents = [identifier_name(i) for i in iter_descendants(node) if i.tag == "identifier"]
            facts.imports.append({"source": ".".join(i for i in idents if i), "names": []})

        if node.tag == "class_declaration":
            name_el = child_by_field(node, "name")
            if name_el is not None:
                facts.class_names.append(identifier_name(name_el))

        if node.tag == "method_declaration":
            name_el = child_by_field(node, "name")
            params_el = child_by_field(node, "parameters")
            params = []
            if params_el is not None:
                for p in children_by_tag(params_el, "formal_parameter"):
                    pname = child_by_field(p, "name")
                    if pname is not None:
                        params.append(identifier_name(pname))
            facts.functions.append({
                "name": identifier_name(name_el) if name_el is not None else None,
                "line": line_of(node), "params": params,
                "is_async": False, "exported": True,
            })
            for mod in children_by_tag(node, "modifiers"):
                for ann in list(mod):
                    if ann.tag in ("annotation", "marker_annotation"):
                        name_el2 = child_by_field(ann, "name")
                        ann_name = identifier_name(name_el2) if name_el2 is not None else None
                        if ann_name in SPRING_ANNOTATIONS:
                            path_str = None
                            args = child_by_field(ann, "arguments")
                            if args is not None:
                                for a in iter_descendants(args):
                                    if a.tag == "string_fragment":
                                        path_str = a.text
                                        break
                            facts.routes.append({
                                "method": SPRING_ANNOTATIONS[ann_name], "path": path_str,
                                "handler": identifier_name(name_el) if name_el is not None else None,
                                "line": line_of(node),
                            })

        if node.tag == "formal_parameter":
            for mod in children_by_tag(node, "modifiers"):
                for ann in list(mod):
                    if ann.tag in ("annotation", "marker_annotation"):
                        name_el = child_by_field(ann, "name")
                        ann_name = identifier_name(name_el) if name_el is not None else None
                        if ann_name in ("RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue"):
                            pname = child_by_field(node, "name")
                            facts.user_input_sources.append({
                                "type": f"@{ann_name}",
                                "field": identifier_name(pname) if pname is not None else None,
                                "line": line_of(node),
                            })

        if node.tag == "method_invocation":
            name_el = child_by_field(node, "name")
            obj_el = child_by_field(node, "object")
            method_name = identifier_name(name_el) if name_el is not None else None
            obj_chain = None
            if obj_el is not None:
                if obj_el.tag == "identifier":
                    obj_chain = identifier_name(obj_el)
                elif obj_el.tag == "field_access":
                    idents = [identifier_name(i) for i in iter_descendants(obj_el) if i.tag == "identifier"]
                    obj_chain = ".".join(i for i in idents if i)
            full = f"{obj_chain}.{method_name}" if obj_chain and method_name else method_name
            if full:
                facts.calls_to.append(full)

            if method_name in ("getParameter", "getHeader", "getCookies", "getInputStream", "getReader"):
                facts.user_input_sources.append({
                    "type": f"HttpServletRequest.{method_name}", "field": None, "line": line_of(node),
                })
            if method_name in ("executeQuery", "executeUpdate", "execute"):
                text = source_text(lines, node)
                if "+" in text:
                    facts.dangerous_patterns.append({
                        "type": "sql_injection", "line": line_of(node),
                        "snippet": trim_snippet(text),
                    })
            if obj_chain == "Runtime" and method_name == "exec":
                facts.dangerous_patterns.append({
                    "type": "command_injection", "line": line_of(node),
                    "snippet": trim_snippet(source_text(lines, node)),
                })

        if node.tag == "object_creation_expression":
            type_el = child_by_field(node, "type")
            type_name = identifier_name(type_el) if type_el is not None else None
            if type_name == "ProcessBuilder":
                facts.dangerous_patterns.append({
                    "type": "command_injection", "line": line_of(node),
                    "snippet": trim_snippet(source_text(lines, node)),
                })

    return facts


EXTRACTORS = {"typescript": extract_ts_js, "python": extract_python, "java": extract_java}


# ── role classification & scoring ───────────────────────────────────────────

def classify_role(facts: FileFacts, path: str) -> str:
    if facts.routes:
        return "entry_point"
    # Next.js App/Pages Router convention: file-based routing lives at the
    # repo-root pages/ or app/ directory specifically. A substring check
    # (`"/app/" in path`) instead of this prefix check false-matches any
    # Angular project, since Angular's own convention is `src/app/` for
    # every component — that previously flagged ~130 unrelated Angular
    # frontend files as entry_point on the real Juice Shop repo.
    norm = path.replace("\\", "/")
    if facts.language == "typescript" and (norm.startswith("pages/") or norm.startswith("app/")):
        return "entry_point"
    if facts.is_middleware_shape:
        return "middleware"
    lower = path.lower()
    base = Path(path).stem
    if base.endswith("Middleware") or base.endswith("Filter") or base.endswith("Interceptor"):
        return "middleware"
    if base.endswith("Service"):
        return "service"
    if base.endswith("Repository") or base.endswith("DAO") or base.endswith("Dao"):
        return "dao"
    if any(c in ("query", "execute", "executeQuery", "executeUpdate") for c in facts.calls_to) and (
        base.endswith("Repository") or base.endswith("Dao")
    ):
        return "dao"
    if facts.has_jsx and not facts.routes:
        return "component"
    if not facts.functions and not facts.routes:
        return "model"
    if re.search(r"\.config\.|constants?\.|settings\.|config\.", lower):
        return "config"
    return "util"


_UTILITY_SEGMENT_PATTERN = re.compile(
    r"^(.*_util|.*_helper|.*_manager|.*_extractor|.*_tool|utils?|helpers?|managers?|extractors?|tools?)$",
    re.IGNORECASE,
)


def _is_utility_path(path: str) -> bool:
    """True if any directory segment or the filename stem matches a
    utility/helper/manager/extractor/tool naming convention — checked
    per-segment (not a single filename-suffix regex) so a path like
    `ls_manager/downloaders.py` matches on its directory name even though
    the filename itself ("downloaders") doesn't match any pattern alone."""
    norm = path.replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return False
    stem = Path(parts[-1]).stem
    candidates = parts[:-1] + [stem]
    return any(_UTILITY_SEGMENT_PATTERN.match(seg) for seg in candidates)


def compute_priority(facts: FileFacts, path: str = "") -> int:
    tier5_types = {"eval", "sql_injection", "sql_template_literal", "xss_innerHTML",
                   "xss_dangerouslySetInnerHTML", "command_injection", "deserialization"}
    tier4_types = {"ssrf", "path_traversal", "jwt_sign", "weak_hash"}
    pattern_types = {p["type"] for p in facts.dangerous_patterns}

    if pattern_types & tier5_types:
        return 5
    if pattern_types & tier4_types:
        return 4
    if facts.user_input_sources or facts.has_interaction_handlers:
        return 3

    # A utility/manager/extractor/helper/tool-named file with real function
    # logic can process attacker-controlled data (a file path, bytes, a
    # user-uploaded video) passed in as a plain function parameter rather
    # than read directly from req.*/request.* — our own dangerous-pattern
    # and user-input-source detection above only recognizes the latter, so
    # such a file scores 1 and is silently excluded from the find-vulns scan
    # queue (which only includes security_priority >= 2) even when it's
    # reachable with real attacker-controlled input from an entry point
    # elsewhere. Confirmed gap during a gap-analysis review — floor these at
    # 2 (same tier as "calls into a risky file") so they always get at least
    # one LLM read pass; a file with zero function logic (pure constants/
    # types) still correctly falls through to tier 1.
    if facts.functions and _is_utility_path(path):
        return 2

    return 1  # tier 2 (cross-file call upgrade) applied in a second pass


def second_pass_priority(all_facts, priorities, calls_index) -> None:
    """Tier-2 rule: a file that CALLS into (not merely imports) a file already
    scored >=3 gets bumped to 2, unless it already scored higher on its own."""
    for path, facts in all_facts.items():
        if priorities[path] > 1:
            continue
        if facts.routes:
            priorities[path] = max(priorities[path], 2)
            continue
        called_files = set()
        for callee in facts.calls_to:
            short = callee.split(".")[-1]
            for target_path in calls_index.get(short, []):
                called_files.add(target_path)
        if any(priorities.get(cf, 0) >= 3 for cf in called_files):
            priorities[path] = max(priorities[path], 2)


# ── file discovery ───────────────────────────────────────────────────────────

def collect_files(repo_path: Path, languages):
    exts = set()
    for lang in languages:
        exts.update(LANG_GRAMMAR.get(lang, ()))
    if not exts:
        return []

    results = []
    for p in repo_path.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in exts:
            continue
        rel_parts = p.relative_to(repo_path).parts
        if any(part in EXCLUDE_DIRS for part in rel_parts):
            continue
        if any(part in TEST_DIR_NAMES for part in rel_parts):
            continue
        name = p.name
        if any(name.endswith(suf) for suf in TEST_FILE_SUFFIXES):
            continue
        results.append(p)
    return results


def find_ts_bin(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    import os
    home = os.environ.get("TREE_SITTER_HOME")
    if home and (Path(home) / "bin" / "tree-sitter").exists():
        return str(Path(home) / "bin" / "tree-sitter")
    found = shutil.which("tree-sitter")
    return found


def parse_file_xml(ts_bin: str, path: Path):
    try:
        proc = subprocess.run(
            [ts_bin, "parse", "-x", str(path)],
            capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        return None, "timeout"
    if proc.returncode != 0 and not proc.stdout.strip():
        return None, (proc.stderr or "parse_error")[:300]
    # tree-sitter's -x output doesn't escape raw control bytes that can appear
    # inside string-literal source content (seen in real files: several Juice
    # Shop codefix samples embed literal control characters in payload
    # strings), which is invalid XML 1.0 and breaks ET.fromstring. Strip
    # anything outside XML 1.0's allowed control-char set (tab/LF/CR) before
    # parsing rather than losing the whole file to one bad byte.
    cleaned = _XML_INVALID_CONTROL_CHARS.sub("", proc.stdout)
    # On a file with a real syntax error, tree-sitter still emits the full
    # (partial, error-recovered) XML tree but then ALSO appends a plain-text
    # diagnostic line after `</sources>` (e.g. `Parse: 0.64 ms ... (MISSING
    # "}" ...)`) — confirmed on real Juice Shop codefix sample files, which
    # are intentionally-incomplete snippets. That trailing text breaks
    # ET.fromstring even though the tree itself parsed fine; truncate at the
    # closing tag rather than discarding the whole file's AST over it.
    end_tag = cleaned.rfind("</sources>")
    if end_tag != -1:
        cleaned = cleaned[: end_tag + len("</sources>")]
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError as e:
        return None, f"xml_parse_error: {e}"
    source_elem = root.find("source")
    program = None
    if source_elem is not None:
        for c in list(source_elem):
            program = c
            break
    return program, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo_path")
    ap.add_argument("--manifest", default="./language-manifest.json")
    ap.add_argument("--out", default="./crawl-output.json")
    ap.add_argument("--ts-bin", default=None)
    args = ap.parse_args()

    repo_path = Path(args.repo_path).resolve()
    out_path = Path(args.out)

    ts_bin = find_ts_bin(args.ts_bin)
    if not ts_bin:
        stub = {"ts_available": False, "reason": "tree_sitter_not_installed"}
        out_path.write_text(json.dumps(stub, indent=2), encoding="utf-8")
        print("crawl-tree-sitter: tree-sitter CLI not installed — AST crawl skipped.")
        return 0

    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig")) if manifest_path.exists() else {}
    languages = manifest.get("languages", []) or ([manifest["primary_language"]] if manifest.get("primary_language") else [])
    languages = [lang.lower() for lang in languages]

    known = [lang for lang in languages if lang in LANG_GRAMMAR]
    unknown = [lang for lang in languages if lang not in LANG_GRAMMAR]

    files = collect_files(repo_path, known)

    version_proc = subprocess.run([ts_bin, "--version"], capture_output=True, text=True)
    ts_version = version_proc.stdout.strip()

    all_facts = {}
    skipped_files = []
    parse_errors = 0

    for f in files:
        rel = str(f.relative_to(repo_path)).replace("\\", "/")
        try:
            line_count = sum(1 for _ in f.open("r", encoding="utf-8", errors="replace"))
        except OSError:
            skipped_files.append({"path": rel, "reason": "read_error"})
            continue
        if line_count > MAX_LINES:
            skipped_files.append({"path": rel, "reason": "exceeds line limit"})
            continue

        lang = EXT_TO_LANG[f.suffix]
        program, err = parse_file_xml(ts_bin, f)
        if err:
            skipped_files.append({"path": rel, "reason": f"parse_error: {err}"})
            parse_errors += 1
            continue
        if program is None:
            skipped_files.append({"path": rel, "reason": "empty_parse"})
            continue

        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        facts = EXTRACTORS[lang](program, lines)
        facts.path = rel
        facts.language = lang
        facts.lines = line_count
        all_facts[rel] = facts

    priorities = {}
    calls_index = {}
    for path, facts in all_facts.items():
        base = Path(path).stem
        for fn in facts.functions:
            if fn.get("name"):
                calls_index.setdefault(fn["name"], []).append(path)
        calls_index.setdefault(base, []).append(path)

    for path, facts in all_facts.items():
        priorities[path] = compute_priority(facts, path)
    second_pass_priority(all_facts, priorities, calls_index)

    roles = {path: classify_role(facts, path) for path, facts in all_facts.items()}

    files_out = []
    entry_points = []
    priority_dist = {"5": 0, "4": 0, "3": 0, "2": 0, "1": 0}
    pattern_summary = {}

    for path, facts in all_facts.items():
        prio = priorities[path]
        role = roles[path]
        priority_dist[str(prio)] += 1
        for p in facts.dangerous_patterns:
            pattern_summary[p["type"]] = pattern_summary.get(p["type"], 0) + 1

        file_entry = {
            "path": path, "role": role, "lines": facts.lines,
            "language": facts.language, "security_priority": prio,
            "ts_enriched": True,
            "ast": {
                "functions": facts.functions,
                "imports": facts.imports,
                "routes": facts.routes,
                "user_input_sources": facts.user_input_sources,
                "dangerous_patterns": facts.dangerous_patterns,
                "calls_to": facts.calls_to,
            },
        }
        files_out.append(file_entry)
        if role == "entry_point":
            entry_points.append({
                "path": path, "role": role, "security_priority": prio,
                "routes": facts.routes, "user_input_sources": facts.user_input_sources,
            })

    warnings = [f"no grammar mapping for language: {lang}" for lang in unknown]

    output = {
        "repo_path": str(repo_path),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "ts_available": True,
        "ts_version": ts_version,
        "language": known[0] if known else None,
        "languages_detected": known,
        "framework": manifest.get("framework"),
        "total_files": len(files_out),
        "entry_points": entry_points,
        "files": files_out,
        "security_priority_distribution": priority_dist,
        "dangerous_pattern_summary": pattern_summary,
        "skipped_files": skipped_files,
        "warnings": warnings,
    }
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    role_counts = {}
    for r in roles.values():
        role_counts[r] = role_counts.get(r, 0) + 1

    print("crawl-tree-sitter complete.")
    print(f"  Repo       : {repo_path}")
    print(f"  Languages  : {', '.join(known) or 'none'}")
    print(f"  Files parsed: {len(files_out)} files ({parse_errors} parse errors)")
    print(f"  Skipped    : {len(skipped_files)}")
    print("  Role distribution:")
    for role in ("entry_point", "middleware", "service", "dao", "component", "util"):
        print(f"    {role:12}: {role_counts.get(role, 0)}")
    print("  Security priority:")
    for p in ("5", "4", "3", "2", "1"):
        print(f"    Priority {p}: {priority_dist[p]} files")
    print(f"  Output: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
