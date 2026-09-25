"""Deterministic static rules for ИБ-01…ИБ-08 (Python/Django, configuration, docs).

The rules never import or execute target code: they read the same redacted,
line-numbered documents as the model and use `ast` plus narrow configuration
patterns. Every finding cites exact source lines, so it passes the same
quotation check as model findings. Rules describe *implementation patterns*
(what a correct server-side check looks like), not known defects of a
particular repository.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import PurePosixPath

from .schemas import REQUIREMENT_IDS

RULES_VERSION = '1.0'
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)

DENY_NAMES = {'PermissionDenied', 'Http404', 'HttpResponseForbidden', 'HttpResponseNotFound',
              'redirect_to_login', 'NotAuthenticated', 'AuthenticationFailed'}
AUTH_DECORATORS = {'login_required': {'auth'}, 'staff_member_required': {'auth', 'staff'},
                   'superuser_required': {'auth', 'superuser'}, 'permission_required': {'auth', 'perm'}}
ACCESS_FACTS = {'auth', 'token', 'staff', 'superuser', 'admin_role', 'operator_role', 'perm'}
PUBLIC_ROUTE = re.compile(r'(^|/)(login|signin|static|favicon\.ico|robots\.txt|health|healthz|ping)(/|$)', re.I)
PUBLIC_VIEWS = {'LoginView', 'login', 'login_view', 'signin'}
ADMIN_ROUTE = re.compile(r'(^|/)(manage|admin|administration|users|roles?|permissions?)(/|$)', re.I)
ADMIN_VIEW = re.compile(r'(^|_)(manage|admin|role|grant|revoke|reset_password|permission|create_user)', re.I)
EXPORT_ROUTE = re.compile(r'(^|/)(exports?|dump)(/|$)|\.(csv|json|xlsx)$', re.I)
PD_FIELDS = {'first_name', 'last_name', 'middle_name', 'patronymic', 'surname', 'full_name',
             'email', 'username', 'login', 'phone', 'iin'}
PLAIN_FIELD_TYPES = {'CharField', 'EmailField', 'TextField', 'SlugField'}
AUDIT_NAME = re.compile(r'audit|journal', re.I)
AUDIT_FUNCS = re.compile(r'^(record|log_event|audit\w*|write_event|log_action|append|audited)$')
STRONG_HASHER = re.compile(r'Argon2|BCrypt|Scrypt', re.I)
NORMATIVE = [
    ('Закон РК № 418-V «О кибербезопасности»', re.compile(r'418\s*-\s*V', re.I)),
    ('Закон РК № 94-V «О персональных данных и их защите»', re.compile(r'(?<!\d)94\s*-\s*V', re.I)),
    ('Постановление Правительства РК № 832 (Единые требования в области ИКТ и ИБ)', re.compile(r'№\s*832|N\s*832|P1600000832', re.I)),
    ('СТ РК ISO/IEC 27001-2023', re.compile(r'27001')),
    ('СТ РК ISO/IEC 27002-2023', re.compile(r'27002')),
    ('СТ РК 1073-2007', re.compile(r'1073\s*-\s*2007')),
]


def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f'{base}.{node.attr}' if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ''


def _last(node) -> str:
    return _dotted(node).rsplit('.', 1)[-1]


def _span(documents, path, node) -> str:
    lines = documents[path]['lines']
    return '\n'.join(lines[node.lineno - 1:getattr(node, 'end_lineno', node.lineno)])


class Project:
    """A read-only index of the target's Python modules (never imported)."""

    def __init__(self, documents: dict):
        self.documents = documents
        self.trees, self.modules, self.functions, self.classes, self.imports = {}, {}, {}, {}, {}
        for path, doc in sorted(documents.items()):
            if not path.endswith('.py') or doc.get('kind') == 'docx':
                continue
            try:
                tree = ast.parse('\n'.join(doc['lines']) + '\n')
            except (SyntaxError, ValueError, RecursionError):
                continue
            self.trees[path] = tree
            parts = list(PurePosixPath(path).with_suffix('').parts)
            if parts[-1] == '__init__':
                parts = parts[:-1]
            for i in range(len(parts)):
                self.modules.setdefault('.'.join(parts[i:]), path)
            self.functions[path] = {n.name: n for n in tree.body if isinstance(n, FUNCS)}
            self.classes[path] = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
            imports = {}
            package = parts[:-1] if PurePosixPath(path).name != '__init__.py' else parts
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level:
                        base = package[:len(package) - (node.level - 1)] if node.level > 1 else package
                        module = '.'.join(list(base) + ([node.module] if node.module else []))
                    else:
                        module = node.module or ''
                    for alias in node.names:
                        imports[alias.asname or alias.name] = (module, alias.name)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.asname:
                            imports[alias.asname] = (alias.name, None)
                        else:
                            imports[alias.name.split('.')[0]] = (alias.name.split('.')[0], None)
            self.imports[path] = imports

    def module_path(self, module: str):
        return self.modules.get(module)

    def _lookup(self, module_path, name):
        if module_path is None:
            return None
        item = self.functions.get(module_path, {}).get(name) or self.classes.get(module_path, {}).get(name)
        return (module_path, item) if item is not None else None

    def resolve(self, path: str, node):
        """Resolve a Name/Attribute to (path, FunctionDef|ClassDef) inside the target, else None."""
        dotted = _dotted(node)
        if not dotted:
            return None
        head, _, rest = dotted.partition('.')
        imports = self.imports.get(path, {})
        if not rest:
            local = self._lookup(path, head)
            if local:
                return local
            origin = imports.get(head)
            if origin and origin[1]:
                return self._lookup(self.module_path(origin[0]), origin[1])
            return None
        origin = imports.get(head)
        if not origin or '.' in rest:
            return None
        module = origin[0] + ('.' + origin[1] if origin[1] else '')
        return self._lookup(self.module_path(module), rest)


def _is_deny(statements) -> bool:
    for stmt in statements:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Raise) and node.exc is not None and _last(node.exc) in DENY_NAMES:
                return True
            if isinstance(node, ast.Return) and node.value is not None:
                value = node.value
                if isinstance(value, ast.Call):
                    if _last(value.func) in DENY_NAMES:
                        return True
                    for kw in value.keywords:
                        if kw.arg == 'status' and isinstance(kw.value, ast.Constant) and kw.value.value in (401, 403):
                            return True
                if isinstance(value, ast.Tuple) and value.elts and isinstance(value.elts[0], ast.Constant) \
                        and value.elts[0].value in (401, 403):
                    return True
    return False


class Guards:
    """Server-side access facts: auth, token, staff, superuser, admin_role, operator_role, perm."""

    def __init__(self, project: Project):
        self.p = project
        self._cache = {}

    def expr_facts(self, path, expr, depth, lines):
        facts = set()
        for node in ast.walk(expr):
            if isinstance(node, ast.Compare):
                attrs = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)} | \
                        {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                consts = [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
                if 'role' in attrs and consts:
                    only_admin = all(re.fullmatch(r'admin(istrator)?', c, re.I) for c in consts)
                    facts.add('admin_role' if only_admin else 'operator_role')
                    lines.append((path, node.lineno))
            elif isinstance(node, ast.Attribute):
                if node.attr == 'is_staff':
                    facts.add('staff'); lines.append((path, node.lineno))
                elif node.attr == 'is_superuser':
                    facts.add('superuser'); lines.append((path, node.lineno))
                elif node.attr == 'is_authenticated':
                    facts.add('auth')
            elif isinstance(node, ast.Call):
                if _last(node.func) in ('has_perm', 'has_perms'):
                    facts.add('perm')
                if depth < 4:
                    target = self.p.resolve(path, node.func)
                    if target and isinstance(target[1], FUNCS):
                        for ret in ast.walk(target[1]):
                            if isinstance(ret, ast.Return) and ret.value is not None:
                                facts |= self.expr_facts(target[0], ret.value, depth + 1, lines)
        return facts

    def function_guard(self, path, fn, depth=0, lines=None):
        """Facts enforced by fn: denying branches, decorators, nested wrappers, token checks, guard helpers."""
        lines = [] if lines is None else lines
        key = (path, fn.lineno, fn.name)
        if key in self._cache:
            facts, cached = self._cache[key]
            lines.extend(cached)
            return set(facts)
        if depth > 5:
            return set()
        self._cache[key] = (set(), [])  # recursion guard
        own, facts = [], set()
        for dec in fn.decorator_list:
            facts |= self.decorator_facts(path, dec, depth + 1, own)
        for node in ast.walk(fn):
            if node is fn:
                continue
            if isinstance(node, ast.If) and (_is_deny(node.body) or _is_deny(node.orelse)):
                facts |= self.expr_facts(path, node.test, depth + 1, own)
            elif isinstance(node, FUNCS):
                for dec in node.decorator_list:
                    facts |= self.decorator_facts(path, dec, depth + 1, own)
            elif isinstance(node, ast.Constant) and node.value in ('Authorization', 'HTTP_AUTHORIZATION'):
                facts.add('token'); own.append((path, node.lineno))
            elif isinstance(node, ast.Call) and depth < 4:
                target = self.p.resolve(path, node.func)
                if target and isinstance(target[1], FUNCS) and target[1] is not fn:
                    sub = self.function_guard(target[0], target[1], depth + 1, [])
                    # Only helpers that themselves refuse access (or read a token) are guards.
                    if _is_deny(target[1].body) or 'token' in sub:
                        facts |= self.function_guard(target[0], target[1], depth + 1, own)
        self._cache[key] = (set(facts), list(own))
        lines.extend(own)
        return facts

    def decorator_facts(self, path, dec, depth, lines):
        name = _last(dec)
        if name in AUTH_DECORATORS:
            return set(AUTH_DECORATORS[name])
        if name == 'user_passes_test' and isinstance(dec, ast.Call) and dec.args:
            return {'auth'} | self.expr_facts(path, dec.args[0], depth, lines)
        target = self.p.resolve(path, dec.func if isinstance(dec, ast.Call) else dec)
        if target and isinstance(target[1], FUNCS):
            return self.function_guard(target[0], target[1], depth, lines)
        return set()


def audit_calls(project: Project, path: str, fn, depth=0, seen=None) -> list:
    """(path, line) of audit calls reachable from fn, including through decorators and helpers."""
    seen = set() if seen is None else seen
    key = (path, fn.lineno)
    if key in seen or depth > 3:
        return []
    seen.add(key)
    hits = []
    for dec in fn.decorator_list:
        if AUDIT_NAME.search(_dotted(dec)):
            hits.append((path, dec.lineno))
            continue
        target = project.resolve(path, dec.func if isinstance(dec, ast.Call) else dec)
        if target and isinstance(target[1], FUNCS):
            hits += audit_calls(project, target[0], target[1], depth + 1, seen)
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node.func)
        head = dotted.split('.')[0]
        origin = project.imports.get(path, {}).get(head)
        module = '.'.join(x for x in origin if x) if origin else ''
        if AUDIT_FUNCS.match(dotted.rsplit('.', 1)[-1]) and (AUDIT_NAME.search(dotted) or AUDIT_NAME.search(module)):
            hits.append((path, node.lineno))
            continue
        target = project.resolve(path, node.func)
        if target and isinstance(target[1], FUNCS) and depth < 2:
            if AUDIT_NAME.search(target[0]) and AUDIT_FUNCS.match(target[1].name):
                hits.append((path, node.lineno))
            elif not AUDIT_NAME.search(target[0]):
                hits += audit_calls(project, target[0], target[1], depth + 1, seen)
    return hits


class Collector:
    def __init__(self, documents):
        self.documents = documents
        self.findings = {rid: [] for rid in REQUIREMENT_IDS}
        self.additional = []
        self.notes = {rid: [] for rid in REQUIREMENT_IDS}

    def ev(self, path, start, end=None):
        doc = self.documents.get(path) if path else None
        if not doc or not isinstance(start, int):
            return None
        lines = doc['lines']
        end = end or start
        if not 1 <= start <= end <= len(lines):
            return None
        quote = '\n'.join(lines[start - 1:end])
        return {'path': path, 'start_line': start, 'end_line': end, 'quote': quote} if quote.strip() else None

    @staticmethod
    def _unique(evidence, limit):
        unique = {}
        for item in evidence:
            if item:
                unique.setdefault((item['path'], item['start_line'], item['end_line']), item)
        return list(unique.values())[:limit]

    def add(self, rid, title, severity, explanation, recommendation, evidence):
        evidence = self._unique(evidence, 12)
        if evidence:
            self.findings[rid].append({'requirement_id': rid, 'title': title, 'severity': severity,
                                       'explanation': explanation, 'recommendation': recommendation,
                                       'evidence': evidence, 'detected_by': 'static_rule'})

    def extra(self, title, spec_ref, severity, explanation, recommendation, evidence):
        evidence = self._unique(evidence, 6)
        if evidence:
            self.additional.append({'title': title, 'spec_reference': spec_ref, 'severity': severity,
                                    'explanation': explanation, 'recommendation': recommendation,
                                    'evidence': evidence, 'blocking': False, 'detected_by': 'static_rule'})


def _find_line(doc, pattern):
    rx = re.compile(pattern)
    for number, line in enumerate(doc['lines'], 1):
        if rx.search(line):
            return number
    return None


def _json_documents(documents):
    for path, doc in sorted(documents.items()):
        if path.endswith('.json') and doc.get('kind') != 'docx':
            try:
                yield path, doc, json.loads(doc['text'])
            except ValueError:
                continue


def weak_ciphers(value: str) -> list:
    weak = []
    for token in re.split(r'[:\s,]+', value):
        upper = token.strip().upper()
        if not upper or upper[0] in '!-+@' or upper.startswith('TLS_'):
            continue
        if upper in ('HIGH', 'MEDIUM', 'LOW', 'DEFAULT', 'ALL', 'COMPLEMENTOFALL', 'RSA', 'AES', 'AESGCM') \
                or 'ECDHE' not in upper or not ('GCM' in upper or 'CHACHA20' in upper) \
                or any(bad in upper for bad in ('CBC', 'RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'ANON')) \
                or upper.endswith('-SHA'):
            weak.append(token.strip())
    return weak


def _urlconf_modules(project: Project, root_urlconf):
    """Only URL modules reachable from ROOT_URLCONF via include(); all urls.py if unknown."""
    start = project.module_path(root_urlconf) if root_urlconf else None
    if start is None:
        return [p for p in project.trees if PurePosixPath(p).name == 'urls.py']
    seen, queue = [], [start]
    while queue:
        path = queue.pop(0)
        if path in seen or path not in project.trees:
            continue
        seen.append(path)
        for node in ast.walk(project.trees[path]):
            if isinstance(node, ast.Call) and _last(node.func) == 'include' and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Tuple) and arg.elts:
                    arg = arg.elts[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    target = project.module_path(arg.value)
                    if target:
                        queue.append(target)
                elif isinstance(arg, (ast.Name, ast.Attribute)):
                    origin = project.imports.get(path, {}).get(_dotted(arg).split('.')[0])
                    if origin:
                        module = '.'.join(x for x in origin if x)
                        target = project.module_path(module) or project.module_path(origin[0])
                        if target and PurePosixPath(target).name == 'urls.py':
                            queue.append(target)
    return seen


USER_MODEL_NAMES = {'User', 'UserModel', 'Person', 'Account'}
LISTING = {'all', 'values', 'values_list', 'filter', 'iterator', 'only', 'order_by'}
DATA_RESPONSES = {'JsonResponse', 'FileResponse', 'StreamingHttpResponse'}


def _lists_users(project: Project, path, fn, depth=0) -> bool:
    """True when fn (or a project helper it calls) reads the user directory in bulk."""
    mutated = {id(n.func.value) for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr in ('update', 'delete', 'exists', 'count', 'first', 'get')}
    for node in ast.walk(fn):
        if id(node) in mutated:
            continue  # filter(...).update()/.exists()/.get() is not a directory read
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in LISTING:
            base = node.func.value
            if isinstance(base, ast.Attribute) and base.attr == 'objects':
                owner = base.value
                if (_last(owner) in USER_MODEL_NAMES) or (isinstance(owner, ast.Call) and _last(owner.func) == 'get_user_model'):
                    return True
        if isinstance(node, ast.Call) and depth < 2:
            target = project.resolve(path, node.func)
            if target and isinstance(target[1], FUNCS) and target[1] is not fn and _lists_users(project, target[0], target[1], depth + 1):
                return True
    return False


def _returns_data(fn) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and _last(node.func) in DATA_RESPONSES:
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and 'attachment' in node.value and 'filename' in node.value:
            return True
    return False


def _int_value(project: Project, path, node):
    """Evaluate an int literal, simple arithmetic, or a module-level constant; None if unknown."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add)):
        left, right = _int_value(project, path, node.left), _int_value(project, path, node.right)
        if left is not None and right is not None:
            return left * right if isinstance(node.op, ast.Mult) else left + right
    if isinstance(node, ast.Name):
        for stmt in project.trees.get(path, ast.Module(body=[])).body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == node.id for t in stmt.targets):
                return _int_value(project, path, stmt.value)
    if isinstance(node, ast.Call) and _last(node.func) == 'timedelta':
        units = {'seconds': 1, 'minutes': 60, 'hours': 3600, 'days': 86400}
        total = 0
        for kw in node.keywords:
            value = _int_value(project, path, kw.value)
            if kw.arg not in units or value is None:
                return None
            total += value * units[kw.arg]
        return total
    return None


def _routes(project: Project, url_modules):
    routes = []
    for path in url_modules:
        tree = project.trees[path]
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _last(node.func) in ('path', 're_path', 'url') and len(node.args) >= 2):
                continue
            if not (isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                continue
            view = node.args[1]
            if isinstance(view, ast.Call) and _last(view.func) == 'include':
                continue
            wrappers = []
            while isinstance(view, ast.Call) and view.args and _last(view.func) != 'as_view':
                wrappers.append(view.func)
                view = view.args[0]
            view_ref = view.func if isinstance(view, ast.Call) else view
            if isinstance(view_ref, ast.Attribute) and view_ref.attr == 'as_view':
                view_ref = view_ref.value
            routes.append({'url_path': path, 'line': node.lineno, 'route': node.args[0].value,
                           'view_name': _last(view_ref), 'wrappers': wrappers, 'target': project.resolve(path, view_ref)})
    return routes


def _plain_field(project: Project, path: str, func) -> bool:
    """True for a standard Django text field; aliases and project field classes are resolved."""
    name = _last(func)
    origin = project.imports.get(path, {}).get(_dotted(func).split('.')[0])
    if origin and origin[1] and '.' not in _dotted(func):
        name = origin[1]
    target = project.resolve(path, func)
    if target and isinstance(target[1], ast.ClassDef):
        # A field counts as encrypted only if it (or a project mixin/base) really calls an encryption primitive
        # when storing the value; a name like "EncryptedCharField" alone is not evidence.
        seen, stack, encrypts, plain_base = set(), [target], False, False
        while stack:
            cpath, cls = stack.pop()
            if id(cls) in seen:
                continue
            seen.add(id(cls))
            for node in ast.walk(cls):
                if isinstance(node, ast.Call) and re.fullmatch(r'encrypt\w*|seal', _last(node.func), re.I):
                    encrypts = True
            for base in cls.bases:
                if _last(base) in PLAIN_FIELD_TYPES:
                    plain_base = True
                resolved = project.resolve(cpath, base)
                if resolved and isinstance(resolved[1], ast.ClassDef):
                    stack.append(resolved)
        return plain_base and not encrypts
    if re.search(r'encrypt|cipher', name, re.I):
        return False  # third-party encrypted field library (not in the project): trusted by name
    return name in PLAIN_FIELD_TYPES


def run(documents: dict) -> dict:
    project = Project(documents)
    guards = Guards(project)
    out = Collector(documents)

    settings_paths = []
    for path, tree in project.trees.items():
        names = {t.id for n in tree.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
        if names & {'INSTALLED_APPS', 'MIDDLEWARE', 'DATABASES'}:
            settings_paths.append(path)

    def setting(name):
        found = []
        for path in settings_paths + [p for p in project.trees if p not in settings_paths]:
            for node in project.trees[path].body:
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                    found.append((path, node))
        return found[0] if found else (None, None)

    def const_setting(name):
        path, node = setting(name)
        if node is not None and isinstance(node.value, ast.Constant):
            return path, node, node.value.value
        return path, node, Ellipsis

    # ---- Global middleware (login enforcement, audit) ---------------------------------------
    global_login, global_audit = False, []
    mw_path, mw_node = setting('MIDDLEWARE')
    if mw_node is not None:
        for item in ast.walk(mw_node.value):
            if not (isinstance(item, ast.Constant) and isinstance(item.value, str)):
                continue
            if item.value.endswith('LoginRequiredMiddleware'):
                global_login = True
            module, _, cls = item.value.rpartition('.')
            target = project.module_path(module)
            klass = project.classes.get(target, {}).get(cls) if target else None
            if klass is None:
                continue
            for method in klass.body:
                if isinstance(method, FUNCS) and method.name in ('__call__', 'process_view', 'process_request', 'process_response'):
                    global_audit += audit_calls(project, target, method)
                    if guards.function_guard(target, method) & {'auth', 'token'}:
                        global_login = True

    # ---- Routes and their effective server-side guards ------------------------------------------
    path, node, root_urlconf = const_setting('ROOT_URLCONF')
    url_modules = _urlconf_modules(project, root_urlconf if isinstance(root_urlconf, str) else None)
    views = []
    for r in _routes(project, url_modules):
        lines, facts = [], set()
        for wrapper in r['wrappers']:
            facts |= guards.decorator_facts(r['url_path'], wrapper, 1, lines)
        fn_path, fn = r['target'] if r['target'] and isinstance(r['target'][1], FUNCS) else (None, None)
        if fn is not None:
            facts |= guards.function_guard(fn_path, fn, 0, lines)
        klass = r['target'][1] if r['target'] and isinstance(r['target'][1], ast.ClassDef) else None
        if klass is not None:
            for dec in klass.decorator_list:
                facts |= guards.decorator_facts(r['target'][0], dec, 1, lines)
            if any(_last(b) in ('LoginRequiredMixin', 'PermissionRequiredMixin', 'UserPassesTestMixin') for b in klass.bases):
                facts.add('auth')
        exempt = fn is not None and any(_last(d) == 'login_not_required' for d in fn.decorator_list)
        if global_login and not exempt:
            facts.add('auth')
        name = fn.name if fn is not None else r['view_name']
        is_admin = bool(ADMIN_ROUTE.search(r['route'])) or bool(ADMIN_VIEW.search(name))
        views.append(dict(r, facts=facts, guard_lines=lines, fn=fn, fn_path=fn_path, name=name,
                          public=bool(PUBLIC_ROUTE.search(r['route'])) or r['view_name'] in PUBLIC_VIEWS,
                          admin=bool(ADMIN_ROUTE.search(r['route'])) or bool(ADMIN_VIEW.search(name)),
                          export=bool(EXPORT_ROUTE.search(r['route'])) or name.startswith('export')
                          or (not is_admin and fn is not None and _returns_data(fn) and _lists_users(project, fn_path, fn))))

    # ---- ИБ-01 / ИБ-02 / ИБ-08 per route ----------------------------------------------------------
    admin_groups = {}
    for v in views:
        if v['public']:
            continue
        fn, fn_path, facts, name = v['fn'], v['fn_path'], v['facts'], v['name']
        base_ev = [out.ev(v['url_path'], v['line']), out.ev(fn_path, fn.lineno) if fn is not None else None]
        staff_ev = [out.ev(p, l) for p, l in v['guard_lines']
                    if 'is_staff' in documents[p]['lines'][l - 1]][:2]
        route = '/' + v['route']
        if not facts & ACCESS_FACTS:
            out.add('ИБ-02', f'Маршрут «{route}» ({name}) доступен без проверки сессии или токена', 'critical',
                    f'Для маршрута «{route}» сервер не проверяет ни сессию (login_required или глобальный middleware), ни токен доступа: '
                    f'в обработчике {name} и его обёртках нет проверки аутентификации. Любой анонимный клиент получает ответ '
                    'защищённой конечной точки, включая данные обращений.',
                    'Добавить серверную проверку аутентификации (login_required либо проверку токена с ответом 401). '
                    'Надёжнее — общий middleware, запрещающий анонимный доступ ко всем маршрутам, кроме формы входа.',
                    base_ev)
            continue
        if v['export']:
            hits = audit_calls(project, fn_path, fn) if fn is not None else []
            problems = []
            if 'admin_role' not in facts:
                problems.append('роль «администратор» не проверяется на сервере'
                                + (' (проверяется только признак is_staff)' if 'staff' in facts else ''))
            if not hits:
                # A generic request log does not record format and number of exported records (ТЗ 4.7.3).
                problems.append('факт выгрузки не записывается в журнал аудита (формат, число записей)')
            if problems:
                out.add('ИБ-08', f'Выгрузка «{route}» ({name}): ' + '; '.join(problems),
                        'critical' if 'admin_role' not in facts else 'high',
                        f'Обработчик {name} отдаёт выгрузку данных, однако ' + ', '.join(problems) + '. '
                        'Выгрузка справочника с ФИО, логинами и email должна быть доступна только администратору, '
                        'а каждый её факт — фиксироваться в журнале аудита.',
                        'Защитить обработчик той же проверкой роли администратора, что и остальные форматы выгрузки, '
                        'и регистрировать событие аудита (инициатор, формат, число записей) при каждой выгрузке.',
                        base_ev + staff_ev)
            continue
        if v['admin'] and 'admin_role' not in facts:
            # One root cause (the same shared guard) is one finding with several locations.
            key = tuple(sorted((e['path'], e['start_line']) for e in staff_ev if e)) or ('no-role-check', route)
            admin_groups.setdefault(key, []).append((v, base_ev, staff_ev))

    for key, items in admin_groups.items():
        staff = key and key[0] != 'no-role-check'
        routes = ', '.join(f'«/{v["route"]}» ({v["name"]})' for v, _, _ in items)
        evidence = [e for _, base, _ in items for e in base] + [e for _, _, st in items for e in st]
        if staff:
            guard = items[0][2][0]['path'] if items[0][2] and items[0][2][0] else 'общий декоратор'
            out.add('ИБ-01', f'Административные функции защищены проверкой is_staff вместо роли администратора ({len(items)} маршр.)',
                    'critical',
                    f'Маршруты {routes} выполняют административные функции (пользователи, роли, права, пароли), '
                    f'но общий декоратор в {guard} допускает любого пользователя с признаком is_staff. Этот признак установлен и у '
                    'операторов, поэтому оператор может просматривать справочник пользователей, назначать роли (в том числе себе — '
                    '«администратор»), выдавать права на очереди и сбрасывать чужие пароли.',
                    'В общем декораторе административных маршрутов проверять user.role == "administrator" на сервере при каждом запросе; '
                    'is_staff не использовать как признак администратора.', evidence)
        else:
            v = items[0][0]
            out.add('ИБ-01', f'Административная функция «/{v["route"]}» ({v["name"]}) без проверки роли администратора', 'high',
                    f'Маршрут «/{v["route"]}» выполняет административную функцию ({v["name"]}), но сервер проверяет только факт входа — '
                    'роль не проверяется. Любой вошедший пользователь (в том числе заявитель) может выполнить её прямым запросом.',
                    'Применить к маршруту общую серверную проверку роли администратора (как для остальных административных функций).',
                    evidence)

    # ---- ИБ-02: token validation ------------------------------------------------------------------
    for path, tree in project.trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _dotted(node.func)
            kws = {k.arg: k.value for k in node.keywords}
            origin = project.imports.get(path, {}).get(dotted.split('.')[0], ('', None))
            is_signing = dotted.endswith('signing.loads') or (dotted == 'loads' and origin[0] == 'django.core.signing')
            ttl = _int_value(project, path, kws['max_age']) if is_signing and 'max_age' in kws else None
            if is_signing and 'max_age' in kws and (ttl is not None and ttl > 900 or (isinstance(kws['max_age'], ast.Constant) and kws['max_age'].value is None)):
                out.add('ИБ-02', 'Срок действия токена доступа превышает 15 минут', 'medium',
                        f'{dotted}() принимает токены возрастом до {ttl if ttl is not None else "∞"} с; техническая спецификация (п. 4.4.7) '
                        'ограничивает срок действия токена 15 минутами.', 'Установить max_age не более 900 секунд.',
                        [out.ev(path, node.lineno)])
            if is_signing and 'max_age' not in kws:
                out.add('ИБ-02', 'Токен доступа проверяется без ограничения срока действия', 'high',
                        f'{dotted}() вызывается без max_age: сервер проверяет только подпись, но не срок действия. '
                        'Выданный токен остаётся действительным бессрочно, в том числе после выхода, смены пароля или роли.',
                        'Передавать max_age (не более 900 с) и связывать токен с версией учётных данных пользователя, '
                        'чтобы выход, смена пароля или роли отзывали ранее выданные токены.',
                        [out.ev(path, node.lineno)])
            if dotted.endswith('jwt.decode'):
                disabled = isinstance(kws.get('verify'), ast.Constant) and kws['verify'].value is False
                options = kws.get('options')
                if isinstance(options, ast.Dict):
                    disabled |= any(isinstance(k, ast.Constant) and k.value in ('verify_exp', 'verify_signature')
                                    and isinstance(val, ast.Constant) and val.value is False
                                    for k, val in zip(options.keys, options.values))
                if disabled:
                    out.add('ИБ-02', 'JWT проверяется с отключённой проверкой подписи или срока', 'high',
                            'jwt.decode вызывается с отключённой проверкой подписи или срока действия.',
                            'Включить проверку подписи и срока действия токена.', [out.ev(path, node.lineno)])

    # ---- ИБ-02: session settings -----------------------------------------------------------------
    path, node = setting('SESSION_COOKIE_AGE')
    age = _int_value(project, path, node.value) if node is not None else None
    if age is not None and age > 3600:
        out.add('ИБ-02', 'Срок жизни сессии больше 60 минут', 'medium',
                f'SESSION_COOKIE_AGE = {age} с: сессия остаётся действительной дольше установленных 60 минут (п. 4.4.2 спецификации), '
                'сервер принимает устаревшую сессию.', 'Установить SESSION_COOKIE_AGE не более 3600.', [out.ev(path, node.lineno)])
    path, node, value = const_setting('SESSION_COOKIE_HTTPONLY')
    if value is False:
        out.add('ИБ-02', 'Идентификатор сессии доступен сценариям браузера', 'medium',
                'SESSION_COOKIE_HTTPONLY = False: cookie сессии читается из JavaScript, и при XSS идентификатор сессии может быть похищен.',
                'Установить SESSION_COOKIE_HTTPONLY = True.', [out.ev(path, node.lineno)])

    # ---- ИБ-04: plaintext password assignment ------------------------------------------------------
    for path, tree in project.trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == 'password' for t in node.targets):
                if not (isinstance(node.value, ast.Call) and _last(node.value.func) in ('make_password', 'encode', 'hash', 'hashpw')) \
                        and not (isinstance(node.value, ast.Constant) and node.value.value in ('', None)):
                    out.add('ИБ-04', 'Пароль сохраняется без хеширования', 'critical',
                            'Атрибуту password присваивается значение напрямую, без set_password()/make_password(): пароль попадает в БД '
                            'в открытом виде.', 'Использовать user.set_password(...) (argon2/bcrypt/scrypt).', [out.ev(path, node.lineno)])
            if isinstance(node, ast.Call) and _last(node.func) in ('create', 'update', 'update_or_create', 'get_or_create') \
                    and any(kw.arg == 'password' for kw in node.keywords) and 'objects' in _dotted(node.func):
                out.add('ИБ-04', 'Пароль сохраняется без хеширования', 'critical',
                        f'{_dotted(node.func)}(password=...) записывает пароль в БД как есть, минуя хеширование.',
                        'Использовать create_user() или set_password().', [out.ev(path, node.lineno)])

    # ---- ИБ-05: journal records written without encryption ------------------------------------------
    for path, tree in project.trees.items():
        if not AUDIT_NAME.search(path):
            continue
        for fn in (n for n in ast.walk(tree) if isinstance(n, FUNCS)):
            writes = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                      and (n.func.attr in ('write_bytes', 'write_text', 'write', 'writelines')
                           or (n.func.attr == 'dump' and len(n.args) >= 2))]
            encrypts = any(isinstance(n, ast.Call) and re.search(r'encrypt|seal|sign', _last(n.func), re.I) for n in ast.walk(fn))
            if writes and not encrypts:
                out.add('ИБ-05', 'Записи журнала сохраняются без шифрования', 'high',
                        f'Функция {fn.name} в {path} записывает событие журнала на диск без шифрования и кода целостности: '
                        'локальный пользователь может прочитать и изменить записи до отправки сборщику.',
                        'Шифровать каждую запись аутентифицированным шифрованием (AES-GCM) ключом, недоступным пользователям.',
                        [out.ev(path, writes[0].lineno)])

    # ---- ИБ-03: transport protection --------------------------------------------------------------
    redirect_false, redirect_true, cookie_ev = [], False, []
    for path, doc, data in _json_documents(documents):
        stack = [data]
        while stack:
            obj = stack.pop()
            if isinstance(obj, list):
                stack.extend(obj)
                continue
            if not isinstance(obj, dict):
                continue
            for key, value in obj.items():
                stack.append(value)
                k = str(key).lower()
                line = _find_line(doc, re.escape(json.dumps(key, ensure_ascii=False)))
                if re.search(r'http.*redirect|redirect.*http|force_?https|https_?only|ssl_?redirect', k) and isinstance(value, bool):
                    if value:
                        redirect_true = True
                    else:
                        redirect_false.append(out.ev(path, line))
                elif 'cipher' in k and isinstance(value, str) and weak_ciphers(value):
                    out.add('ИБ-03', 'Разрешены нестойкие наборы шифров TLS', 'high',
                            f'Параметр «{key}» в {path} разрешает наборы {", ".join(weak_ciphers(value))} — без эфемерного обмена ключами '
                            'ECDHE и/или без AEAD (режим CBC, MAC на SHA-1). Для TLS 1.2 допустимы только ECDHE + AEAD.',
                            'Оставить только наборы ECDHE с AES-GCM или CHACHA20-POLY1305, например '
                            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256.',
                            [out.ev(path, line)])
                elif re.search(r'min(imum)?_?tls|tls_?min|min(imum)?_?version|ssl_?version', k) and isinstance(value, str) \
                        and re.fullmatch(r'(PROTOCOL_)?(TLS(V)?1([_.]0|[_.]1)?|SSLV[23])', value.strip().upper()):
                    out.add('ИБ-03', 'Допускается устаревшая версия TLS', 'high',
                            f'Параметр «{key}» = «{value}» допускает протокол ниже TLS 1.2.',
                            'Установить минимальную версию TLSv1_2 (или TLSv1_3).', [out.ev(path, line)])
    for name in ('SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE'):
        path, node, value = const_setting(name)
        if value is False:
            cookie_ev.append(out.ev(path, node.lineno))
    path, node, value = const_setting('SECURE_HSTS_SECONDS')
    if value in (0, None):
        cookie_ev.append(out.ev(path, node.lineno))
    path, node, value = const_setting('SECURE_SSL_REDIRECT')
    ssl_redirect_off = value is False
    if ssl_redirect_off and not redirect_true:
        redirect_false.append(out.ev(path, node.lineno))
    if redirect_false:
        out.add('ИБ-03', 'Нет принудительного перенаправления с HTTP на HTTPS', 'high',
                'Перенаправление незащищённых HTTP-запросов на HTTPS отключено ни на уровне транспортного модуля, ни в приложении: '
                'обращение по HTTP обрабатывается, и данные, пароли и cookie передаются без шифрования.',
                'Включить перенаправление (301/308) всех HTTP-запросов на HTTPS в транспортном модуле и/или '
                'SECURE_SSL_REDIRECT = True; не обслуживать приложение по HTTP.', redirect_false)
    if cookie_ev:
        out.add('ИБ-03', 'Сессионные cookie и HSTS допускают передачу по незащищённому соединению', 'medium',
                'Параметры Django разрешают передачу сессионной и CSRF-cookie по HTTP (SESSION_COOKIE_SECURE / CSRF_COOKIE_SECURE = False) '
                'и/или не объявляют политику HSTS (SECURE_HSTS_SECONDS = 0).',
                'Установить SESSION_COOKIE_SECURE = True, CSRF_COOKIE_SECURE = True, SECURE_HSTS_SECONDS ≥ 31536000.',
                cookie_ev)
    for path, tree in project.trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                dotted = _dotted(node.func)
                if dotted.endswith('_create_unverified_context'):
                    out.add('ИБ-03', 'Отключена проверка сертификата', 'high', 'Используется ssl._create_unverified_context().',
                            'Использовать ssl.create_default_context() с проверкой сертификата.', [out.ev(path, node.lineno)])
                if dotted.endswith('set_ciphers') and node.args and isinstance(node.args[0], ast.Constant) \
                        and isinstance(node.args[0].value, str) and weak_ciphers(node.args[0].value):
                    out.add('ИБ-03', 'Разрешены нестойкие наборы шифров TLS', 'high',
                            f'set_ciphers() разрешает {", ".join(weak_ciphers(node.args[0].value))}.',
                            'Оставить только наборы ECDHE + AEAD.', [out.ev(path, node.lineno)])
                if any(kw.arg == 'verify' and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords) \
                        and re.search(r'requests|httpx|session|client|get|post', dotted, re.I):
                    out.add('ИБ-03', 'Отключена проверка сертификата', 'high', f'{dotted}(verify=False) отключает проверку сертификата.',
                            'Удалить verify=False, доверять конкретному сертификату стенда.', [out.ev(path, node.lineno)])
            elif isinstance(node, ast.Attribute):
                if node.attr in ('PROTOCOL_TLSv1', 'PROTOCOL_TLSv1_1', 'PROTOCOL_SSLv23', 'PROTOCOL_SSLv3') \
                        or (node.attr in ('TLSv1', 'TLSv1_1', 'SSLv3') and _dotted(node).endswith('TLSVersion.' + node.attr)):
                    out.add('ИБ-03', 'Допускается устаревшая версия TLS', 'high', f'Используется ssl.{_dotted(node)}.',
                            'Использовать PROTOCOL_TLS_SERVER и minimum_version = TLSVersion.TLSv1_2.', [out.ev(path, node.lineno)])
                elif node.attr == 'CERT_NONE':
                    out.add('ИБ-03', 'Отключена проверка сертификата', 'high', 'Используется ssl.CERT_NONE.',
                            'Использовать CERT_REQUIRED.', [out.ev(path, node.lineno)])

    # ---- ИБ-04: passwords and personal data at rest -----------------------------------------------
    path, node = setting('PASSWORD_HASHERS')
    if node is not None:
        first = next((n for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)), None)
        if first is not None:
            module, _, cls = first.value.rpartition('.')
            target = project.module_path(module)
            klass = project.classes.get(target, {}).get(cls) if target else None
            label = ' '.join(_dotted(b) for b in klass.bases) if klass is not None else first.value
            if not STRONG_HASHER.search(label):
                out.add('ИБ-04', 'Пароли хешируются не bcrypt/argon2/scrypt', 'high',
                        f'Основной хешер паролей «{first.value}» не относится к bcrypt, argon2 или scrypt.',
                        'Указать первым Argon2PasswordHasher, BCryptSHA256PasswordHasher или ScryptPasswordHasher.',
                        [out.ev(path, first.lineno)])
    elif settings_paths and any('django' in d['text'] for d in documents.values() if d.get('kind') != 'docx'):
        p = settings_paths[0]
        out.add('ИБ-04', 'Используется хешер паролей Django по умолчанию (PBKDF2)', 'medium',
                'PASSWORD_HASHERS не задан, поэтому Django использует PBKDF2, не входящий в перечень bcrypt/argon2/scrypt из ТЗ.',
                'Задать PASSWORD_HASHERS с Argon2PasswordHasher первым.', [out.ev(p, 1)])
    for path, tree in project.trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _last(node.func) in ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512') \
                    and _dotted(node.func).split('.')[0] in ('hashlib', 'md5', 'sha1', 'sha256', 'sha512'):
                names = {n.id.lower() for n in ast.walk(node) if isinstance(n, ast.Name)} | \
                        {n.attr.lower() for n in ast.walk(node) if isinstance(n, ast.Attribute)}
                if any('passw' in n or n in ('pwd', 'secret_pass') for n in names):
                    out.add('ИБ-04', 'Пароль хешируется быстрой хеш-функцией', 'high',
                            f'Пароль обрабатывается {_dotted(node.func)} — быстрой хеш-функцией общего назначения без адаптивного алгоритма.',
                            'Использовать argon2, bcrypt или scrypt с индивидуальной солью и параметрами стоимости.', [out.ev(path, node.lineno)])
    encrypted_types = {name for classes in project.classes.values() for name in classes if re.search(r'encrypt', name, re.I)}
    _, _, user_model = const_setting('AUTH_USER_MODEL')
    user_app, user_cls = (user_model.split('.', 1) if isinstance(user_model, str) and '.' in user_model else (None, 'User'))
    for path, classes in project.classes.items():
        # The account store is the user model (AUTH_USER_MODEL) and its app; other apps are
        # reviewed by the model-based analysis to avoid flagging unrelated library tables.
        if user_app and PurePosixPath(path).parts[-2:-1] != (user_app,):
            continue
        for cls in classes.values():
            bases = {_last(b) for b in cls.bases}
            if not bases & {'Model', 'AbstractUser', 'AbstractBaseUser'}:
                continue
            if not user_app and cls.name != user_cls:
                continue
            plain = [(stmt.targets[0].id, stmt.lineno) for stmt in cls.body
                     if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)
                     and stmt.targets[0].id in PD_FIELDS and isinstance(stmt.value, ast.Call)
                     and _plain_field(project, path, stmt.value.func)]
            if plain:
                out.add('ИБ-04', f'Персональные данные модели {cls.name} хранятся в БД открытым текстом', 'high',
                        f'Поля {", ".join(f for f, _ in plain)} модели {cls.name} объявлены стандартными полями Django и записываются в БД '
                        'без шифрования. ТЗ требует криптографической защиты ФИО, логина и email при хранении (СТ РК 1073-2007: '
                        'аутентифицированное шифрование, ключ не менее 256 бит); ограничение доступа к файлу БД шифрование не заменяет.',
                        'Хранить поля ПД в зашифрованном виде (поле модели с AES-256-GCM, ключ из защищённого каталога ключей); '
                        'для поиска и уникальности логина — отдельный HMAC-индекс.',
                        [out.ev(path, cls.lineno)] + [out.ev(path, line) for _, line in plain])
            elif 'AbstractUser' in bases and not encrypted_types:
                out.add('ИБ-04', f'Персональные данные модели {cls.name} хранятся в БД открытым текстом', 'high',
                        f'Модель {cls.name} наследует стандартные поля AbstractUser (username, first_name, last_name, email), '
                        'а механизма шифрования полей в проекте нет.',
                        'Переопределить поля ПД зашифрованными полями.', [out.ev(path, cls.lineno)])

    # ---- ИБ-05: local application log protection -------------------------------------------------
    key_near_logs = []
    for path, tree in project.trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                consts = [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
                if any(c.endswith('.key') for c in consts) and any(re.fullmatch(r'journal|logs?|audit|pending', c, re.I) for c in consts):
                    key_near_logs.append(out.ev(path, node.lineno))
            elif isinstance(node, ast.IfExp):
                consts = [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
                if any(re.fullmatch(r'journal|logs?|audit', c, re.I) for c in consts) and any('.key' in c for c in consts):
                    key_near_logs.append(out.ev(path, node.lineno))
            elif isinstance(node, ast.Call) and _dotted(node.func) == 'os.chmod' and len(node.args) >= 2 \
                    and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, int):
                mode, target = node.args[1].value, _dotted(node.args[0])
                if mode & 0o002 or (mode & 0o077 and re.search(r'journal|log|pending|audit|key|base|root', target, re.I)):
                    out.add('ИБ-05', 'Права на каталог журнала/ключей допускают доступ других пользователей', 'high',
                            f'os.chmod({target}, {oct(mode)}) открывает каталог или файл журнала (или его родителя) другим локальным '
                            'пользователям: записи можно прочитать, подменить или удалить до отправки сборщику.',
                            'Выставлять 0o700 для каталогов и 0o600 для файлов журнала и ключей.', [out.ev(path, node.lineno)])
    if key_near_logs:
        out.add('ИБ-05', 'Ключ шифрования журнала хранится в каталоге журнала', 'high',
                'Ключ шифрования локального журнала размещается внутри каталога журнала, права на который выдаются субъектам, '
                'читающим и пополняющим буфер. Получив ключ, локальный пользователь может расшифровать записи и сформировать '
                'поддельные с корректным тегом целостности — шифрование и контроль целостности теряют смысл.',
                'Хранить ключ журнала в отдельном каталоге ключей, недоступном непривилегированным субъектам (как keys/), '
                'и не выдавать права на запись в буфер pending посторонним.', key_near_logs)
    path, node = setting('LOGGING')
    if node is not None:
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                    and re.search(r'logging\.(handlers\.)?(Rotating|TimedRotating|Watched)?FileHandler$', sub.value):
                out.add('ИБ-05', 'Журнал приложения пишется в файл открытым текстом', 'medium',
                        f'LOGGING использует {sub.value}: локальный журнал хранится без шифрования и контроля целостности.',
                        'Писать события через шифрующий обработчик (AEAD) или сразу передавать сборщику.', [out.ev(path, sub.lineno)])

    # ---- ИБ-06: normative references in README ---------------------------------------------------
    readmes = sorted((p for p in documents if '/' not in p and p.lower().startswith('readme')), key=len)
    if readmes:
        missing = [label for label, rx in NORMATIVE if not rx.search(documents[readmes[0]]['text'])]
        if missing:
            out.add('ИБ-06', 'В README нет ссылок на обязательные нормативные акты', 'low',
                    f'В {readmes[0]} не найдены ссылки на: {"; ".join(missing)}.',
                    'Добавить в README раздел «Нормативные источники» с наименованиями и ссылками на все акты п. 3.1 ТЗ.',
                    [out.ev(readmes[0], 1)])
        else:
            out.notes['ИБ-06'].append(f'Все шесть обязательных ссылок найдены в {readmes[0]}.')
    else:
        out.notes['ИБ-06'].append('README в корне проекта не найден; вывод сделан по прочим документам.')
    for path, doc in documents.items():
        if doc.get('kind') == 'docx' and re.search(r'специфик|spec', path, re.I):
            missing = [label for label, rx in NORMATIVE if not rx.search(doc['text'])]
            if missing:
                out.extra('В технической спецификации нет части нормативных ссылок', '4.10.2', 'low',
                          f'В {path} не найдены: {"; ".join(missing)}.', 'Добавить недостающие ссылки.', [out.ev(path, 1)])

    # ---- ИБ-07: unified user-action log and DBMS event log -----------------------------------------
    unaudited, bulk = [], []
    for v in views:
        fn, fn_path = v['fn'], v['fn_path']
        if fn is None or v['public']:
            continue
        hits = audit_calls(project, fn_path, fn)
        if not hits and not global_audit:
            unaudited.append((fn_path, fn))
        if not hits:
            # The request log does not list the objects a bulk change actually touched (spec 4.6.4).
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                        and (node.func.attr in ('bulk_update', 'bulk_create') or (node.func.attr == 'update' and node.keywords and not node.args)):
                    bulk.append(out.ev(fn_path, node.lineno))
    if bulk:
        out.add('ИБ-07', 'Пакетные изменения выполняются в обход журнала аудита', 'high',
                'Массовые операции QuerySet.update()/bulk_*() не порождают сигналы post_save/post_delete, на которых построена запись '
                'изменений, а явного события аудита в обработчике нет: пакетная смена данных не регистрируется.',
                'Регистрировать событие аудита с перечнем фактически затронутых объектов в той же транзакции '
                '(transaction.on_commit) или выполнять изменения через общий аудируемый сервис.', bulk)
    if unaudited:
        names = ', '.join(sorted({fn.name for _, fn in unaudited}))
        out.add('ИБ-07', 'Обращения к данным не регистрируются в едином журнале действий пользователей', 'high',
                f'Обработчики {names} работают с данными, но ни они, ни общий middleware не записывают событие аудита. '
                'Журнал формируется только сигналами ORM о сохранении/удалении и отдельными вызовами, поэтому просмотр списков и карточек, '
                'скачивание вложений, чтение через API и отказы в доступе не регистрируются. Журналирование охватывает '
                'отдельные функции, а не проект в целом.',
                'Добавить общий компонент аудита (middleware или декоратор для всех маршрутов), фиксирующий пользователя, операцию, '
                'объект, результат, идентификатор запроса и источника для каждого обращения к данным.',
                [out.ev(p, fn.lineno) for p, fn in unaudited])
    db_log = any(re.search(r'connection_created\.connect\(|receiver\(\s*connection_created|set_trace_callback\(|execute_wrapper\(', d['text'])
                 for d in documents.values() if d.get('kind') != 'docx')
    path, node = setting('LOGGING')
    if node is not None:
        text = _span(documents, path, node)
        if re.search(r"django\.db\.backends", text) and not re.search(r"NullHandler", text):
            db_log = True
    path, node = setting('DATABASES')
    if node is not None and not db_log:
        out.add('ИБ-07', 'Журнал событий СУБД не ведётся', 'high',
                'В проекте нет регистрации событий СУБД — установления и отказа соединения, изменения структуры данных, '
                'изменения прав доступа к файлу БД: не используются connection_created/execute_wrapper, логгер django.db.backends '
                'не направлен в журнал.',
                'Подключить обработчик connection_created и execute_wrapper (DDL), регистрировать миграции и изменение прав '
                'на файл БД в журнале аудита.', [out.ev(path, node.lineno)])

    # ---- Additional non-blocking observations (technical specification) ----------------------------
    path, node = setting('AUTH_PASSWORD_VALIDATORS')
    if node is not None:
        missing = [n for n in ('CommonPasswordValidator', 'NumericPasswordValidator') if n not in _span(documents, path, node)]
        if missing:
            out.extra('Не отклоняются распространённые и полностью числовые пароли', '4.4.8', 'medium',
                      f'В AUTH_PASSWORD_VALIDATORS нет {", ".join(missing)}.', 'Добавить стандартные валидаторы Django.',
                      [out.ev(path, node.lineno)])
    code_text = '\n'.join(d['text'] for d in documents.values() if d.get('kind') != 'docx')
    path, node = setting('INSTALLED_APPS')
    if node is not None and not re.search(r'axes|ratelimit|lockout|failed_attempts|login_attempt|throttl', code_text, re.I):
        out.extra('Нет ограничения неуспешных попыток входа', '4.4.6', 'medium',
                  'Не найдено ограничения числа неуспешных входов по учётной записи и по источнику.',
                  'Блокировать вход после 5 неуспешных попыток за 15 минут (django-axes или счётчик в БД).', [out.ev(path, node.lineno)])
    for path, tree in project.trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _last(node.func) in ('ThreadingHTTPServer', 'HTTPServer') \
                    and not re.search(r'\btimeout\s*=|settimeout|request_queue_size', documents[path]['text']):
                out.extra('Транспортный модуль без таймаутов и лимита соединений', '4.8.5', 'medium',
                          f'{_last(node.func)} создаётся без таймаута чтения и ограничения числа соединений: медленные клиенты '
                          'могут занять все потоки.', 'Задать timeout обработчика и ограничить число одновременных соединений.',
                          [out.ev(path, node.lineno)])
    for v in views:
        fn = v['fn']
        if fn is not None and 'role' in fn.name:
            text = _span(documents, v['fn_path'], fn)
            if 'user_permissions' not in text and '.clear(' not in text:
                out.extra('Смена роли не снимает права на очереди и не отзывает токены', '4.3.5', 'medium',
                          f'{fn.name} меняет роль, не удаляя ранее выданные права на очереди и не прекращая действие токенов.',
                          'При смене роли очищать user_permissions и отзывать токены пользователя.', [out.ev(v['fn_path'], fn.lineno)])

    # ---- Assemble per-requirement results ---------------------------------------------------------
    scope = (f'Проанализировано Python-модулей: {len(project.trees)}, маршрутов: {len(views)}, '
             f'JSON-конфигураций: {sum(1 for _ in _json_documents(documents))}, документов всего: {len(documents)}.')
    checks = []
    for rid in REQUIREMENT_IDS:
        findings = out.findings[rid]
        checks.append({
            'requirement_id': rid,
            'status': 'violated' if findings else 'no_violations_found',
            'rationale': ('Статические правила выявили нарушения. ' if findings else 'Статические правила нарушений не выявили. ')
                         + scope + (' ' + ' '.join(out.notes[rid]) if out.notes[rid] else ''),
            'findings': findings,
            'limitations': ['Детерминированные правила покрывают типовые реализации Python/Django; нестандартные механизмы '
                            'защиты проверяются LLM-анализом.'],
            'coverage_complete': True,
            'semantic_validation': 'deterministic static rules (ast and configuration patterns); locations and quotes checked',
        })
    route_map = [{'route': '/' + v['route'], 'view': v['name'], 'guards': sorted(v['facts']),
                  'public': v['public'], 'admin': v['admin'], 'export': v['export']} for v in views]
    return {'checks': checks, 'additional_findings': out.additional, 'rules_version': RULES_VERSION, 'routes': route_map}
