"""Generic AST/text map. Never imports or evaluates the analyzed project."""
from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath


def _module(path: str) -> str:
    parts = list(PurePosixPath(path).with_suffix('').parts)
    if parts and parts[0] == 'src':
        parts.pop(0)
    if parts and parts[-1] == '__init__':
        parts.pop()
    return '.'.join(parts)


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f'{_name(node.value)}.{node.attr}'.strip('.')
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ''


def _expression(node, limit: int = 500) -> str:
    try:
        text = ast.unparse(node)
    except (RecursionError, ValueError, TypeError):
        return '[index expression unavailable; consult complete source]'
    return text if len(text) <= limit else text[:limit] + f' [index excerpt; {len(text) - limit} chars omitted, consult source]'


def build_index(documents: dict) -> dict:
    result = {}
    modules = {_module(path): path for path in documents if path.endswith('.py')}

    def resolve(module: str) -> str | None:
        while module:
            if module in modules:
                return modules[module]
            module = module.rpartition('.')[0]
        return None

    for path, document in sorted(documents.items()):
        text = document['text']
        item = {'kind': document.get('kind', 'text'), 'module': _module(path) if path.endswith('.py') else None,
                'imports': [], 'symbols': [], 'decorators': [], 'calls': [], 'routes': [],
                'assignments': [], 'models': [], 'signals': [], 'references': [],
                'dependencies': [], 'dependents': [], 'limitations': []}
        # Store exact strings as navigation clues; evidence must use source chunks.
        literals = set(re.findall(r'''["']([^\n"']{1,250})["']''', text))
        references = {value for value in literals if '/' in value or re.fullmatch(r'[A-Za-z_]\w*(?:\.\w+)+', value)}
        item['references'] = sorted(references)
        if not path.endswith('.py'):
            item['dependencies'] = sorted({target for target in documents if target != path and
                                           (target in literals or any(target.endswith('/' + value) for value in references if '/' in value))})
            result[path] = item
            continue
        try:
            tree = ast.parse(text, filename=path)
        except (SyntaxError, ValueError, RecursionError) as exc:
            item['parse_error'] = f'{type(exc).__name__} at line {getattr(exc, "lineno", "unknown")}; raw source still reviewed'
            item['limitations'].append('AST unavailable; dependencies may be incomplete')
            result[path] = item
            continue
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    item['imports'].append({'module': alias.name, 'names': [], 'line': node.lineno, 'level': 0})
                    aliases[alias.asname or alias.name.split('.')[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                package = item['module'] if path.endswith('/__init__.py') else item['module'].rpartition('.')[0]
                if node.level:
                    base = package.split('.') if package else []
                    base = base[:max(0, len(base) - node.level + 1)]
                    module = '.'.join(base + ([node.module] if node.module else []))
                else:
                    module = node.module or ''
                item['imports'].append({'module': module, 'names': [alias.name for alias in node.names],
                                        'line': node.lineno, 'level': node.level})
                for alias in node.names:
                    aliases[alias.asname or alias.name] = '.'.join(filter(None, [module, alias.name]))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                decorators = [_expression(value) for value in node.decorator_list]
                symbol = {'name': node.name, 'kind': 'class' if isinstance(node, ast.ClassDef) else 'function',
                          'start_line': node.lineno, 'end_line': node.end_lineno,
                          'decorators': decorators}
                if isinstance(node, ast.ClassDef):
                    symbol['bases'] = [_expression(base) for base in node.bases]
                    if any(base.endswith(('Model', 'AbstractUser', 'AbstractBaseUser', 'ModelForm', 'ModelSerializer')) for base in symbol['bases']):
                        item['models'].append({'name': node.name, 'line': node.lineno, 'bases': symbol['bases']})
                else:
                    symbol['parameters'] = [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
                item['symbols'].append(symbol)
                item['decorators'].extend({'expression': value, 'line': raw.lineno, 'symbol': node.name}
                                          for raw, value in zip(node.decorator_list, decorators))
            elif isinstance(node, ast.Call):
                call = _name(node.func)
                expanded = aliases.get(call.split('.')[0], call.split('.')[0]) + ('.' + call.partition('.')[2] if '.' in call else '')
                item['calls'].append({'name': call, 'resolved_name': expanded, 'line': node.lineno})
                if expanded.rsplit('.', 1)[-1] in {'path', 're_path', 'url', 'route', 'add_url_rule'}:
                    item['routes'].append({'line': node.lineno, 'call': expanded,
                                           'pattern': _expression(node.args[0]) if node.args else '',
                                           'target': _expression(node.args[1]) if len(node.args) > 1 else '',
                                           'keywords': {kw.arg: _expression(kw.value) for kw in node.keywords if kw.arg}})
                if call.endswith(('.connect', '.send', '.send_robust')) or expanded.rsplit('.', 1)[-1] in {'receiver', 'Signal'}:
                    item['signals'].append({'call': expanded, 'line': node.lineno})
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                item['assignments'].extend({'name': _name(target), 'line': node.lineno,
                                             'value': _expression(node.value) if node.value is not None else ''}
                                            for target in targets if _name(target))
        dependencies = set()
        for entry in item['imports']:
            choices = [entry['module']] + ['.'.join(filter(None, [entry['module'], name])) for name in entry['names']]
            dependencies.update(target for choice in choices if (target := resolve(choice)) and target != path)
        for reference in references:
            if re.fullmatch(r'[A-Za-z_]\w*(?:\.\w+)+', reference):
                target = resolve(reference)
                if target and target != path:
                    dependencies.add(target)
            elif '/' in reference:
                dependencies.update(target for target in documents if target != path and (target == reference or target.endswith('/' + reference)))
        item['dependencies'] = sorted(dependencies)
        result[path] = item
    # App-label/class references (for example a configurable user model) need
    # not spell the module containing the class. Resolve against actual symbols.
    for path, item in result.items():
        dependencies = set(item['dependencies'])
        for reference in item['references']:
            if not re.fullmatch(r'[A-Za-z_]\w*(?:\.\w+)+', reference):
                continue
            package, _, symbol_name = reference.rpartition('.')
            for target, target_item in result.items():
                module = target_item.get('module') or ''
                if target != path and (module == package or module.startswith(package + '.')) and any(symbol['name'] == symbol_name for symbol in target_item['symbols']):
                    dependencies.add(target)
        item['dependencies'] = sorted(dependencies)
    for path, item in result.items():
        for dependency in item['dependencies']:
            if dependency in result:
                result[dependency]['dependents'].append(path)
    for item in result.values():
        item['dependents'].sort()
    return result
