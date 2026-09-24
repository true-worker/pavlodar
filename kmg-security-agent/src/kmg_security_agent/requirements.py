from importlib.resources import files
import json

_ROOT = files('kmg_security_agent').joinpath('resources')
REQUIREMENTS = json.loads(_ROOT.joinpath('requirements.json').read_text(encoding='utf-8'))

def system_prompt():
    return _ROOT.joinpath('system.md').read_text(encoding='utf-8')

def skill(requirement_id):
    return _ROOT.joinpath('skills', 'ib-' + requirement_id[-2:] + '.md').read_text(encoding='utf-8')
