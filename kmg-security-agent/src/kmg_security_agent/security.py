"""Best-effort secret masking, preserving source line numbers."""
import re

class Redactor:
    def __init__(self, *secrets: str):
        self.secrets = tuple(sorted((s for s in secrets if s), key=len, reverse=True))

    def __call__(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, '[REDACTED]')
        text = re.sub(r'-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END (?:[A-Z ]*PRIVATE KEY)-----',
                      lambda m: '\n'.join('[REDACTED PRIVATE KEY]' if i == 0 else '' for i, _ in enumerate(m[0].split('\n'))), text)
        text = re.sub(r'\b(?:sk-or-v1-[A-Za-z0-9_-]+|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16})\b', '[REDACTED]', text)
        # Quoted string values only: do not erase permission predicates or variable references.
        text = re.sub(r'''(?im)(["']?\b(?:[a-z0-9_]+[_-])?(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|token)["']?\s*[:=]\s*)(["'])((?:\\[^\r\n]|(?!\2)[^\\\r\n])*)(\2)''',
                      lambda m: m[1] + m[2] + '[REDACTED]' + m[4], text)
        # Plain YAML scalar credentials and literal password-setting calls.
        text = re.sub(r'(?im)^(\s*(?:[a-z0-9_]+[_-])?(?:password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\s*:\s*)(?![\s\"\'])([^\r\n#]+)',
                      lambda m: m[1] + '[REDACTED]', text)
        text = re.sub(r"(?i)(\b(?:set_password|check_password|make_password)\s*\(\s*)([\"'])((?:\\[^\r\n]|(?!\2)[^\\\r\n])*)(\2)",
                      lambda m: m[1] + m[2] + '[REDACTED]' + m[4], text)
        text = re.sub(r'(?i)(authorization["\s:=]+bearer\s+)[A-Za-z0-9._~+/-]+', r'\1[REDACTED]', text)
        text = re.sub(r'(?i)(https?://[^\s/:@]+:)[^\s/@]+(@)', r'\1[REDACTED]\2', text)
        return text
