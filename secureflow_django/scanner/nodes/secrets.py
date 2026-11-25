import re
from .base import BaseNode, Finding, NodeContext, relative_path


class SecretsNode(BaseNode):
    node_type = 'secrets_scanner'
    display_name = 'Поиск секретов (Passwords, Keys)'

    PATTERNS = [
        (re.compile(r'(?i)(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'), 'CRITICAL', 'api-key'),
        (re.compile(r'-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----'), 'CRITICAL', 'private-key'),
        (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), 'HIGH', 'configuration-token'),
        (re.compile(r'''(?i)\b(?:password|passwd|pwd|db_password)\b\s*[:=]\s*['"][^'"\s]{4,}['"]'''), 'HIGH', 'password'),
        (re.compile(r'''(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*['"][A-Za-z0-9_./+=-]{8,}['"]'''), 'HIGH', 'api-key'),
        (re.compile(r'\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b'), 'CRITICAL', 'api-key'),
        (re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}\b'), 'CRITICAL', 'api-key'),
        (re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'), 'CRITICAL', 'api-key'),
        (re.compile(r'''(?i)://[^:/\s]+:[^@/\s]{4,}@[^/\s]+'''), 'HIGH', 'password'),
        (re.compile(r'''(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}'''), 'HIGH', 'configuration-token'),
    ]
    ALLOWED = {'.kt', '.kts', '.java', '.yml', '.yaml', '.sql', '.properties',
               '.xml', '.json', '.js', '.jsx', '.ts', '.tsx', '.py', '.gradle',
               '.toml', '.ini', '.cfg', '.conf', '.txt', '.env'}
    SKIP_VALUES = {'changeme', 'change_me', 'your_password', 'your_api_key',
                   'example', 'placeholder', 'xxx', 'test', 'replace_me'}

    @classmethod
    def _placeholder(cls, value):
        low = value.lower()
        return any(x in low for x in cls.SKIP_VALUES) or '${' in value or 'env(' in low

    def run(self, context: NodeContext) -> list[Finding]:
        findings, seen = [], set()
        for file in context.files:
            if file.suffix.lower() not in self.ALLOWED and file.name.lower() not in {'.env', '.env.local', '.env.example'}:
                continue
            try:
                text = file.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            rel, lines = relative_path(file, context.root), text.splitlines()

            for line_no, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '*', '<!--')):
                    continue
                # Sensitive variable/property with a hard-coded string.
                assignment = re.search(
                    r'''(?i)([A-Za-z_][\w.-]*(?:password|passwd|pwd|api[_-]?key|secret|token|authorization|credential)[\w.-]*)\s*[:=]\s*["']([^"']{4,})["']''',
                    line)
                if assignment and not self._placeholder(assignment.group(2)):
                    name = assignment.group(1)
                    cls = 'password' if re.search(r'(?i)pass|pwd', name) else (
                        'api-key' if re.search(r'(?i)api.?key', name) else 'configuration-token')
                    severity = {'password': 'HIGH', 'api-key': 'MEDIUM',
                                'configuration-token': 'HIGH'}.get(cls, 'HIGH')
                    key = (rel, line_no, cls)
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding('SECRET', line_no, rel, severity, cls))

                for pattern, severity, cls in self.PATTERNS:
                    match = pattern.search(line)
                    if match and not self._placeholder(match.group(0)):
                        key = (rel, line_no, cls)
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding('SECRET', line_no, rel, severity, cls))

                # Environment variable with an unsafe literal fallback.
                if re.search(r'(?i)(token|secret|password|api.?key)', line) and re.search(
                    r'''System\.getenv\s*\([^)]*\)\s*\?:\s*["'][^"']{4,}["']''', line):
                    m = re.search(r'''\?:\s*["']([^"']+)["']''', line)
                    if m and not self._placeholder(m.group(1)):
                        key = (rel, line_no, 'secret-fallback')
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding('SECRET', line_no, rel, 'LOW', 'secret-fallback'))

            # Detect two local string literals combined into a token and passed to an auth header.
            if re.search(r'(?i)(setBearerAuth|Authorization|Bearer)', text):
                literal_vars = {}
                for line_no, line in enumerate(lines, 1):
                    m = re.search(r'''(?i)\b(?:val|var)\s+([A-Za-z_]\w*)\s*=\s*["']([^"']{3,})["']''', line)
                    if m and not self._placeholder(m.group(2)):
                        literal_vars[m.group(1)] = line_no
                concat = None
                for line_no, line in enumerate(lines, 1):
                    m = re.search(r'''(?i)\b(?:val|var)\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\+\s*([A-Za-z_]\w*)''', line)
                    if m and m.group(2) in literal_vars and m.group(3) in literal_vars:
                        concat = (m.group(1), m.group(2), m.group(3), line_no)
                        break
                if concat:
                    use_line = next((n for n, line in enumerate(lines, 1)
                                     if re.search(r'(?i)(?:setBearerAuth|Authorization)', line)
                                     and re.search(rf'\b{re.escape(concat[0])}\b', line)), None)
                    if use_line:
                        first = min(literal_vars[concat[1]], literal_vars[concat[2]])
                        key = (rel, first, 'recoverable-token')
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding('SECRET', first, rel, 'MEDIUM',
                                                    'recoverable-token', use_line))
        return sorted(findings, key=lambda x: (x.file, x.line, x.type))
