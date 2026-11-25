import re
from .base import BaseNode, Finding, NodeContext, relative_path


class SastNode(BaseNode):
    node_type = 'sast_scanner'
    display_name = 'Логический анализ (SAST)'
    ALLOWED = {'.kt', '.kts', '.java', '.js', '.jsx', '.ts', '.tsx', '.py', '.sql', '.xml', '.gradle'}

    def run(self, context: NodeContext) -> list[Finding]:
        findings, seen, contents = [], set(), {}
        for file in context.files:
            if file.suffix.lower() not in self.ALLOWED:
                continue
            try:
                lines = file.read_text(encoding='utf-8', errors='replace').splitlines()
            except OSError:
                continue
            contents[file] = lines
            rel = relative_path(file, context.root)
            text = '\n'.join(lines)

            def add(line, severity, class_code, end_line=None):
                key = (rel, line, class_code)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding('SAST', line, rel, severity, class_code, end_line))

            # SQL injection: untrusted Kotlin interpolation/string concatenation in a JDBC query.
            for idx, line in enumerate(lines):
                if re.search(r'(?i)(queryFor(List|Object|Map)|jdbc\.query|prepareStatement|createStatement)', line):
                    window = '\n'.join(lines[idx:min(len(lines), idx+3)])
                    if re.search(r'''(?i)(SELECT|INSERT|UPDATE|DELETE)\b[^"\n]*["']?\s*\$[A-Za-z_]''', window) or re.search(r'''(?i)(SELECT|INSERT|UPDATE|DELETE)[^"\n]*["']\s*\+\s*[A-Za-z_]''', window):
                        start_line = idx + 1
                        for previous in range(idx, -1, -1):
                            if re.match(r'\s*fun\s+\w+\s*\(', lines[previous]):
                                start_line = previous + 1
                                break
                        add(start_line, 'HIGH', 'sql-injection', idx + 1)

            # Hostname verification disabled (trust-all callback).
            for idx, line in enumerate(lines):
                if re.search(r'(?i)hostnameVerifier\s*=\s*HostnameVerifier\s*\{', line):
                    window = '\n'.join(lines[idx:min(len(lines), idx+4)])
                    if re.search(r'->\s*true\b', window):
                        add(idx + 1, 'MEDIUM', 'tls-verification')

            # Wildcard origin combined with credentials is unsafe; require both settings in same file.
            wildcard_line = None
            has_credentials = False
            for idx, line in enumerate(lines):
                if re.search(r'(?i)allowCredentials\s*=\s*true', line):
                    has_credentials = True
                if re.search(r'''(?i)allowedOriginPatterns?\s*=\s*(?:listOf\s*\(\s*["']\*["']|["']\*["'])''', line):
                    wildcard_line = idx + 1
            if wildcard_line and has_credentials:
                add(wildcard_line, 'MEDIUM', 'credentialed-cors', min(len(lines), wildcard_line + 1))

            # Sensitive route explicitly marked permitAll. Ignore public catalog/status routes.
            for idx, line in enumerate(lines):
                if 'permitAll' not in line:
                    continue
                # The matcher and its path are normally on the same Kotlin DSL line.
                # If split across lines, inspect only the immediately preceding matcher line.
                window = line
                if not re.search(r'''["'](/api/[^"']+)["']''', window) and idx > 0:
                    window = lines[idx - 1] + '\n' + line
                path_match = re.search(r'''["'](/api/[^"']+)["']''', window)
                if path_match:
                    route = path_match.group(1).lower()
                    sensitive = any(word in route for word in ('export', 'admin', 'customer', 'private', 'internal', 'pickup'))
                    public_catalog = any(word in route for word in ('catalog', 'services', 'health', 'status'))
                    if sensitive and not public_catalog:
                        add(idx + 1, 'HIGH', 'route-authorization')

            # IDOR: inspect the object-reader method only. A separate safe method
            # filtering by customerId must not hide a vulnerable lookup elsewhere.
            m = re.search(r'(?i)^\s*fun\s+read\s*\([^)]*(?:id|Id)', text, re.M)
            if not m:
                m = re.search(r'(?i)^\s*(?:fun\s+)?(?:findById|getById)\s*\([^)]*(?:id|Id)', text, re.M)
            if m:
                next_method = re.search(r'(?im)^\s*fun\s+\w+\s*\(', text[m.end():])
                block_end = m.end() + next_method.start() if next_method else len(text)
                method_block = text[m.start():block_end]
                has_id_lookup = bool(re.search(r'(?i)WHERE\s+\w*_?id\s*=\s*\?', method_block))
                selects_owner = bool(re.search(r'(?i)SELECT[^"\n]*(?:customer_id|owner_id|user_id)', method_block))
                filters_owner = bool(re.search(r'(?i)WHERE[^"\n]*(?:customer_id|owner_id|user_id)\s*=', method_block))
                if has_id_lookup and selects_owner and not filters_owner:
                    line_no = text.count('\n', 0, m.start()) + 1
                    add(line_no, 'HIGH', 'object-authorization', line_no + 1)

        return sorted(findings, key=lambda x: (x.file, x.line, x.class_code or ''))
