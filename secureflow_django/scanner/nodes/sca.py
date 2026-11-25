import json
import re
from pathlib import Path
from .base import BaseNode, Finding, NodeContext, relative_path


class ScaNode(BaseNode):
    node_type = 'sca_scanner'
    display_name = 'Проверка зависимостей (SCA)'

    COORD = re.compile(r'([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"\'\s)]+)')
    MAVEN_GROUP = re.compile(r'<groupId>\s*([^<]+)\s*</groupId>', re.I)
    MAVEN_ARTIFACT = re.compile(r'<artifactId>\s*([^<]+)\s*</artifactId>', re.I)
    MAVEN_VERSION = re.compile(r'<version>\s*([^<]+)\s*</version>', re.I)

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.vulnerabilities = self._load_db()

    def _load_db(self):
        if not self.db_path.exists():
            return []
        with self.db_path.open('r', encoding='utf-8') as stream:
            payload = json.load(stream)
        records = payload.get('vulnerabilities', [])
        return records if isinstance(records, list) else []

    @staticmethod
    def _version_tuple(value):
        return tuple(int(x) for x in re.findall(r'\d+', str(value))) or (0,)

    @classmethod
    def _is_vulnerable(cls, version, ranges):
        if not version or '$' in str(version) or str(version).startswith('libs.'):
            return False
        current = cls._version_tuple(version)
        for item in ranges:
            lower, upper = item.get('lower'), item.get('upper')
            if lower is not None:
                low = cls._version_tuple(lower)
                if current < low or (current == low and not item.get('lowerInclusive', False)):
                    continue
            if upper is not None:
                high = cls._version_tuple(upper)
                if current > high or (current == high and not item.get('upperInclusive', False)):
                    continue
            return True
        return False

    @staticmethod
    def _gradle_lock_versions(root):
        locked = {}
        for path in root.rglob('gradle.lockfile'):
            try:
                for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                    m = re.match(r'\s*([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^=\s]+)(?:=.*)?$', line)
                    if m:
                        locked[(m.group(1), m.group(2))] = m.group(3)
            except OSError:
                continue
        return locked

    @staticmethod
    def _gradle_properties(root):
        values = {}
        # Gradle property file.
        for path in root.rglob('gradle.properties'):
            try:
                for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                    m = re.match(r'\s*([A-Za-z_][\w.-]*)\s*=\s*(.*?)\s*$', line)
                    if m and not m.group(1).startswith('#'):
                        values[m.group(1)] = m.group(2).strip().strip('"\'')
            except OSError:
                pass
        return values

    @staticmethod
    def _dependencies_block(text):
        # Only inspect the dependencies { ... } block, avoiding comments and arbitrary strings.
        start = re.search(r'\bdependencies\s*\{', text)
        if not start:
            return []
        depth, end = 1, start.end()
        in_string = None
        escaped = False
        for i in range(start.end(), len(text)):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == '\\':
                    escaped = True
                elif ch == in_string:
                    in_string = None
                continue
            if ch in ('"', "'"):
                in_string = ch
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break
        return [(start.end(), text[start.end():end])]

    @classmethod
    def _parse_gradle(cls, text, properties):
        # Resolve simple local declarations: val version = "1.2.3" and val version by ...
        variables = dict(properties)
        for m in re.finditer(r'''(?m)^\s*(?:val|var|def)\s+([A-Za-z_]\w*)\s*=\s*["']([^"']+)["']''', text):
            variables[m.group(1)] = m.group(2)
        for m in re.finditer(r'''providers\.gradleProperty\(["']([^"']+)["']\)\.get\(\)''', text):
            prop = m.group(1)
            if prop in properties:
                variables[prop] = properties[prop]
        for m in re.finditer(r'''(?m)^\s*(?:val|var|def)\s+([A-Za-z_]\w*)\s*=\s*providers\.gradleProperty\(["']([^"']+)["']\)\.get\(\)''', text):
            variable, prop = m.groups()
            if prop in properties:
                variables[variable] = properties[prop]

        results = []
        blocks = cls._dependencies_block(text)
        for block_start, body in blocks:
            # Standard implementation("g:a:v") and multiline add("implementation", "g:a:v")
            for m in re.finditer(r'''(?:implementation|api|runtimeOnly|compileOnly|testImplementation|classpath)\s*\(\s*["']([^"']+)["']\s*\)''', body, re.S):
                coord = m.group(1)
                cls._append_coordinate(results, coord, body, block_start + m.start(), variables)
            for m in re.finditer(r'''add\s*\(\s*["'][^"']+["']\s*,\s*["']([^"']+)["']\s*\)''', body, re.S):
                cls._append_coordinate(results, m.group(1), body, block_start + m.start(), variables)
        return results

    @classmethod
    def _append_coordinate(cls, results, coordinate, full_text, absolute_offset, variables):
        m = cls.COORD.fullmatch(coordinate.strip())
        if not m:
            return
        group, artifact, version = m.groups()
        version = version.strip()
        if version.startswith('$'):
            key = version.lstrip('$').strip('{}')
            version = variables.get(key, version)
        elif version.startswith('${') and version.endswith('}'):
            version = variables.get(version[2:-1], version)
        if version.startswith('providers.gradleProperty'):
            prop = re.search(r'''gradleProperty\(["']([^"']+)["']\)''', version)
            version = variables.get(prop.group(1), version) if prop else version
        line_no = full_text.count('\n', 0, absolute_offset) + 1
        results.append((line_no, group, artifact, version))

    @classmethod
    def _parse_maven(cls, text):
        result = []
        for block in re.finditer(r'<dependency\b[^>]*>(.*?)</dependency>', text, re.I | re.S):
            body = block.group(1)
            group, artifact, version = (cls.MAVEN_GROUP.search(body),
                                       cls.MAVEN_ARTIFACT.search(body),
                                       cls.MAVEN_VERSION.search(body))
            if group and artifact and version:
                result.append((text.count('\n', 0, block.start()) + 1,
                               group.group(1).strip(), artifact.group(1).strip(),
                               version.group(1).strip()))
        return result

    def _check(self, group, artifact, version, line_no, rel):
        results = []
        for vuln in self.vulnerabilities:
            if vuln.get('group') != group or vuln.get('artifact') != artifact:
                continue
            if self._is_vulnerable(version, vuln.get('ranges', [])):
                advisory_ids = []
                if vuln.get('advisory'):
                    advisory_ids.append(vuln['advisory'])
                advisory_ids.extend(vuln.get('aliases') or [])
                if vuln.get('id') and vuln['id'] not in advisory_ids:
                    advisory_ids.append(vuln['id'])
                if not advisory_ids:
                    advisory_ids = ['unknown']
                results.append(Finding(
                    'SCA', line_no, rel, vuln.get('severity', 'LOW'),
                    'known-vulnerable-dependency', None, group, artifact, version,
                    advisory_ids
                ))
        return results

    def run(self, context: NodeContext) -> list[Finding]:
        findings, seen = [], set()
        properties = self._gradle_properties(context.root)
        locked_versions = self._gradle_lock_versions(context.root)
        for file in context.files:
            name = file.name.lower()
            if name not in {'build.gradle.kts', 'build.gradle', 'pom.xml'}:
                continue
            try:
                text = file.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            rel = relative_path(file, context.root)
            dependencies = self._parse_maven(text) if name == 'pom.xml' else self._parse_gradle(text, properties)
            for line_no, group, artifact, version in dependencies:
                # The lockfile is the resolved version source when available.
                version = locked_versions.get((group, artifact), version)
                for finding in self._check(group, artifact, version, line_no, rel):
                    key = (finding.file, finding.line, finding.group, finding.artifact, finding.version, tuple(finding.advisory_ids or []))
                    if key not in seen:
                        seen.add(key)
                        findings.append(finding)
        return sorted(findings, key=lambda x: (x.file, x.line, x.artifact or ''))
