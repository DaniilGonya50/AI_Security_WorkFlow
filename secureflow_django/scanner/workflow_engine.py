import ast
import asyncio
import operator
import re
from pathlib import Path
from dataclasses import replace

from .nodes.base import NodeContext
from .nodes.secrets import SecretsNode
from .nodes.sca import ScaNode
from .nodes.sast import SastNode


class WorkflowError(ValueError):
    pass


_ALLOWED_COMPARE = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne,
    ast.Gt: operator.gt, ast.GtE: operator.ge,
    ast.Lt: operator.lt, ast.LtE: operator.le,
}
_ALLOWED_BOOL = {ast.And: all, ast.Or: any}


def _resolve_name(name, metrics):
    aliases = {
        'vulnerabilities': metrics['findings']['total'],
        'critical': metrics['findings']['critical'],
        'critical_count': metrics['findings']['critical'],
        'high': metrics['findings']['high'],
        'high_count': metrics['findings']['high'],
        'medium': metrics['findings']['medium'],
        'medium_count': metrics['findings']['medium'],
        'low': metrics['findings']['low'],
        'low_count': metrics['findings']['low'],
        'total_count': metrics['findings']['total'],
        'sast': metrics['sast'], 'sca': metrics['sca'], 'secrets': metrics['secrets'],
        'findings': metrics['findings'],
    }
    if name in aliases:
        return aliases[name]
    raise WorkflowError(f'Неизвестная переменная в условии: {name}')


def _eval_condition(expression, metrics):
    """Safe expression evaluator: no eval(), calls, attributes or arbitrary code."""
    try:
        tree = ast.parse(expression, mode='eval')
    except SyntaxError as exc:
        raise WorkflowError(f'Некорректное условие IF/ELSE: {exc.msg}') from exc

    def value(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool)):
            return node.value
        if isinstance(node, ast.Name):
            return _resolve_name(node.id, metrics)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            root = _resolve_name(node.value.id, metrics)
            if isinstance(root, dict) and node.attr in root:
                return root[node.attr]
            raise WorkflowError(f'Неизвестное поле в условии: {node.value.id}.{node.attr}')
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            op = _ALLOWED_COMPARE.get(type(node.ops[0]))
            if not op:
                raise WorkflowError('Этот оператор сравнения не поддерживается')
            try:
                return op(value(node.left), value(node.comparators[0]))
            except TypeError as exc:
                raise WorkflowError('В условии сравниваются несовместимые типы данных') from exc
        if isinstance(node, ast.BoolOp) and type(node.op) in _ALLOWED_BOOL:
            values = [bool(value(item)) for item in node.values]
            return _ALLOWED_BOOL[type(node.op)](values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not bool(value(node.operand))
        raise WorkflowError('Условие содержит неподдерживаемую конструкцию')

    return bool(value(tree.body))


class WorkflowEngine:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    @staticmethod
    def _ordered_nodes(nodes_data: list[dict]) -> list[dict]:
        if not isinstance(nodes_data, list) or not nodes_data:
            raise WorkflowError('Граф workflow пуст')
        by_id = {}
        for node in nodes_data:
            node_id = str(node.get('id'))
            if node_id in by_id:
                raise WorkflowError(f'Повторяется id ноды: {node_id}')
            by_id[node_id] = node
        children = {node_id: [] for node_id in by_id}
        indegree = {node_id: 0 for node_id in by_id}
        for node_id, node in by_id.items():
            parents = node.get('parentid', [])
            if not isinstance(parents, list):
                raise WorkflowError(f'parentid ноды {node_id} должен быть списком')
            branches = node.get('info', {}).get('parent_branches', [])
            for index, parent in enumerate(parents):
                if parent in (-1, '-1'):
                    continue
                parent_id = str(parent)
                if parent_id not in by_id:
                    raise WorkflowError(f'У ноды {node_id} указан отсутствующий родитель {parent_id}')
                branch = branches[index] if index < len(branches) else None
                children[parent_id].append((node_id, branch))
                indegree[node_id] += 1
        queue = [node_id for node_id in by_id if indegree[node_id] == 0]
        ordered = []
        while queue:
            current = queue.pop(0)
            ordered.append(by_id[current])
            for child_id, _ in children[current]:
                indegree[child_id] -= 1
                if indegree[child_id] == 0:
                    queue.append(child_id)
        if len(ordered) != len(by_id):
            raise WorkflowError('В графе обнаружен цикл')
        return ordered

    @staticmethod
    def _regex_files(files, config):
        if not config:
            return files, 0
        pattern = str(config.get('pattern') or '')
        if not pattern:
            raise WorkflowError('Regex включён, но выражение пустое')
        flags = 0
        flag_text = str(config.get('flags') or '')
        if 'i' in flag_text.lower(): flags |= re.IGNORECASE
        if 'm' in flag_text.lower(): flags |= re.MULTILINE
        if 's' in flag_text.lower(): flags |= re.DOTALL
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            raise WorkflowError(f'Некорректное регулярное выражение: {exc}') from exc
        scope = config.get('scope', 'path')
        mode = config.get('mode', 'include')
        selected = []
        for file in files:
            try:
                target = file.as_posix() if scope == 'path' else file.read_text(encoding='utf-8', errors='replace')
            except OSError:
                target = ''
            matched = bool(compiled.search(target))
            if matched == (mode != 'exclude'):
                selected.append(file)
        return selected, len(selected)

    async def execute_graph(self, graph_json: list[dict], context: NodeContext, session):
        ordered = self._ordered_nodes(graph_json)
        by_id = {str(n.get('id')): n for n in ordered}
        children = {node_id: [] for node_id in by_id}
        parents = {node_id: [] for node_id in by_id}
        for node_id, node in by_id.items():
            branches = (node.get('info') or {}).get('parent_branches', [])
            for idx, parent in enumerate(node.get('parentid', [])):
                if parent in (-1, '-1'):
                    continue
                parent_id = str(parent)
                branch = branches[idx] if idx < len(branches) else None
                children[parent_id].append((node_id, branch))
                parents[node_id].append((parent_id, branch))

        message_config = None
        llm_config = None
        all_findings = []
        node_results = {}
        scanners = {'secrets': SecretsNode(), 'sca': ScaNode(self.db_path), 'sast': SastNode()}
        metrics = {
            'findings': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'sast': 0, 'sca': 0, 'secrets': 0,
        }
        session.events = []
        executed = set()
        skipped_nodes = set()
        root_regex = next(((n.get('info') or {}).get('regex_config') for n in ordered if n.get('type') == 'projecttype'), None)
        for index, node in enumerate(ordered, start=1):
            node_id = str(node.get('id'))
            node_type = node.get('type')
            info = node.get('info') or {}
            incoming = parents[node_id]
            eligible = True
            if incoming:
                # На слиянии веток достаточно одного активного входа. Пропущенная
                # альтернативная ветка не должна блокировать общую последующую ноду.
                active_incoming = False
                for parent_id, branch in incoming:
                    if parent_id in skipped_nodes or parent_id not in executed:
                        continue
                    parent_branch = node_results.get(parent_id, {}).get('branch')
                    if parent_branch is not None and branch is not None:
                        if str(branch).lower() != str(parent_branch).lower():
                            continue
                    active_incoming = True
                eligible = active_incoming
            title = str(node.get('title') or info.get('type') or node_type)
            if not eligible:
                event = {'node_id': node_id, 'type': node_type, 'title': title,
                         'status': 'skipped', 'findings_count': 0,
                         'message': 'Пропущено: выбрана другая ветка IF/ELSE',
                         'progress': min(95, int(index / len(ordered) * 95))}
                session.events.append(event)
                executed.add(node_id)
                skipped_nodes.add(node_id)
                await asyncio.to_thread(session.save, update_fields=['events', 'updated_at'])
                continue

            session.current_text = f'Выполняется: {title}'
            session.stage = 'scanning'
            session.progress = min(95, int((index - 1) / len(ordered) * 95))
            await asyncio.to_thread(session.save, update_fields=['current_text', 'stage', 'progress', 'updated_at'])
            session.events.append({'node_id': node_id, 'type': node_type, 'title': title,
                'status': 'running', 'findings_count': 0, 'message': 'Выполняется этап...',
                'progress': session.progress})
            await asyncio.to_thread(session.save, update_fields=['events', 'updated_at'])

            node_findings = []
            branch_result = None
            message = 'Этап выполнен'
            if node_type == 'message':
                message_config = info
            elif node_type == 'llmtype':
                llm_config = info
            elif node_type in ('triggers', 'trigger_button', 'trigger_schedule', 'projecttype'):
                pass
            elif node_type == 'check':
                scanner_type = info.get('type')
                scanner = scanners.get(scanner_type)
                if scanner is None:
                    raise WorkflowError(f'Неизвестный тип проверки: {scanner_type}')
                regex_config = info.get('regex_config') or root_regex
                scan_files = context.files
                regex_count = None
                if regex_config:
                    scan_files, regex_count = self._regex_files(context.files, regex_config)
                scan_context = replace(context, files=scan_files)
                results = await asyncio.to_thread(scanner.run, scan_context)
                node_findings = [vars(item) for item in results]
                all_findings.extend(node_findings)
                metrics[scanner_type] += len(node_findings)
                message = f'Проверка завершена: {len(node_findings)} находок'
                if regex_count is not None:
                    message += f'; файлов после Regex-фильтра: {regex_count}'
            elif node_type == 'logic':
                branch_result = _eval_condition(str(info.get('condition') or info.get('data') or ''), metrics)
                message = f'Условие IF/ELSE: {"TRUE" if branch_result else "FALSE"}'
            else:
                raise WorkflowError(f'Неизвестный тип ноды: {node_type}')

            for finding in node_findings:
                metrics['findings']['total'] += 1
                severity = str(finding.get('severity', '')).lower()
                if severity in metrics['findings']:
                    metrics['findings'][severity] += 1
            node_results[node_id] = {'branch': branch_result, 'findings_count': len(node_findings)}
            executed.add(node_id)
            session.events.append({'node_id': node_id, 'type': node_type, 'title': title,
                'status': 'done', 'findings_count': len(node_findings), 'message': message,
                'branch': branch_result, 'progress': min(95, int(index / len(ordered) * 95))})
            await asyncio.to_thread(session.save, update_fields=['events', 'current_text', 'stage', 'progress', 'updated_at'])

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        all_findings.sort(key=lambda item: severity_order.get(item.get('severity', 'LOW'), 5))
        session.final_data = {'message_config': message_config, 'llm_config': llm_config,
                              'findings': all_findings, 'metrics': metrics}
        session.status = 'ended'
        session.stage = 'done'
        session.progress = 100
        session.current_text = 'Анализ завершен'
        await asyncio.to_thread(session.save, update_fields=['status', 'stage', 'progress', 'current_text', 'final_data', 'updated_at'])
