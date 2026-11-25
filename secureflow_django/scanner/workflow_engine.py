import asyncio
from pathlib import Path
from .nodes.base import NodeContext
from .nodes.secrets import SecretsNode
from .nodes.sca import ScaNode
from .nodes.sast import SastNode

class WorkflowError(ValueError):
    pass

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
        roots = []
        for node_id, node in by_id.items():
            parents = node.get('parentid', [])
            if not isinstance(parents, list):
                raise WorkflowError(f'parentid ноды {node_id} должен быть списком')
            if -1 in parents or '-1' in parents:
                roots.append(node_id)
            for parent in parents:
                if parent in (-1, '-1'):
                    continue
                parent_id = str(parent)
                if parent_id not in by_id:
                    raise WorkflowError(f'У ноды {node_id} указан отсутствующий родитель {parent_id}')
                children[parent_id].append(node_id)
                indegree[node_id] += 1
        if not roots:
            raise WorkflowError('В графе не найдена корневая нода (parentid должен содержать -1)')
        # Kahn: гарантирует отсутствие циклов; порядок максимально близок к обходу исходного графа.
        queue = [node_id for node_id in by_id if indegree[node_id] == 0]
        ordered = []
        while queue:
            current = queue.pop(0)
            ordered.append(by_id[current])
            for child in children[current]:
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
        if len(ordered) != len(by_id):
            raise WorkflowError('В графе обнаружен цикл или недостижимая цепочка нод')
        return ordered

    async def execute_graph(self, graph_json: list[dict], context: NodeContext, session):
        ordered = self._ordered_nodes(graph_json)
        message_config = None
        llm_config = None
        all_findings = []
        scanners = {
            'secrets': SecretsNode(),
            'sca': ScaNode(self.db_path),
            'sast': SastNode(),
        }
        for index, node in enumerate(ordered, start=1):
            node_type = node.get('type')
            info = node.get('info') or {}
            session.current_text = f"Выполняется: {node_type} ({info.get('type', '')})"
            session.stage = 'scanning'
            session.progress = min(95, int(index / len(ordered) * 95))
            # В Django состояние хранится в БД, поэтому фиксируем прогресс для polling.
            await asyncio.to_thread(
                session.save,
                update_fields=['current_text', 'stage', 'progress', 'updated_at'],
            )
            if node_type == 'message':
                message_config = info
                session.data_ready = True
            elif node_type == 'llmtype':
                llm_config = info
            elif node_type in ('triggers', 'trigger_button', 'trigger_schedule', 'projecttype'):
                continue
            elif node_type == 'check':
                scanner_type = info.get('type')
                scanner = scanners.get(scanner_type)
                if scanner is None:
                    raise WorkflowError(f'Неизвестный тип проверки: {scanner_type}')
                results = await asyncio.to_thread(scanner.run, context)
                all_findings.extend(vars(item) for item in results)
            elif node_type == 'logic':
                # В исходной реализации if/else тоже пропускались.
                continue
            else:
                raise WorkflowError(f'Неизвестный тип ноды: {node_type}')
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        all_findings.sort(key=lambda item: severity_order.get(item.get('severity', 'LOW'), 5))
        session.final_data = {
            'message_config': message_config,
            'llm_config': llm_config,
            'findings': all_findings,
        }
        session.status = 'ended'
        session.stage = 'done'
        session.progress = 100
        session.current_text = 'Анализ завершен'
