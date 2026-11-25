import asyncio
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from scanner.workflow_engine import WorkflowEngine, _eval_condition, WorkflowError
from scanner.nodes.base import Finding, NodeContext


class WorkflowEngineUnitTests(unittest.TestCase):
    def setUp(self):
        self.metrics = {
            'findings': {'total': 4, 'critical': 1, 'high': 2, 'medium': 1, 'low': 0},
            'sast': 2, 'sca': 1, 'secrets': 1,
        }

    def test_condition_uses_previous_scan_metrics(self):
        self.assertTrue(_eval_condition('findings.critical > 0 and sast == 2', self.metrics))
        self.assertTrue(_eval_condition('critical_count > 0 or secrets == 0', self.metrics))
        self.assertFalse(_eval_condition('findings.low > 0', self.metrics))

    def test_condition_rejects_function_calls(self):
        with self.assertRaises(WorkflowError):
            _eval_condition('__import__("os").system("whoami")', self.metrics)

    def test_regex_file_filter_include_and_exclude(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            kotlin = root / 'src' / 'Main.kt'
            java = root / 'src' / 'Main.java'
            kotlin.parent.mkdir()
            kotlin.write_text('val safe = true', encoding='utf-8')
            java.write_text('val safe = true', encoding='utf-8')
            files = [kotlin, java]
            included, count = WorkflowEngine._regex_files(files, {
                'pattern': r'\.kt$', 'scope': 'path', 'mode': 'include', 'flags': 'i'
            })
            self.assertEqual(count, 1)
            self.assertEqual(included, [kotlin])
            excluded, count = WorkflowEngine._regex_files(files, {
                'pattern': r'\.kt$', 'scope': 'path', 'mode': 'exclude', 'flags': 'i'
            })
            self.assertEqual(count, 1)
            self.assertEqual(excluded, [java])

    def test_regex_rejects_invalid_pattern(self):
        with self.assertRaises(WorkflowError):
            WorkflowEngine._regex_files([], {'pattern': '(', 'scope': 'path'})


class _FakeScanner:
    def run(self, context):
        return [Finding('SAST', 1, 'sample.kt', 'CRITICAL', 'test-rule')]


class _FakeSession:
    def __init__(self):
        self.events = []
        self.status = 'running'
        self.final_data = {}
        self.current_text = ''
        self.stage = ''
        self.progress = 0

    def save(self, update_fields=None):
        pass


class WorkflowBranchExecutionTests(unittest.TestCase):
    def test_true_branch_skips_false_and_merges(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'sample.kt'
            source.write_text('safe', encoding='utf-8')
            graph = [
                {'id': 1, 'type': 'projecttype', 'parentid': [-1], 'info': {}},
                {'id': 2, 'type': 'check', 'parentid': [1], 'info': {'type': 'sast'}},
                {'id': 3, 'type': 'logic', 'parentid': [2], 'info': {'condition': 'critical_count > 0'}},
                {'id': 4, 'type': 'message', 'parentid': [3], 'info': {'type': 'telegram', 'parent_branches': ['true']}},
                {'id': 5, 'type': 'message', 'parentid': [3], 'info': {'type': 'smtp', 'parent_branches': ['false']}},
                {'id': 6, 'type': 'message', 'parentid': [4, 5], 'info': {'type': 'webhook', 'parent_branches': [None, None]}},
            ]
            session = _FakeSession()
            with patch('scanner.workflow_engine.SastNode', return_value=_FakeScanner()):
                asyncio.run(WorkflowEngine(Path('data/vulnerabilities.json')).execute_graph(
                    graph, NodeContext([source], root, 'test-run'), session
                ))
            states = {(event['node_id'], event['status']) for event in session.events}
            self.assertIn(('4', 'done'), states)
            self.assertIn(('5', 'skipped'), states)
            self.assertIn(('6', 'done'), states)
            self.assertEqual(session.final_data['metrics']['findings']['critical'], 1)


if __name__ == '__main__':
    unittest.main()
