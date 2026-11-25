import json
import uuid
from pathlib import Path
from django.conf import settings
from django.http import Http404, FileResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import ScanSession, WorkflowScenario
from .serializers import WorkflowSerializer, UploadScanSerializer
from .services import start_scan

class GitScanView(APIView):
    def post(self, request):
        serializer = WorkflowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        workflow = serializer.validated_data['workflow']
        repo_url = next((node.get('info', {}).get('data') for node in workflow
                         if node.get('type') == 'projecttype'), None)
        if not repo_url:
            return Response({'detail': 'В графе нет URL репозитория (нода projecttype)'},
                            status=status.HTTP_400_BAD_REQUEST)
        session = ScanSession.objects.create()
        start_scan(session, repo_url, 'git', workflow)
        return Response({'status': 'Ok', 'session_id': str(session.session_id),
                         'text': 'Клонирование и сканирование запущены'}, status=status.HTTP_202_ACCEPTED)

class UploadScanView(APIView):
    def post(self, request):
        serializer = UploadScanSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        uploaded_file = serializer.validated_data['file']
        workflow = serializer.validated_data['workflow_json']
        temp_path = settings.SCAN_TEMP_DIR / f'upload_{uuid.uuid4().hex}.zip'
        try:
            with temp_path.open('wb') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
        except OSError:
            temp_path.unlink(missing_ok=True)
            return Response({'detail': 'Не удалось сохранить загруженный архив'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        session = ScanSession.objects.create()
        start_scan(session, str(temp_path), 'zip', workflow)
        return Response({'status': 'Ok', 'session_id': str(session.session_id),
                         'text': 'Распаковка и сканирование запущены'}, status=status.HTTP_202_ACCEPTED)

class ScanStatusView(APIView):
    def get(self, request):
        session_id = request.query_params.get('session_id')
        if not session_id:
            return Response({'detail': 'Не указан session_id'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            uuid.UUID(session_id)
            session = ScanSession.objects.get(session_id=session_id)
        except (ValueError, ScanSession.DoesNotExist):
            raise Http404('Сессия не найдена')

        payload = {'text': session.current_text, 'progress': session.progress, 'stage': session.stage, 'events': session.events or []}
        if session.status == ScanSession.Status.ERROR:
            return Response({'status': 'Error', **payload, 'error': session.error_text})
        if session.status == ScanSession.Status.ENDED:
            return Response({'status': 'End', **payload, 'data': session.final_data})
        return Response({'status': 'Ok', **payload})


def frontend_index(request):
    index_file = settings.BASE_DIR / 'static' / 'index.html'
    return FileResponse(open(index_file, 'rb'))

def frontend_static(request, path):
    from django.http import FileResponse
    from django.utils._os import safe_join
    from django.core.exceptions import SuspiciousFileOperation
    try:
        file_path = safe_join(str(settings.BASE_DIR / 'static'), path)
    except SuspiciousFileOperation:
        raise Http404
    if not Path(file_path).is_file():
        raise Http404
    return FileResponse(open(file_path, 'rb'))


class ScenarioListCreateView(APIView):
    def get(self, request):
        items = WorkflowScenario.objects.order_by('-updated_at')[:100]
        return Response([
            {'id': item.id, 'title': item.title, 'created_at': item.created_at.isoformat(),
             'updated_at': item.updated_at.isoformat()} for item in items
        ])

    def post(self, request):
        title = str(request.data.get('title', '')).strip()[:120]
        snapshot = request.data.get('snapshot')
        if not title:
            return Response({'detail': 'Укажи название сценария'}, status=status.HTTP_400_BAD_REQUEST)
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get('nodes'), list) or not isinstance(snapshot.get('edges'), list):
            return Response({'detail': 'Некорректная структура сценария'}, status=status.HTTP_400_BAD_REQUEST)
        item = WorkflowScenario.objects.create(title=title, snapshot=snapshot)
        return Response({'id': item.id, 'title': item.title, 'created_at': item.created_at.isoformat()},
                        status=status.HTTP_201_CREATED)


class ScenarioDetailView(APIView):
    def get(self, request, scenario_id):
        try:
            item = WorkflowScenario.objects.get(pk=scenario_id)
        except WorkflowScenario.DoesNotExist:
            raise Http404('Сценарий не найден')
        return Response({'id': item.id, 'title': item.title, 'snapshot': item.snapshot,
                         'created_at': item.created_at.isoformat()})

    def delete(self, request, scenario_id):
        try:
            item = WorkflowScenario.objects.get(pk=scenario_id)
        except WorkflowScenario.DoesNotExist:
            raise Http404('Сценарий не найден')
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ReportListView(APIView):
    """История завершённых запусков. До добавления аккаунтов общая для инсталляции."""
    def get(self, request):
        items = ScanSession.objects.filter(status=ScanSession.Status.ENDED).order_by('-created_at')[:100]
        return Response([
            {'session_id': str(item.session_id), 'created_at': item.created_at.isoformat(),
             'findings_count': len((item.final_data or {}).get('findings', [])),
             'summary': ((item.final_data or {}).get('ai_report') or {}).get('summary', ''),
             'status': item.status}
            for item in items
        ])


class ReportDetailView(APIView):
    def get(self, request, session_id):
        try:
            item = ScanSession.objects.get(session_id=session_id, status=ScanSession.Status.ENDED)
        except (ScanSession.DoesNotExist, ValueError):
            raise Http404('Отчёт не найден')
        return Response({'session_id': str(item.session_id), 'created_at': item.created_at.isoformat(),
                         'data': item.final_data or {}, 'events': item.events or []})
