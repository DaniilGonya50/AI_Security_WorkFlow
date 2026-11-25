from django.urls import path
from scanner.views import GitScanView, UploadScanView, ScanStatusView, frontend_index, frontend_static, ScenarioListCreateView, ScenarioDetailView

urlpatterns = [
    path('', frontend_index, name='frontend-index'),
    path('static/<path:path>', frontend_static, name='frontend-static'),
    path('api/scan/start/git', GitScanView.as_view(), name='scan-start-git'),
    # Совместимый короткий маршрут для клиентов, которые отправляют workflow напрямую.
    path('api/scan/start', GitScanView.as_view(), name='scan-start'),
    path('api/scan/start/upload', UploadScanView.as_view(), name='scan-start-upload'),
    path('api/scan/status', ScanStatusView.as_view(), name='scan-status'),
    path('api/scenarios', ScenarioListCreateView.as_view(), name='scenario-list-create'),
    path('api/scenarios/<int:scenario_id>', ScenarioDetailView.as_view(), name='scenario-detail'),
]
