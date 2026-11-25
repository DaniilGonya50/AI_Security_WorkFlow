import uuid
from django.db import models

class ScanSession(models.Model):
    class Status(models.TextChoices):
        RUNNING = 'running', 'Running'
        ERROR = 'error', 'Error'
        ENDED = 'ended', 'Ended'

    session_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.RUNNING)
    current_text = models.CharField(max_length=500, default='Инициализация...')
    error_text = models.TextField(null=True, blank=True)
    final_data = models.JSONField(null=True, blank=True)
    data_ready = models.BooleanField(default=False)
    progress = models.PositiveSmallIntegerField(default=0)
    events = models.JSONField(default=list, blank=True)
    stage = models.CharField(max_length=32, default='init')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.session_id)


class WorkflowScenario(models.Model):
    title = models.CharField(max_length=120)
    snapshot = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title
