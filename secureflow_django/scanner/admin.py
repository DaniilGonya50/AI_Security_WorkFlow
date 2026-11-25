from django.contrib import admin
from .models import ScanSession

@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
    list_display = ('session_id', 'status', 'stage', 'progress', 'created_at')
    readonly_fields = ('session_id', 'created_at', 'updated_at')
