import uuid
from django.db import migrations, models

class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name='ScanSession',
            fields=[
                ('session_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('status', models.CharField(choices=[('running', 'Running'), ('error', 'Error'), ('ended', 'Ended')], default='running', max_length=16)),
                ('current_text', models.CharField(default='Инициализация...', max_length=500)),
                ('error_text', models.TextField(blank=True, null=True)),
                ('final_data', models.JSONField(blank=True, null=True)),
                ('data_ready', models.BooleanField(default=False)),
                ('progress', models.PositiveSmallIntegerField(default=0)),
                ('stage', models.CharField(default='init', max_length=32)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
