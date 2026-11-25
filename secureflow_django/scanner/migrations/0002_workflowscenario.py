from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('scanner', '0001_initial')]
    operations = [
        migrations.CreateModel(
            name='WorkflowScenario',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=120)),
                ('snapshot', models.JSONField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
