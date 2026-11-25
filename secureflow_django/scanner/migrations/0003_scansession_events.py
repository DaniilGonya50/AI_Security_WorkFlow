from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('scanner', '0002_workflowscenario')]

    operations = [
        migrations.AddField(
            model_name='scansession',
            name='events',
            field=models.JSONField(blank=True, default=list),
        ),
    ]
