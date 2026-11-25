from rest_framework import serializers

class WorkflowSerializer(serializers.Serializer):
    workflow = serializers.ListField(child=serializers.DictField(), allow_empty=False)

    def validate_workflow(self, value):
        for index, node in enumerate(value):
            if not isinstance(node.get('id'), (str, int)):
                raise serializers.ValidationError(f'У ноды #{index} отсутствует корректный id')
            if not isinstance(node.get('type'), str) or not node['type']:
                raise serializers.ValidationError(f'У ноды #{index} отсутствует type')
            if 'parentid' in node and not isinstance(node['parentid'], list):
                raise serializers.ValidationError(f'parentid ноды #{index} должен быть списком')
            if 'info' in node and not isinstance(node['info'], dict):
                raise serializers.ValidationError(f'info ноды #{index} должен быть объектом')
        return value

class UploadScanSerializer(serializers.Serializer):
    file = serializers.FileField()
    workflow_json = serializers.CharField()

    def validate_file(self, value):
        if not value.name.lower().endswith('.zip'):
            raise serializers.ValidationError('Поддерживаются только ZIP-архивы')
        return value

    def validate_workflow_json(self, value):
        import json
        try:
            data = json.loads(value)
        except json.JSONDecodeError as exc:
            raise serializers.ValidationError('Некорректный JSON графа') from exc
        if not isinstance(data, list) or not data:
            raise serializers.ValidationError('Граф должен быть непустым JSON-массивом')
        serializer = WorkflowSerializer(data={'workflow': data})
        serializer.is_valid(raise_exception=True)
        return data
