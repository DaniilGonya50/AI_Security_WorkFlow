import os
from django.core.management.base import BaseCommand, CommandError
from ai_module.storage import UserStorage
from ai_module.telegram_bot import TelegramBot


class Command(BaseCommand):
    help = 'Запускает Telegram-бота SecureFlow и обработчик /start'

    def handle(self, *args, **options):
        token = os.getenv('TELEGRAM_BOT_TOKEN', '').strip()
        if not token:
            raise CommandError('В .env не задан TELEGRAM_BOT_TOKEN')
        self.stdout.write(self.style.SUCCESS('Telegram-бот запускается. Напиши ему /start.'))
        TelegramBot(token, UserStorage()).run()
