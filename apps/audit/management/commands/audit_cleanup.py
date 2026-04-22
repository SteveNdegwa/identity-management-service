from datetime import timedelta

from django.core.management import BaseCommand
from django.utils import timezone

from audit.models import ModelAuditLog


class Command(BaseCommand):
    help = 'Clean up old model audit logs based on retention policies'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=None,
            help='Days to retain (overrides model configuration)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )

    def handle(self, *args, **options):
        if options['days'] is not None:
            if options['days'] < 0:
                self.stderr.write(self.style.ERROR('Days must be a non-negative integer'))
                return
            retention_days = options['days']
        else:
            retention_days = 365

        cutoff_date = timezone.now() - timedelta(days=retention_days)
        old_logs = ModelAuditLog.objects.filter(created_at__lt=cutoff_date)
        count = old_logs.count()

        if options['dry_run']:
            self.stdout.write(
                self.style.WARNING(f'Would delete {count} model audit log entries older than {retention_days} days')
            )
        else:
            deleted_count, _ = old_logs.delete()
            self.stdout.write(
                self.style.SUCCESS(f'Deleted {deleted_count} model audit log entries older than {retention_days} days')
            )
