from datetime import timedelta

from django.db import models

from base.models import BaseModel


class RateLimitRule(BaseModel):
    SCOPE_CHOICES = [
        ('global','Global'),
        ('user_id', 'Per User ID'),
        ('system_user_id', 'Per System User ID'),
        ('ip', 'Per IP'),
        ('endpoint', 'Per Endpoint'),
        ('user_id_endpoint', 'Per User ID + Endpoint'),
        ('system_user_id_endpoint', 'Per System User ID + Endpoint'),
        ('ip_endpoint', 'Per IP + Endpoint'),
    ]

    PERIOD_CHOICES = [
        ('second', 'Second'),
        ('minute', 'Minute'),
        ('hour', 'Hour'),
        ('day', 'Day'),
        ('week', 'Week'),
        ('month', 'Month'),
    ]

    name = models.CharField(max_length=100, unique=True)
    scope = models.CharField(max_length=20, choices=SCOPE_CHOICES)
    limit = models.PositiveIntegerField(help_text='Number of requests allowed')
    period = models.CharField(max_length=10, choices=PERIOD_CHOICES)
    period_count = models.PositiveIntegerField(
        default=1,
        help_text="Number of periods (e.g., 2 for '2 hours')"
    )
    endpoint_pattern = models.CharField(
        max_length=200,
        blank=True,
        help_text='Regex pattern for URL matching'
    )
    http_methods = models.CharField(
        max_length=50,
        blank=True,
        help_text='Comma-separated HTTP methods (GET,POST,etc)'
    )
    is_active = models.BooleanField(default=True)
    priority = models.IntegerField(
        default=0,
        help_text='Higher priority rules are checked first'
    )
    block_duration_minutes = models.PositiveIntegerField(
        default=0,
        help_text='Block duration after limit exceeded (0 = no blocking)'
    )

    def __str__(self) -> str:
        return f'{self.name}: {self.limit}/{self.period_count} {self.period}(s) - {self.scope}'

    def get_period_timedelta(self) -> timedelta:
        period_map = {
            'second': timedelta(seconds=self.period_count),
            'minute': timedelta(minutes=self.period_count),
            'hour': timedelta(hours=self.period_count),
            'day': timedelta(days=self.period_count),
            'week': timedelta(weeks=self.period_count),
            'month': timedelta(days=self.period_count * 30),
        }
        return period_map.get(self.period, timedelta(minutes=self.period_count))


class RateLimitAttempt(BaseModel):
    rule = models.ForeignKey(RateLimitRule, on_delete=models.CASCADE)
    key = models.CharField(max_length=255, db_index=True)
    endpoint = models.CharField(max_length=200, blank=True)
    method = models.CharField(max_length=10)
    count = models.PositiveIntegerField(default=1)
    window_start = models.DateTimeField(db_index=True)
    last_attempt = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['rule', 'key', 'endpoint', 'window_start']
        indexes = [
            models.Index(fields=['rule', 'key', 'window_start']),
            models.Index(fields=['window_start']),
        ]

    def __str__(self) -> str:
        return f'Attempt: {self.key} - {self.count} times for {self.rule.name}'


class RateLimitBlock(BaseModel):
    rule = models.ForeignKey(RateLimitRule, on_delete=models.CASCADE)
    key = models.CharField(max_length=255, db_index=True)
    blocked_until = models.DateTimeField(db_index=True)

    def __str__(self) -> str:
        return f'Block: {self.key} until {self.blocked_until} by {self.rule.name}'