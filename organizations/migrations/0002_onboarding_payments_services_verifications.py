# Generated manually for onboarding payments, services, and verification workflow.

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
        ('organizations', '0001_initial'),
        ('systems', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='DocumentRequest',
        ),
        migrations.AlterField(
            model_name='organizationonboarding',
            name='status',
            field=models.CharField(
                choices=[
                    ('draft', 'Draft'),
                    ('submitted', 'Submitted — Awaiting Review'),
                    ('verified', 'Verified'),
                    ('approved', 'Approved'),
                    ('rejected', 'Rejected'),
                    ('onboarded', 'Onboarded'),
                ],
                db_index=True,
                default='draft',
                max_length=30,
            ),
        ),
        migrations.AlterField(
            model_name='onboardingactivity',
            name='activity_type',
            field=models.CharField(
                choices=[
                    ('created', 'Application created'),
                    ('updated', 'Application updated'),
                    ('submitted', 'Application submitted'),
                    ('document_uploaded', 'Document uploaded'),
                    ('document_reviewed', 'Document reviewed'),
                    ('note_added', 'Note added'),
                    ('assigned', 'Assigned to reviewer'),
                    ('approved', 'Application approved'),
                    ('rejected', 'Application rejected'),
                    ('services_selected', 'Services selected'),
                    ('payment_recorded', 'Payment recorded'),
                    ('verification_triggered', 'Verification triggered'),
                    ('verification_completed', 'Verification completed'),
                    ('onboarded', 'Organisation onboarded'),
                ],
                db_index=True,
                max_length=40,
            ),
        ),
        migrations.CreateModel(
            name='OnboardingServiceProduct',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('code', models.SlugField(max_length=80)),
                ('name', models.CharField(max_length=160)),
                ('description', models.TextField(blank=True)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=12)),
                ('tax_amount', models.DecimalField(decimal_places=2, default=0, max_digits=12)),
                ('currency', models.CharField(default='KES', max_length=3)),
                ('is_active', models.BooleanField(default=True)),
                ('sort_order', models.PositiveIntegerField(default=0)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('system', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='onboarding_service_products', to='systems.system')),
            ],
            options={
                'db_table': 'organizations_onboarding_service_product',
                'ordering': ['sort_order', 'name'],
                'unique_together': {('system', 'code')},
            },
        ),
        migrations.CreateModel(
            name='OnboardingVerificationCheck',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('code', models.SlugField(max_length=80)),
                ('name', models.CharField(max_length=160)),
                ('description', models.TextField(blank=True)),
                ('integration_code', models.CharField(blank=True, max_length=120)),
                ('trigger_mode', models.CharField(choices=[('auto_after_payment', 'Automatic after payment'), ('manual', 'Manual')], db_index=True, default='auto_after_payment', max_length=30)),
                ('is_active', models.BooleanField(default=True)),
                ('required_for_onboarding', models.BooleanField(default=True)),
                ('sort_order', models.PositiveIntegerField(default=0)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('system', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='onboarding_verification_checks', to='systems.system')),
            ],
            options={
                'db_table': 'organizations_onboarding_verification_check',
                'ordering': ['sort_order', 'name'],
                'unique_together': {('system', 'code')},
            },
        ),
        migrations.CreateModel(
            name='OnboardingPayment',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('success', 'Success'), ('failed', 'Failed'), ('cancelled', 'Cancelled')], db_index=True, default='pending', max_length=20)),
                ('method', models.CharField(blank=True, max_length=60)),
                ('currency', models.CharField(default='KES', max_length=3)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=12)),
                ('tax_amount', models.DecimalField(decimal_places=2, default=0, max_digits=12)),
                ('total_amount', models.DecimalField(decimal_places=2, max_digits=12)),
                ('external_reference', models.CharField(blank=True, db_index=True, max_length=120)),
                ('paid_at', models.DateTimeField(blank=True, null=True)),
                ('service_snapshot', models.JSONField(blank=True, default=list)),
                ('provider_payload', models.JSONField(blank=True, default=dict)),
                ('onboarding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='payments', to='organizations.organizationonboarding')),
                ('recorded_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='recorded_onboarding_payments', to='accounts.systemuser')),
            ],
            options={
                'db_table': 'organizations_onboarding_payment',
            },
        ),
        migrations.CreateModel(
            name='OnboardingServiceSelection',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('onboarding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='service_selections', to='organizations.organizationonboarding')),
                ('selected_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='selected_onboarding_services', to='accounts.systemuser')),
                ('service', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='onboarding_selections', to='organizations.onboardingserviceproduct')),
            ],
            options={
                'db_table': 'organizations_onboarding_service_selection',
                'unique_together': {('onboarding', 'service')},
            },
        ),
        migrations.CreateModel(
            name='OnboardingVerificationRun',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('triggered', 'Triggered'), ('success', 'Success'), ('failed', 'Failed'), ('skipped', 'Skipped')], db_index=True, default='pending', max_length=20)),
                ('trigger_mode', models.CharField(choices=[('auto_after_payment', 'Automatic after payment'), ('manual', 'Manual')], max_length=30)),
                ('external_reference', models.CharField(blank=True, db_index=True, max_length=120)),
                ('request_payload', models.JSONField(blank=True, default=dict)),
                ('response_payload', models.JSONField(blank=True, default=dict)),
                ('result_summary', models.TextField(blank=True)),
                ('error_message', models.TextField(blank=True)),
                ('triggered_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('verification_check', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='runs', to='organizations.onboardingverificationcheck')),
                ('onboarding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='verification_runs', to='organizations.organizationonboarding')),
                ('triggered_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='triggered_onboarding_verifications', to='accounts.systemuser')),
            ],
            options={
                'db_table': 'organizations_onboarding_verification_run',
            },
        ),
        migrations.AddIndex(
            model_name='onboardingpayment',
            index=models.Index(fields=['onboarding', 'status'], name='organizatio_onboard_9f4220_idx'),
        ),
        migrations.AddIndex(
            model_name='onboardingverificationrun',
            index=models.Index(fields=['onboarding', 'status'], name='organizatio_onboard_e7c73a_idx'),
        ),
        migrations.AddIndex(
            model_name='onboardingverificationrun',
            index=models.Index(fields=['onboarding', 'verification_check'], name='organizatio_onboard_1e68c5_idx'),
        ),
    ]
