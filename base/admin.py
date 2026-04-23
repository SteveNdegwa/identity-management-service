from django.contrib import admin
from .models import Country, Realm


@admin.register(Country)
class CountryAdmin(admin.ModelAdmin):
    list_display = ("code", "code3", "name", "phone_code", "is_active")
    list_filter = ("is_active",)
    search_fields = ("code", "code3", "name")
    ordering = ("name",)

    fieldsets = (
        ("Country Details", {
            "fields": ("code", "code3", "name", "phone_code", "is_active")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at")


@admin.register(Realm)
class RealmAdmin(admin.ModelAdmin):
    list_display = ("name",)
    search_fields = ("name",)
    ordering = ("name",)

    fieldsets = (
        ("Realm Details", {
            "fields": ("name", "description")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at")