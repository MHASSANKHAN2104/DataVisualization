from django.db import models
from django.conf import settings
from django.utils import timezone
import os
import uuid


def normalized_filename(original_name: str) -> str:
    """
    Normalize filename: lowercase, no spaces, simple ASCII-friendly.
    """
    name, ext = os.path.splitext(original_name)
    name = name.strip().replace(" ", "_")
    name = "".join(c for c in name if c.isalnum() or c in ("_", "-", "."))
    return f"{name.lower()}{ext.lower()}"


def upload_to_datasource(instance, filename):
    """
    Path inside MEDIA_ROOT where files will be stored.
    e.g. datasets/<datasource_id>/<uuid>__normalized.csv
    """
    norm_name = normalized_filename(filename)
    uid = uuid.uuid4().hex[:8]
    return f"datasets/{instance.data_source_id}/{uid}__{norm_name}"


class DataSource(models.Model):
    """
    Logical dataset. For now, 1 upload = 1 datasource, which we can
    extend later for multiple versions.
    """
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="data_sources",
    )
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} (id={self.id})"


class FileIngest(models.Model):
    """
    One uploaded file (CSV/XLSX) with metadata and tracking.
    """
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("stored", "Stored"),
        ("failed", "Failed"),
    ]

    data_source = models.ForeignKey(
        DataSource,
        on_delete=models.CASCADE,
        related_name="file_ingests",
    )
    uploader = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="file_uploads",
    )

    file = models.FileField(upload_to=upload_to_datasource)
    original_filename = models.CharField(max_length=255)
    normalized_filename = models.CharField(max_length=255)
    mime_type = models.CharField(max_length=100)
    size_bytes = models.BigIntegerField()
    checksum_sha256 = models.CharField(max_length=64)

    delimiter = models.CharField(max_length=10, default=",")
    header_row = models.BooleanField(default=True)
    date_format = models.CharField(max_length=50, blank=True, default="")
    encoding = models.CharField(max_length=50, blank=True, default="utf-8")

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending"
    )
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    storage_key = models.CharField(max_length=255, blank=True)
    storage_backend = models.CharField(
        max_length=50, blank=True, default="local"
    )

    def mark_stored(self):
        self.status = "stored"
        self.completed_at = timezone.now()
        self.save(update_fields=["status", "completed_at"])

    def mark_failed(self, message: str):
        self.status = "failed"
        self.error_message = message
        self.completed_at = timezone.now()
        self.save(update_fields=["status", "error_message", "completed_at"])

    def __str__(self):
        return f"FileIngest id={self.id}, status={self.status}"
