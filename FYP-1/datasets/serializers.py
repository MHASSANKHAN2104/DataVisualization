from rest_framework import serializers
from .models import DataSource, FileIngest


class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField()
    delimiter = serializers.CharField(max_length=10, default=",", required=False)
    header_row = serializers.BooleanField(default=True, required=False)
    date_format = serializers.CharField(
       max_length=50, required=False, allow_blank=True
    )
    encoding = serializers.CharField(
        max_length=50, required=False, allow_blank=True, default="utf-8"
    )
    name = serializers.CharField(
        max_length=255, required=False, allow_blank=True
    )  # optional dataset name

    def validate(self, data):
        upload_file = data["file"]

        # Size limit (50MB)
        max_size = 50 * 1024 * 1024  # 50 MB
        if upload_file.size > max_size:
            raise serializers.ValidationError(
                f"File too large. Max size is 50MB."
            )

        # Basic type check: allow csv & xlsx
        # We'll check extension + MIME as a simple first step
        filename = upload_file.name.lower()
        if not (filename.endswith(".csv") or filename.endswith(".xlsx")):
            raise serializers.ValidationError(
                "Invalid file type. Only CSV and XLSX are allowed."
            )

        return data


class FileIngestMetadataSerializer(serializers.ModelSerializer):
    data_source = serializers.StringRelatedField()
    uploader = serializers.StringRelatedField()

    class Meta:
        model = FileIngest
        fields = [
            "id",
            "data_source",
            "uploader",
            "original_filename",
            "normalized_filename",
            "mime_type",
            "size_bytes",
            "checksum_sha256",
            "delimiter",
            "header_row",
            "date_format",
            "encoding",
            "status",
            "error_message",
            "created_at",
            "completed_at",
            "storage_key",
            "storage_backend",
        ]
