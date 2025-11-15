import hashlib
import mimetypes

from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status, permissions

from .models import DataSource, FileIngest
from .serializers import FileUploadSerializer, FileIngestMetadataSerializer


# Optional: only certain roles can upload, but for now just IsAuthenticated
class IsUploaderOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj: FileIngest):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.role == "Admin":
            return True
        return obj.uploader_id == user.id


class DatasetUploadView(APIView):
    """
    POST /datasets/upload
    Accepts: multipart/form-data
    Fields:
      - file (required)
      - delimiter (optional)
      - header_row (optional)
      - date_format (optional)
      - encoding (optional)
      - name (optional dataset name)
    Returns:
      { "upload_id": <id> }
    """
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

        file_obj = serializer.validated_data["file"]
        delimiter = serializer.validated_data.get("delimiter", ",")
        header_row = serializer.validated_data.get("header_row", True)
        date_format = serializer.validated_data.get("date_format", "")
        encoding = serializer.validated_data.get("encoding", "utf-8")
        ds_name = serializer.validated_data.get("name") or file_obj.name

        # Create DataSource (1 per upload for now)
        data_source = DataSource.objects.create(
            name=ds_name,
            owner=request.user,
            description="Uploaded dataset",
        )

        # Compute checksum (SHA-256) by streaming
        sha256 = hashlib.sha256()
        for chunk in file_obj.chunks():
            sha256.update(chunk)
        checksum = sha256.hexdigest()

        # Reset file pointer (so FileField can save it)
        file_obj.seek(0)

        mime_type, _ = mimetypes.guess_type(file_obj.name)
        if not mime_type:
            mime_type = "application/octet-stream"

        # Create FileIngest entry
        ingest = FileIngest(
            data_source=data_source,
            uploader=request.user,
            file=file_obj,
            original_filename=file_obj.name,
            normalized_filename=file_obj.name,  # normalized in path already
            mime_type=mime_type,
            size_bytes=file_obj.size,
            checksum_sha256=checksum,
            delimiter=delimiter,
            header_row=header_row,
            date_format=date_format,
            encoding=encoding,
            status="pending",
            storage_backend="local",
        )

        # Saving will store the file to MEDIA_ROOT using upload_to_datasource
        ingest.save()

        # Mark as stored (in real life you'd run parsing/validation first)
        ingest.mark_stored()
        ingest.storage_key = ingest.file.name  # path relative to MEDIA_ROOT
        ingest.save(update_fields=["storage_key"])

        return Response({"upload_id": ingest.id},
                        status=status.HTTP_201_CREATED)


class UploadMetadataView(APIView):
    """
    GET /uploads/<id>
    Returns metadata about the upload.
    Admin or uploader can view.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, id):
        ingest = get_object_or_404(FileIngest, pk=id)

        # Permission: only uploader or Admin
        perm = IsUploaderOrAdmin()
        if not perm.has_object_permission(request, self, ingest):
            return Response({"detail": "Forbidden."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = FileIngestMetadataSerializer(ingest)
        return Response(serializer.data, status=status.HTTP_200_OK)
