from django.urls import path
from .views import DatasetUploadView, UploadMetadataView

urlpatterns = [
    path("datasets/upload", DatasetUploadView.as_view(), name="datasets-upload"),
    path("uploads/<int:id>", UploadMetadataView.as_view(), name="upload-metadata"),
]
