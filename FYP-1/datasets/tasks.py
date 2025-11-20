# datasets/tasks.py

import logging

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from .models import FileIngest, DatasetVersion
from .agent_client import call_cleaning_agent

logger = logging.getLogger("data_profiling")


def start_profiling_and_cleaning_job(ingest_id: int, user_id: int) -> None:
    """
    Phase 4 background job (sync stub):

    1. Load FileIngest.
    2. Call external cleaning/profiling agent (stub for now).
    3. Create DatasetVersion with profile + lineage.

    In the future you can run this as a Celery task.
    """

    try:
        ingest = FileIngest.objects.get(id=ingest_id)
    except FileIngest.DoesNotExist:
        logger.error("FileIngest id=%s not found", ingest_id)
        return

    logger.info("Starting profiling/cleaning for ingest id=%s", ingest_id)

    # Talk to the (stub) agent – right now returns dummy profile data
    result = call_cleaning_agent(ingest)

    row_count = result.get("row_count", 0)
    column_count = result.get("column_count", 0)
    schema_hash = result.get("schema_hash", "")
    profile_json = result.get("profile_json", {})
    lineage = result.get("lineage", {}) or {}

    # Enrich lineage with upload info
    lineage.setdefault("upload_id", str(ingest.id))
    lineage.setdefault("checksum", ingest.checksum_sha256)
    lineage.setdefault("created_at", timezone.now().isoformat())

    # Next version number for this dataset
    max_no = (
        DatasetVersion.objects.filter(dataset=ingest.data_source)
        .aggregate(Max("version_no"))["version_no__max"]
        or 0
    )
    version_no = max_no + 1

    # Create DatasetVersion atomically
    with transaction.atomic():
        DatasetVersion.objects.create(
            dataset=ingest.data_source,
            file_ingest=ingest,
            version_no=version_no,
            row_count=row_count,
            column_count=column_count,
            schema_hash=schema_hash,
            profile_json=profile_json,
            lineage_json=lineage,
            created_by_id=user_id,
        )

    logger.info(
        "Finished profiling/cleaning: ingest id=%s -> dataset=%s version=%s",
        ingest_id,
        ingest.data_source_id,
        version_no,
    )
