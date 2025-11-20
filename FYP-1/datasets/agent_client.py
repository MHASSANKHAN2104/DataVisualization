# datasets/agent_client.py

import requests
from django.conf import settings

# URL where the other team will host their agent
AGENT_BASE_URL = getattr(settings, "AGENT_BASE_URL", "http://localhost:9000")


def call_cleaning_agent(ingest):
    """
    TEMP STUB for FYP:

    Later this will call the external cleaning/profiling agent.
    For now it just returns fake profile data so your backend works.
    """

    # Example of what you *might* send later:
    # with ingest.file.open("rb") as f:
    #     files = {"file": (ingest.original_filename, f)}
    #     resp = requests.post(f"{AGENT_BASE_URL}/clean", files=files)
    #     resp.raise_for_status()
    #     return resp.json()

    # ---- Dummy data for now ----
    return {
        "row_count": 0,
        "column_count": 0,
        "schema_hash": "dummy_hash",
        "profile_json": {
            "summary": "stub profile – external agent not connected yet",
            "columns": {},
        },
        "lineage": {},
    }
