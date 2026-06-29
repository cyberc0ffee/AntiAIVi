import json
import shutil
import time
from pathlib import Path

from .paths import DEFAULT_STATE_DIR


def apply_response(detection, file_path=None, quarantine=False, state_dir=DEFAULT_STATE_DIR):
    actions = []
    action = detection.get("action")
    if action == "monitor":
        actions.append({"type": "monitor", "status": "planned"})
    elif action == "suspend":
        actions.append({"type": "suspend_process", "status": "planned", "note": "OS enforcement is not enabled in the Python prototype."})
    elif action == "kill_quarantine":
        actions.append({"type": "terminate_process", "status": "planned", "note": "OS enforcement is not enabled in the Python prototype."})
        if quarantine and file_path:
            metadata = quarantine_file(file_path, detection, state_dir)
            actions.append({"type": "quarantine_file", "status": "completed", "metadata": metadata})
        elif file_path:
            actions.append({"type": "quarantine_file", "status": "skipped", "note": "Pass --quarantine to move files into quarantine."})
    return actions


def quarantine_file(file_path, detection, state_dir=DEFAULT_STATE_DIR):
    source = Path(file_path)
    qdir = Path(state_dir) / "quarantine_py"
    qdir.mkdir(parents=True, exist_ok=True)
    qid = f"{int(time.time())}-{source.name}"
    dest = qdir / qid
    shutil.move(str(source), str(dest))
    metadata = {
        "id": qid,
        "original_path": str(source.resolve()),
        "quarantine_path": str(dest.resolve()),
        "date": int(time.time()),
        "detection_score": detection.get("score"),
        "detection_action": detection.get("action"),
        "encrypted": False,
    }
    (qdir / f"{qid}.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata
