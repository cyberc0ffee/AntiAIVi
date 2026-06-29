import json
import os
import platform
import socket
import urllib.error
import urllib.request
from urllib.parse import urljoin

from .severity import now_iso


class LogShipper:
    def __init__(self, server_url=None, agent_id=None, api_key=None, timeout=5.0):
        self.server_url = (server_url or os.environ.get("ANTIAI_SERVER_URL") or "").rstrip("/")
        self.agent_id = agent_id or os.environ.get("ANTIAI_AGENT_ID") or socket.gethostname()
        self.api_key = api_key or os.environ.get("ANTIAI_API_KEY")
        self.timeout = timeout

    @property
    def enabled(self):
        return bool(self.server_url)

    def send(self, event):
        if not self.enabled:
            return {"sent": False, "reason": "disabled"}
        payload = self.envelope(event)
        return self.post([payload])

    def send_many(self, events):
        if not self.enabled:
            return {"sent": False, "reason": "disabled"}
        return self.post([self.envelope(event) for event in events])

    def envelope(self, event):
        if not isinstance(event, dict):
            event = {"type": "raw", "value": event}
        return {
            "type": event.get("type", "event"),
            "agent_id": event.get("agent_id", self.agent_id),
            "sent_at": now_iso(),
            "host": {
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
            },
            **event,
        }

    def post(self, events):
        url = urljoin(f"{self.server_url}/", "api/v1/events")
        body = json.dumps({"agent_id": self.agent_id, "events": events}, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Agent-Id": self.agent_id,
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                parsed = json.loads(raw) if raw else {}
                return {"sent": True, "status": response.status, "response": parsed}
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            return {"sent": False, "status": error.code, "error": detail}
        except Exception as error:
            return {"sent": False, "error": str(error)}
