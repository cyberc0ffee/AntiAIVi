import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .paths import DEFAULT_STATE_DIR


DEFAULT_DB = DEFAULT_STATE_DIR / "server" / "edr.sqlite"


class EdrStore:
    def __init__(self, db_path=DEFAULT_DB, jsonl_path=None):
        self.db_path = Path(db_path)
        self.jsonl_path = Path(jsonl_path) if jsonl_path else None
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if self.jsonl_path:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    def init(self):
        with closing(self.connect()) as db:
            with db:
                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      received_at TEXT NOT NULL,
                      agent_id TEXT NOT NULL,
                      event_type TEXT NOT NULL,
                      severity TEXT,
                      score INTEGER,
                      action TEXT,
                      payload_json TEXT NOT NULL
                    )
                    """
                )
                db.execute("CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS agent_heartbeats (
                      agent_id TEXT PRIMARY KEY,
                      last_seen TEXT NOT NULL,
                      payload_json TEXT NOT NULL
                    )
                    """
                )
                heartbeat_rows = db.execute(
                    """
                    SELECT agent_id, received_at, payload_json
                    FROM events
                    WHERE event_type = 'agent.heartbeat'
                    ORDER BY id ASC
                    """
                ).fetchall()
                if heartbeat_rows:
                    db.executemany(
                        """
                        INSERT INTO agent_heartbeats(agent_id, last_seen, payload_json)
                        VALUES (?, ?, ?)
                        ON CONFLICT(agent_id) DO UPDATE SET
                          last_seen = excluded.last_seen,
                          payload_json = excluded.payload_json
                        """,
                        heartbeat_rows,
                    )
                    db.execute("DELETE FROM events WHERE event_type = 'agent.heartbeat'")

    def connect(self):
        return sqlite3.connect(self.db_path)

    def insert_many(self, events, default_agent="unknown"):
        rows = []
        event_payloads = []
        heartbeats = []
        received_at = utc_now()
        for payload in events:
            if not isinstance(payload, dict):
                payload = {"type": "raw", "value": payload}
            agent_id = str(payload.get("agent_id") or default_agent or "unknown")
            event_type = str(payload.get("type") or payload.get("event_type") or "event")
            if event_type == "agent.heartbeat":
                heartbeats.append((agent_id, received_at, json.dumps(payload, ensure_ascii=False)))
                continue
            detection = payload.get("detection") if isinstance(payload.get("detection"), dict) else {}
            severity = payload.get("severity") or detection.get("severity")
            score = payload.get("score") if payload.get("score") is not None else detection.get("score")
            action = payload.get("action") or detection.get("action")
            rows.append(
                (
                    received_at,
                    agent_id,
                    event_type,
                    severity,
                    int(score) if score is not None else None,
                    action,
                    json.dumps(payload, ensure_ascii=False),
                )
            )
            event_payloads.append(payload)

        with closing(self.connect()) as db:
            with db:
                if rows:
                    db.executemany(
                        """
                        INSERT INTO events(received_at, agent_id, event_type, severity, score, action, payload_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        rows,
                    )
                if heartbeats:
                    db.executemany(
                        """
                        INSERT INTO agent_heartbeats(agent_id, last_seen, payload_json)
                        VALUES (?, ?, ?)
                        ON CONFLICT(agent_id) DO UPDATE SET
                          last_seen = excluded.last_seen,
                          payload_json = excluded.payload_json
                        """,
                        heartbeats,
                    )
        if self.jsonl_path:
            with self.jsonl_path.open("a", encoding="utf-8") as handle:
                for row, payload in zip(rows, event_payloads):
                    handle.write(json.dumps({"received_at": row[0], "payload": payload}, ensure_ascii=False) + "\n")
        return len(rows) + len(heartbeats)

    def query(self, limit=100, agent_id=None, event_type=None, min_score=None):
        limit = max(1, min(int(limit), 1000))
        clauses = []
        params = []
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if min_score is not None:
            clauses.append("score >= ?")
            params.append(int(min_score))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT id, received_at, agent_id, event_type, severity, score, action, payload_json "
            f"FROM events {where} ORDER BY id DESC LIMIT ?"
        )
        params.append(limit)
        with closing(self.connect()) as db:
            rows = db.execute(sql, params).fetchall()
        return [
            {
                "id": row[0],
                "received_at": row[1],
                "agent_id": row[2],
                "type": row[3],
                "severity": row[4],
                "score": row[5],
                "action": row[6],
                "payload": json.loads(row[7]),
            }
            for row in rows
        ]

    def count(self):
        with closing(self.connect()) as db:
            return int(db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def agents(self, green_seconds=180, yellow_seconds=1800):
        with closing(self.connect()) as db:
            event_rows = db.execute(
                """
                SELECT e.agent_id, COUNT(*) AS event_count, MAX(e.received_at) AS last_seen
                FROM events e
                GROUP BY e.agent_id
                ORDER BY last_seen DESC
                """
            ).fetchall()
            heartbeat_rows = db.execute(
                """
                SELECT agent_id, last_seen, payload_json
                FROM agent_heartbeats
                ORDER BY last_seen DESC
                """
            ).fetchall()
            latest_rows = db.execute(
                """
                SELECT e.agent_id, e.event_type, e.severity, e.score, e.action, e.received_at
                FROM events e
                JOIN (
                  SELECT agent_id, MAX(id) AS max_id
                  FROM events
                  GROUP BY agent_id
                ) latest ON latest.max_id = e.id
                """
            ).fetchall()
        latest = {
            row[0]: {
                "last_type": row[1],
                "last_severity": row[2],
                "last_score": row[3],
                "last_action": row[4],
                "last_event_at": row[5],
            }
            for row in latest_rows
        }
        event_summary = {
            row[0]: {
                "event_count": int(row[1]),
                "last_event_at": row[2],
            }
            for row in event_rows
        }
        heartbeat_summary = {
            row[0]: {
                "last_heartbeat_at": row[1],
                "last_heartbeat": json.loads(row[2]),
            }
            for row in heartbeat_rows
        }
        agents = []
        for agent_id in sorted(set(event_summary) | set(heartbeat_summary)):
            heartbeat = heartbeat_summary.get(agent_id, {})
            heartbeat_at = heartbeat.get("last_heartbeat_at")
            heartbeat_age = seconds_since(heartbeat_at) if heartbeat_at else None
            status = heartbeat_status(heartbeat_age, green_seconds=green_seconds, yellow_seconds=yellow_seconds)
            event_data = event_summary.get(agent_id, {"event_count": 0, "last_event_at": None})
            agents.append(
                {
                    "agent_id": agent_id,
                    "event_count": event_data["event_count"],
                    "last_seen": heartbeat_at or event_data["last_event_at"],
                    "last_heartbeat_at": heartbeat_at,
                    "last_heartbeat_age_seconds": heartbeat_age,
                    "last_heartbeat": heartbeat.get("last_heartbeat"),
                    "last_event_at": event_data["last_event_at"],
                    "status": status,
                    "active": status == "green",
                    **latest.get(agent_id, {}),
                }
            )
        return sorted(agents, key=lambda item: item["last_seen"] or "", reverse=True)


def run_server(host="127.0.0.1", port=8765, db_path=DEFAULT_DB, api_key=None, jsonl_path=None):
    store = EdrStore(db_path=db_path, jsonl_path=jsonl_path)
    server = create_http_server(host, port, store, api_key=api_key)
    print(f"AntiAiVi EDR server listening on http://{host}:{port}")
    print(f"SQLite storage: {store.db_path}")
    if api_key:
        print("API key authentication: enabled")
    else:
        print("API key authentication: disabled")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def create_http_server(host, port, store, api_key=None):
    class Handler(EdrRequestHandler):
        pass

    Handler.store = store
    Handler.api_key = api_key
    return ThreadingHTTPServer((host, int(port)), Handler)


class EdrRequestHandler(BaseHTTPRequestHandler):
    store = None
    api_key = None
    server_version = "AntiAiViEDR/0.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/dashboard"}:
            return self.html_response(200, dashboard_html(auth_enabled=bool(self.api_key)))
        if parsed.path == "/api/v1/health":
            agents = self.store.agents()
            return self.json_response(
                200,
                {
                    "ok": True,
                    "events": self.store.count(),
                    "agents": len(agents),
                    "active_agents": sum(1 for agent in agents if agent["active"]),
                    "time": utc_now(),
                },
            )
        if parsed.path == "/api/v1/agents":
            if not self.authorized():
                return self.json_response(401, {"error": "unauthorized"})
            query = parse_qs(parsed.query)
            green_seconds = int(first(query.get("green_seconds"), 180))
            yellow_seconds = int(first(query.get("yellow_seconds"), 1800))
            agents = self.store.agents(green_seconds=green_seconds, yellow_seconds=yellow_seconds)
            return self.json_response(
                200,
                {
                    "agents": agents,
                    "total": len(agents),
                    "green": sum(1 for agent in agents if agent["status"] == "green"),
                    "yellow": sum(1 for agent in agents if agent["status"] == "yellow"),
                    "red": sum(1 for agent in agents if agent["status"] == "red"),
                    "active": sum(1 for agent in agents if agent["active"]),
                    "green_seconds": green_seconds,
                    "yellow_seconds": yellow_seconds,
                },
            )
        if parsed.path == "/api/v1/events":
            if not self.authorized():
                return self.json_response(401, {"error": "unauthorized"})
            query = parse_qs(parsed.query)
            events = self.store.query(
                limit=int(first(query.get("limit"), 100)),
                agent_id=first(query.get("agent_id")),
                event_type=first(query.get("type")),
                min_score=first(query.get("min_score")),
            )
            agent_id = first(query.get("agent_id"))
            agent = None
            if agent_id:
                agent = next((item for item in self.store.agents() if item["agent_id"] == agent_id), None)
            return self.json_response(200, {"events": events, "agent": agent})
        return self.json_response(404, {"error": "not_found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/v1/events":
            return self.json_response(404, {"error": "not_found"})
        if not self.authorized():
            return self.json_response(401, {"error": "unauthorized"})

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as error:
            return self.json_response(400, {"error": f"invalid_json: {error}"})

        if isinstance(body, list):
            events = body
            default_agent = self.headers.get("X-Agent-Id", "unknown")
        elif isinstance(body, dict) and isinstance(body.get("events"), list):
            events = body["events"]
            default_agent = body.get("agent_id") or self.headers.get("X-Agent-Id", "unknown")
        elif isinstance(body, dict):
            events = [body]
            default_agent = body.get("agent_id") or self.headers.get("X-Agent-Id", "unknown")
        else:
            return self.json_response(400, {"error": "payload must be an object, list, or {events: []}"})

        inserted = self.store.insert_many(events, default_agent=default_agent)
        return self.json_response(202, {"ok": True, "inserted": inserted})

    def authorized(self):
        if not self.api_key:
            return True
        return self.headers.get("X-API-Key") == self.api_key

    def json_response(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def html_response(self, status, html):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def first(values, fallback=None):
    if not values:
        return fallback
    return values[0]


def seconds_since(iso_value):
    if not iso_value:
        return 999999999
    try:
        normalized = iso_value.replace("Z", "+00:00")
        then = datetime.fromisoformat(normalized)
        if then.tzinfo is None:
            then = then.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - then).total_seconds()
    except Exception:
        return 999999999


def heartbeat_status(age_seconds, green_seconds=180, yellow_seconds=1800):
    if age_seconds is None:
        return "red"
    if age_seconds <= green_seconds:
        return "green"
    if age_seconds <= yellow_seconds:
        return "yellow"
    return "red"


def dashboard_html(auth_enabled=False):
    auth_note = "API key richiesta" if auth_enabled else "API key non richiesta"
    return f"""<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AntiAiVi EDR Console</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f7fa;
      --panel: #ffffff;
      --line: #d8dee8;
      --text: #172033;
      --muted: #657084;
      --accent: #0f766e;
      --danger: #b42318;
      --warn: #b54708;
      --ok: #067647;
      --yellow: #d6a100;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", Arial, sans-serif;
      font-size: 14px;
    }}
    header {{
      height: 64px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }}
    h1 {{
      font-size: 18px;
      margin: 0;
      font-weight: 650;
    }}
    main {{
      display: grid;
      grid-template-columns: minmax(420px, 0.95fr) minmax(460px, 1.05fr);
      gap: 16px;
      padding: 16px;
      min-height: calc(100vh - 64px);
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      min-width: 0;
      overflow: hidden;
    }}
    .toolbar {{
      display: flex;
      gap: 8px;
      align-items: center;
      padding: 12px;
      border-bottom: 1px solid var(--line);
    }}
    input, button {{
      height: 34px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 0 10px;
      font: inherit;
      background: #fff;
    }}
    input {{ min-width: 210px; }}
    button {{
      cursor: pointer;
      color: #fff;
      background: var(--accent);
      border-color: var(--accent);
      font-weight: 600;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 8px;
      padding: 12px;
      border-bottom: 1px solid var(--line);
    }}
    .stat {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfcfe;
    }}
    .stat strong {{
      display: block;
      font-size: 22px;
      line-height: 1.1;
    }}
    .stat span {{ color: var(--muted); font-size: 12px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      padding: 9px 10px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      white-space: nowrap;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 650;
      background: #fbfcfe;
    }}
    tr {{ cursor: default; }}
    tr:hover, tr.selected {{ background: #eef8f6; }}
    .dot {{
      width: 9px;
      height: 9px;
      display: inline-block;
      border-radius: 50%;
      margin-right: 6px;
      background: var(--muted);
    }}
    .dot.green {{ background: var(--ok); }}
    .dot.yellow {{ background: var(--yellow); }}
    .dot.red {{ background: var(--danger); }}
    .hb-card {{
      border-bottom: 1px solid var(--line);
      padding: 12px;
      background: #fbfcfe;
    }}
    .hb-card h2 {{
      margin: 0 0 8px;
      font-size: 14px;
    }}
    .severity-critical, .severity-high {{ color: var(--danger); font-weight: 650; }}
    .severity-medium {{ color: var(--warn); font-weight: 650; }}
    .severity-low, .severity-info {{ color: var(--muted); }}
    .logs {{
      height: calc(100vh - 176px);
      overflow: auto;
    }}
    .log-row {{
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
    }}
    .log-head {{
      display: flex;
      justify-content: space-between;
      gap: 8px;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 6px;
    }}
    pre {{
      margin: 0;
      padding: 10px;
      background: #111827;
      color: #d1d5db;
      border-radius: 6px;
      overflow: auto;
      max-height: 280px;
      font-size: 12px;
    }}
    .empty {{
      padding: 24px;
      color: var(--muted);
    }}
    @media (max-width: 980px) {{
      main {{ grid-template-columns: 1fr; }}
      .logs {{ height: 520px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>AntiAiVi EDR Console</h1>
    <div>{auth_note}</div>
  </header>
  <main>
    <section>
      <div class="toolbar">
        <input id="apiKey" type="password" placeholder="API key">
        <button id="saveKey">Salva</button>
        <button id="refresh">Aggiorna</button>
      </div>
      <div class="stats">
        <div class="stat"><strong id="totalAgents">0</strong><span>Client totali</span></div>
        <div class="stat"><strong id="greenAgents">0</strong><span>Verdi &lt; 3 min</span></div>
        <div class="stat"><strong id="yellowAgents">0</strong><span>Gialli &lt; 30 min</span></div>
        <div class="stat"><strong id="redAgents">0</strong><span>Rossi</span></div>
        <div class="stat"><strong id="totalEvents">0</strong><span>Log eventi</span></div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Stato</th>
            <th>Client</th>
            <th>Ultimo heartbeat</th>
            <th>Ultimo evento</th>
            <th>Eventi</th>
          </tr>
        </thead>
        <tbody id="agents"></tbody>
      </table>
    </section>
    <section>
      <div class="toolbar">
        <strong id="logTitle">Log client</strong>
      </div>
      <div id="logs" class="logs">
        <div class="empty">Doppio click su un client per vedere i log.</div>
      </div>
    </section>
  </main>
  <script>
    const apiKeyInput = document.getElementById("apiKey");
    const agentsBody = document.getElementById("agents");
    const logs = document.getElementById("logs");
    const logTitle = document.getElementById("logTitle");
    let selectedAgent = null;

    apiKeyInput.value = localStorage.getItem("antiai_api_key") || "";
    document.getElementById("saveKey").addEventListener("click", () => {{
      localStorage.setItem("antiai_api_key", apiKeyInput.value);
      refresh();
    }});
    document.getElementById("refresh").addEventListener("click", refresh);

    function headers() {{
      const key = apiKeyInput.value.trim();
      return key ? {{ "X-API-Key": key }} : {{}};
    }}

    async function api(path) {{
      const response = await fetch(path, {{ headers: headers() }});
      if (!response.ok) throw new Error(`HTTP ${{response.status}}`);
      return response.json();
    }}

    async function refresh() {{
      try {{
        const [health, agentData] = await Promise.all([
          api("/api/v1/health"),
          api("/api/v1/agents")
        ]);
        document.getElementById("totalAgents").textContent = agentData.total;
        document.getElementById("greenAgents").textContent = agentData.green;
        document.getElementById("yellowAgents").textContent = agentData.yellow;
        document.getElementById("redAgents").textContent = agentData.red;
        document.getElementById("totalEvents").textContent = health.events;
        renderAgents(agentData.agents);
        if (selectedAgent) loadLogs(selectedAgent);
      }} catch (error) {{
        agentsBody.innerHTML = `<tr><td colspan="5">Errore: ${{escapeHtml(error.message)}}</td></tr>`;
      }}
    }}

    function renderAgents(agents) {{
      if (!agents.length) {{
        agentsBody.innerHTML = `<tr><td colspan="5">Nessun client ha ancora inviato log.</td></tr>`;
        return;
      }}
      agentsBody.innerHTML = agents.map(agent => `
        <tr data-agent="${{escapeHtml(agent.agent_id)}}" class="${{agent.agent_id === selectedAgent ? "selected" : ""}}">
          <td><span class="dot ${{escapeHtml(agent.status || "red")}}"></span>${{statusLabel(agent.status)}}</td>
          <td>${{escapeHtml(agent.agent_id)}}</td>
          <td>${{escapeHtml(formatDate(agent.last_heartbeat_at))}}<br>${{heartbeatAge(agent.last_heartbeat_age_seconds)}}</td>
          <td>${{escapeHtml(formatDate(agent.last_event_at))}}<br><span class="severity-${{escapeHtml(agent.last_severity || "info")}}">${{escapeHtml(agent.last_type || "")}} ${{agent.last_score ?? ""}} ${{escapeHtml(agent.last_action || "")}}</span></td>
          <td>${{agent.event_count}}</td>
        </tr>
      `).join("");
      for (const row of agentsBody.querySelectorAll("tr[data-agent]")) {{
        row.addEventListener("dblclick", () => {{
          selectedAgent = row.dataset.agent;
          for (const item of agentsBody.querySelectorAll("tr")) item.classList.remove("selected");
          row.classList.add("selected");
          loadLogs(selectedAgent);
        }});
      }}
    }}

    async function loadLogs(agentId) {{
      logTitle.textContent = `Log client: ${{agentId}}`;
      logs.innerHTML = `<div class="empty">Caricamento...</div>`;
      try {{
        const data = await api(`/api/v1/events?agent_id=${{encodeURIComponent(agentId)}}&limit=100`);
        if (!data.events.length) {{
          logs.innerHTML = renderHeartbeat(data.agent) + `<div class="empty">Nessun log evento per questo client.</div>`;
          return;
        }}
        logs.innerHTML = renderHeartbeat(data.agent) + data.events.map(event => `
          <div class="log-row">
            <div class="log-head">
              <span>#${{event.id}} ${{escapeHtml(event.type)}} <span class="severity-${{escapeHtml(event.severity || "info")}}">${{escapeHtml(event.severity || "info")}}</span></span>
              <span>${{escapeHtml(formatDate(event.received_at))}}</span>
            </div>
            <pre>${{escapeHtml(JSON.stringify(event.payload, null, 2))}}</pre>
          </div>
        `).join("");
      }} catch (error) {{
        logs.innerHTML = `<div class="empty">Errore: ${{escapeHtml(error.message)}}</div>`;
      }}
    }}

    function renderHeartbeat(agent) {{
      if (!agent || !agent.last_heartbeat) {{
        return `<div class="hb-card"><h2>Ultimo heartbeat</h2><div class="empty">Nessun heartbeat ricevuto.</div></div>`;
      }}
      return `
        <div class="hb-card">
          <h2>Ultimo heartbeat</h2>
          <div class="log-head">
            <span><span class="dot ${{escapeHtml(agent.status || "red")}}"></span>${{statusLabel(agent.status)}} ${{heartbeatAge(agent.last_heartbeat_age_seconds)}}</span>
            <span>${{escapeHtml(formatDate(agent.last_heartbeat_at))}}</span>
          </div>
          <pre>${{escapeHtml(JSON.stringify(agent.last_heartbeat, null, 2))}}</pre>
        </div>
      `;
    }}

    function statusLabel(status) {{
      if (status === "green") return "Verde";
      if (status === "yellow") return "Giallo";
      return "Rosso";
    }}

    function heartbeatAge(seconds) {{
      if (seconds === null || seconds === undefined) return "";
      if (seconds < 60) return `${{Math.round(seconds)}}s fa`;
      if (seconds < 3600) return `${{Math.round(seconds / 60)}}m fa`;
      return `${{Math.round(seconds / 3600)}}h fa`;
    }}

    function formatDate(value) {{
      if (!value) return "";
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
    }}

    function escapeHtml(value) {{
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }}

    refresh();
    setInterval(refresh, 10000);
  </script>
</body>
</html>"""
