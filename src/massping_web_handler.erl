%%%-------------------------------------------------------------------
%%% @doc MassPing Web UI Handler
%%% Serves the dashboard HTML/JS
%%% @end
%%%-------------------------------------------------------------------
-module(massping_web_handler).

-export([init/2]).

%%====================================================================
%% Cowboy Handler
%%====================================================================

init(Req0, State) ->
    Path = cowboy_req:path(Req0),
    Req = handle_path(Path, Req0),
    {ok, Req, State}.

handle_path(<<"/">>, Req) ->
    serve_dashboard(Req);
handle_path(<<"/dashboard">>, Req) ->
    serve_dashboard(Req);
handle_path(<<"/metrics">>, Req) ->
    %% Prometheus metrics endpoint
    Metrics = massping_metrics:get_metrics(),
    cowboy_req:reply(200, #{
        <<"content-type">> => <<"text/plain; charset=utf-8">>
    }, Metrics, Req);
handle_path(<<"/health">>, Req) ->
    cowboy_req:reply(200, #{
        <<"content-type">> => <<"application/json">>
    }, <<"{\"status\":\"ok\"}">>, Req);
handle_path(_, Req) ->
    cowboy_req:reply(404, #{}, <<"Not Found">>, Req).

serve_dashboard(Req) ->
    Html = dashboard_html(),
    cowboy_req:reply(200, #{
        <<"content-type">> => <<"text/html; charset=utf-8">>
    }, Html, Req).

%%====================================================================
%% Dashboard HTML (embedded for simplicity)
%%====================================================================

dashboard_html() ->
    <<"<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>MassPing Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            min-height: 100vh;
        }
        .header {
            background: #16213e;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #0f3460;
        }
        .header h1 {
            color: #e94560;
            font-size: 1.5rem;
        }
        .header .status {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #4caf50;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .card {
            background: #16213e;
            border-radius: 8px;
            padding: 1.5rem;
            border: 1px solid #0f3460;
        }
        .card h2 {
            color: #e94560;
            font-size: 1rem;
            margin-bottom: 1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid #0f3460;
        }
        .metric:last-child { border-bottom: none; }
        .metric-value {
            font-weight: bold;
            color: #4caf50;
        }
        .btn {
            background: #e94560;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
            transition: background 0.3s;
        }
        .btn:hover { background: #c73e54; }
        .btn:disabled { background: #666; cursor: not-allowed; }
        .btn-secondary {
            background: #0f3460;
        }
        .btn-secondary:hover { background: #1a4a7a; }
        input, select, textarea {
            background: #1a1a2e;
            border: 1px solid #0f3460;
            color: #eee;
            padding: 0.75rem;
            border-radius: 4px;
            width: 100%;
            margin-bottom: 1rem;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #e94560;
        }
        .scan-form {
            display: grid;
            gap: 1rem;
        }
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #0f3460;
        }
        th {
            color: #e94560;
            text-transform: uppercase;
            font-size: 0.8rem;
        }
        .status-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            text-transform: uppercase;
        }
        .status-running { background: #2196f3; }
        .status-completed { background: #4caf50; }
        .status-stopped { background: #ff9800; }
        .status-failed { background: #f44336; }
        .nodes-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .node-card {
            background: #1a1a2e;
            padding: 1rem;
            border-radius: 4px;
            text-align: center;
        }
        .node-card.online { border-left: 3px solid #4caf50; }
        .node-card.offline { border-left: 3px solid #f44336; }
        .progress-bar {
            background: #0f3460;
            border-radius: 4px;
            height: 8px;
            overflow: hidden;
        }
        .progress-fill {
            background: #4caf50;
            height: 100%;
            transition: width 0.3s;
        }
        .tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid #0f3460;
        }
        .tab {
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
        }
        .tab:hover { color: #e94560; }
        .tab.active {
            color: #e94560;
            border-bottom-color: #e94560;
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .log-output {
            background: #0a0a15;
            padding: 1rem;
            border-radius: 4px;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            max-height: 300px;
            overflow-y: auto;
        }
        .log-line { margin-bottom: 0.25rem; }
        .log-time { color: #666; }
        .log-info { color: #4caf50; }
        .log-warn { color: #ff9800; }
        .log-error { color: #f44336; }
    </style>
</head>
<body>
    <header class=\"header\">
        <h1>🎯 MassPing Dashboard</h1>
        <div class=\"status\">
            <div class=\"status-dot\"></div>
            <span id=\"node-name\">Loading...</span>
        </div>
    </header>

    <div class=\"container\">
        <!-- Stats Cards -->
        <div class=\"grid\">
            <div class=\"card\">
                <h2>📊 Statistics</h2>
                <div class=\"metric\">
                    <span>Targets Scanned</span>
                    <span class=\"metric-value\" id=\"stat-scanned\">0</span>
                </div>
                <div class=\"metric\">
                    <span>Open Ports</span>
                    <span class=\"metric-value\" id=\"stat-open\">0</span>
                </div>
                <div class=\"metric\">
                    <span>Scan Rate</span>
                    <span class=\"metric-value\" id=\"stat-rate\">0/s</span>
                </div>
                <div class=\"metric\">
                    <span>Active Scans</span>
                    <span class=\"metric-value\" id=\"stat-active\">0</span>
                </div>
            </div>

            <div class=\"card\">
                <h2>🖥️ Cluster Nodes</h2>
                <div class=\"nodes-grid\" id=\"nodes-list\">
                    <div class=\"node-card online\">
                        <div>🟢 Local Node</div>
                        <small id=\"local-node\">Loading...</small>
                    </div>
                </div>
                <button class=\"btn btn-secondary\" style=\"margin-top: 1rem;\" onclick=\"showAddNode()\">
                    + Add Node
                </button>
            </div>

            <div class=\"card\">
                <h2>💾 System</h2>
                <div class=\"metric\">
                    <span>Memory</span>
                    <span class=\"metric-value\" id=\"sys-memory\">0 MB</span>
                </div>
                <div class=\"metric\">
                    <span>Processes</span>
                    <span class=\"metric-value\" id=\"sys-procs\">0</span>
                </div>
                <div class=\"metric\">
                    <span>Uptime</span>
                    <span class=\"metric-value\" id=\"sys-uptime\">0s</span>
                </div>
            </div>
        </div>

        <!-- Tabs -->
        <div class=\"tabs\">
            <div class=\"tab active\" onclick=\"switchTab('scans', this)\">Active Scans</div>
            <div class=\"tab\" onclick=\"switchTab('new', this)\">New Scan</div>
            <div class=\"tab\" onclick=\"switchTab('sessions', this)\">Saved Sessions</div>
            <div class=\"tab\" onclick=\"switchTab('results', this)\">Results</div>
            <div class=\"tab\" onclick=\"switchTab('cluster', this)\">Cluster</div>
        </div>

        <!-- Active Scans Tab -->
        <div id=\"tab-scans\" class=\"tab-content active\">
            <div class=\"card\">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Target</th>
                            <th>Ports</th>
                            <th>Progress</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id=\"scans-table\">
                        <tr>
                            <td colspan=\"6\" style=\"text-align: center; color: #666;\">
                                No active scans
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- New Scan Tab -->
        <div id=\"tab-new\" class=\"tab-content\">
            <div class=\"card\">
                <h2>🚀 Start New Scan</h2>
                <form class=\"scan-form\" onsubmit=\"startScan(event)\">
                    <div>
                        <label>Target CIDRs (one per line)</label>
                        <textarea id=\"cidrs\" rows=\"3\" placeholder=\"192.168.1.0/24&#10;10.0.0.0/16\"></textarea>
                    </div>
                    <div class=\"form-row\">
                        <div>
                            <label>Ports</label>
                            <input type=\"text\" id=\"ports\" placeholder=\"80,443,22,3389\" value=\"80,443\">
                        </div>
                        <div>
                            <label>Mode</label>
                            <select id=\"mode\">
                                <option value=\"normal\">Normal</option>
                                <option value=\"aggressive\">Aggressive (Fast)</option>
                                <option value=\"ultra\">Ultra (Faster)</option>
                                <option value=\"turbo\">Turbo (LAN only)</option>
                                <option value=\"stealth\">Stealth (Slow)</option>
                            </select>
                        </div>
                    </div>
                    <div class=\"form-row\">
                        <div>
                            <label>Concurrency</label>
                            <input type=\"number\" id=\"concurrency\" value=\"5000\">
                        </div>
                        <div>
                            <label>Timeout (ms)</label>
                            <input type=\"number\" id=\"timeout\" value=\"1000\">
                        </div>
                    </div>
                    <div class=\"form-row\">
                        <div>
                            <label>
                                <input type=\"checkbox\" id=\"syn-scan\"> Use SYN Scan (requires root)
                            </label>
                        </div>
                        <div>
                            <label>
                                <input type=\"checkbox\" id=\"grab-banner\"> Grab Banners
                            </label>
                        </div>
                    </div>
                    <button type=\"submit\" class=\"btn\">🎯 Start Scan</button>
                </form>
            </div>
        </div>

        <!-- Saved Sessions Tab -->
        <div id=\"tab-sessions\" class=\"tab-content\">
            <div class=\"card\">
                <table>
                    <thead>
                        <tr>
                            <th>Session ID</th>
                            <th>Last Updated</th>
                            <th>Progress</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id=\"sessions-table\">
                        <tr>
                            <td colspan=\"4\" style=\"text-align: center; color: #666;\">
                                No saved sessions
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Results Tab -->
        <div id=\"tab-results\" class=\"tab-content\">
            <div class=\"card\">
                <h2>📋 Scan Results</h2>
                <div class=\"log-output\" id=\"results-output\">
                    Select a scan to view results...
                </div>
            </div>
        </div>

        <!-- Cluster Tab -->
        <div id=\"tab-cluster\" class=\"tab-content\">
            <div class=\"card\">
                <h2>🖥️ Cluster Management</h2>
                <p style=\"color: #aaa; margin-bottom: 1rem;\">
                    Manage distributed scanning cluster nodes. Connect multiple Erlang nodes to scale scanning capacity.
                </p>
                <div class=\"nodes-grid\" id=\"cluster-nodes-list\">
                    <!-- Nodes will be loaded here -->
                </div>
                <div style=\"margin-top: 1rem; display: flex; gap: 1rem;\">
                    <button class=\"btn btn-primary\" onclick=\"showAddNode()\">+ Add Node</button>
                    <button class=\"btn btn-secondary\" onclick=\"fetchCluster()\">Refresh</button>
                </div>
            </div>
            <div class=\"card\">
                <h2>📖 How to Connect Nodes</h2>
                <div class=\"log-output\" style=\"font-size: 0.85rem;\">
1. Start MassPing on another machine with same cookie:
   ./massping web --port 8080 --cookie massping_secret

2. From that machine, connect to this cluster:
   erl -name node2@hostname -setcookie massping_secret -eval \"net_adm:ping('massping@thishost').\"

3. Or add via this UI using format: node@hostname
                </div>
            </div>
        </div>
    </div>

    <script>
        // API base URL
        const API = '/api';
        
        // Tab switching - tabId maps to tab names: scans, new, sessions, results, cluster
        function switchTab(tabId, clickedTab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            const tabContent = document.querySelector(`.tab-content#tab-${tabId}`);
            if (tabContent) tabContent.classList.add('active');
            if (clickedTab) {
                clickedTab.classList.add('active');
            } else {
                // Find tab by data attribute or index
                const tabNames = ['scans', 'new', 'sessions', 'results', 'cluster'];
                const tabIndex = tabNames.indexOf(tabId);
                const tabs = document.querySelectorAll('.tab');
                if (tabIndex >= 0 && tabs[tabIndex]) {
                    tabs[tabIndex].classList.add('active');
                }
            }
        }

        // Fetch status
        async function fetchStatus() {
            try {
                const res = await fetch(`${API}/status`);
                const data = await res.json();
                document.getElementById('node-name').textContent = data.node;
                document.getElementById('local-node').textContent = data.node;
                document.getElementById('sys-memory').textContent = 
                    Math.round(data.memory / 1024 / 1024) + ' MB';
                document.getElementById('sys-procs').textContent = data.process_count;
                document.getElementById('sys-uptime').textContent = 
                    Math.round(data.uptime / 1000) + 's';
            } catch (e) {
                console.error('Failed to fetch status:', e);
            }
        }

        // Fetch scans
        async function fetchScans() {
            try {
                const res = await fetch(`${API}/scans`);
                const data = await res.json();
                updateScansTable(data.scans || []);
                document.getElementById('stat-active').textContent = 
                    (data.scans || []).filter(s => s.status === 'running').length;
            } catch (e) {
                console.error('Failed to fetch scans:', e);
            }
        }

        // Update scans table
        function updateScansTable(scans) {
            const tbody = document.getElementById('scans-table');
            if (scans.length === 0) {
                tbody.innerHTML = `<tr>
                    <td colspan=\"6\" style=\"text-align: center; color: #666;\">
                        No active scans
                    </td>
                </tr>`;
                return;
            }
            tbody.innerHTML = scans.map(s => `
                <tr>
                    <td><code>${s.id.substring(0, 8)}</code></td>
                    <td>${(s.cidrs || []).join(', ')}</td>
                    <td>${(s.ports || []).join(', ')}</td>
                    <td>
                        <div class=\"progress-bar\">
                            <div class=\"progress-fill\" style=\"width: ${s.progress || 0}%\"></div>
                        </div>
                        <small>${(s.progress || 0).toFixed(1)}%</small>
                    </td>
                    <td><span class=\"status-badge status-${s.status}\">${s.status}</span></td>
                    <td>
                        <button class=\"btn btn-secondary\" onclick=\"viewResults('${s.id}')\">View</button>
                        ${s.status === 'running' ? 
                            `<button class=\"btn\" onclick=\"stopScan('${s.id}')\">Stop</button>` : ''}
                    </td>
                </tr>
            `).join('');
        }

        // Start scan
        async function startScan(event) {
            event.preventDefault();
            
            const cidrs = document.getElementById('cidrs').value
                .split('\\n')
                .map(s => s.trim())
                .filter(s => s);
            const ports = document.getElementById('ports').value
                .split(',')
                .map(s => parseInt(s.trim()))
                .filter(n => !isNaN(n));
            const concurrency = parseInt(document.getElementById('concurrency').value);
            const timeout = parseInt(document.getElementById('timeout').value);
            
            try {
                const res = await fetch(`${API}/scans`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        cidrs,
                        ports,
                        concurrency,
                        timeout
                    })
                });
                const data = await res.json();
                if (data.scan_id) {
                    alert(`Scan started: ${data.scan_id}`);
                    switchTab('scans');
                    fetchScans();
                } else {
                    alert(`Error: ${data.error}`);
                }
            } catch (e) {
                alert(`Failed to start scan: ${e.message}`);
            }
        }

        // Stop scan
        async function stopScan(scanId) {
            if (!confirm('Stop this scan?')) return;
            try {
                await fetch(`${API}/scans/${scanId}`, {method: 'DELETE'});
                fetchScans();
            } catch (e) {
                alert(`Failed to stop scan: ${e.message}`);
            }
        }

        // View results
        async function viewResults(scanId) {
            try {
                const res = await fetch(`${API}/scans/${scanId}/results`);
                const data = await res.json();
                const output = document.getElementById('results-output');
                if (data.results && data.results.length > 0) {
                    output.innerHTML = data.results.map(r => 
                        `<div class=\"log-line\">
                            <span class=\"log-info\">${r.ip}:${r.port}</span> - 
                            <span class=\"${r.status === 'open' ? 'log-info' : 'log-warn'}\">${r.status}</span>
                            ${r.banner ? ` - ${r.banner}` : ''}
                        </div>`
                    ).join('');
                } else {
                    output.textContent = 'No results yet...';
                }
                switchTab('results');
            } catch (e) {
                alert(`Failed to fetch results: ${e.message}`);
            }
        }

        // Fetch sessions
        async function fetchSessions() {
            try {
                const res = await fetch(`${API}/sessions`);
                const data = await res.json();
                const tbody = document.getElementById('sessions-table');
                if (!data.sessions || data.sessions.length === 0) {
                    tbody.innerHTML = `<tr>
                        <td colspan=\"4\" style=\"text-align: center; color: #666;\">
                            No saved sessions
                        </td>
                    </tr>`;
                    return;
                }
                tbody.innerHTML = data.sessions.map(s => `
                    <tr>
                        <td><code>${s.id}</code></td>
                        <td>${new Date(s.last_updated * 1000).toLocaleString()}</td>
                        <td>${s.progress.toFixed(1)}%</td>
                        <td>
                            <button class=\"btn\" onclick=\"resumeSession('${s.id}')\">Resume</button>
                        </td>
                    </tr>
                `).join('');
            } catch (e) {
                console.error('Failed to fetch sessions:', e);
            }
        }

        // Resume session
        async function resumeSession(sessionId) {
            try {
                const res = await fetch(`${API}/sessions/${sessionId}/resume`, {method: 'POST'});
                const data = await res.json();
                if (data.scan_id) {
                    alert(`Resumed: ${data.scan_id}`);
                    switchTab('scans');
                    fetchScans();
                }
            } catch (e) {
                alert(`Failed to resume: ${e.message}`);
            }
        }

        // Add node modal
        function showAddNode() {
            const node = prompt('Enter node name (e.g., node@hostname):');
            if (node) {
                addNode(node);
            }
        }

        async function addNode(node) {
            try {
                const res = await fetch(`${API}/cluster/nodes`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({node})
                });
                const data = await res.json();
                if (data.status === 'connected') {
                    alert(`Connected to ${node}`);
                    fetchCluster();
                } else {
                    alert(`Error: ${data.error}`);
                }
            } catch (e) {
                alert(`Failed to connect: ${e.message}`);
            }
        }

        // Fetch cluster
        async function fetchCluster() {
            try {
                const res = await fetch(`${API}/cluster`);
                const data = await res.json();
                // Update sidebar nodes
                const container = document.getElementById('nodes-list');
                if (container) {
                    container.innerHTML = (data.nodes || []).map(n => `
                        <div class=\"node-card ${n.status}\">
                            <div>${n.status === 'online' ? '🟢' : '🔴'} ${n.node}</div>
                        </div>
                    `).join('');
                }
                // Update cluster tab nodes
                const clusterContainer = document.getElementById('cluster-nodes-list');
                if (clusterContainer) {
                    clusterContainer.innerHTML = (data.nodes || []).map(n => `
                        <div class=\"node-card ${n.status}\" style=\"padding: 1rem;\">
                            <div style=\"font-size: 1.2rem;\">${n.status === 'online' ? '🟢' : '🔴'} ${n.node}</div>
                            <small style=\"color: #888;\">Status: ${n.status}</small>
                        </div>
                    `).join('') || '<div style=\"color: #888;\">No cluster nodes connected</div>';
                }
            } catch (e) {
                console.error('Failed to fetch cluster:', e);
            }
        }

        // Initial load
        fetchStatus();
        fetchScans();
        fetchSessions();
        fetchCluster();

        // Auto-refresh every 5 seconds
        setInterval(() => {
            fetchStatus();
            fetchScans();
        }, 5000);
    </script>
</body>
</html>">>.
