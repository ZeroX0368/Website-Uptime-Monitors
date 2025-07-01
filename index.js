
const http = require('http');
const https = require('https');
const url = require('url');

class UptimeMonitor {
  constructor() {
    this.monitors = new Map();
    this.results = new Map();
    this.intervals = new Map();
  }

  // Add a new monitor
  addMonitor(id, config) {
    const monitor = {
      id,
      name: config.name,
      url: config.url,
      interval: config.interval || 300000, // 5 minutes default
      timeout: config.timeout || 30000, // 30 seconds default
      method: config.method || 'GET',
      expectedStatus: config.expectedStatus || 200,
      created: new Date(),
      isActive: true
    };

    this.monitors.set(id, monitor);
    this.results.set(id, []);
    this.startMonitoring(id);
    return monitor;
  }

  // Remove a monitor
  removeMonitor(id) {
    if (this.intervals.has(id)) {
      clearInterval(this.intervals.get(id));
      this.intervals.delete(id);
    }
    this.monitors.delete(id);
    this.results.delete(id);
  }

  // Start monitoring for a specific monitor
  startMonitoring(id) {
    const monitor = this.monitors.get(id);
    if (!monitor || !monitor.isActive) return;

    const check = () => this.checkEndpoint(id);
    check(); // Initial check
    const interval = setInterval(check, monitor.interval);
    this.intervals.set(id, interval);
  }

  // Stop monitoring for a specific monitor
  stopMonitoring(id) {
    if (this.intervals.has(id)) {
      clearInterval(this.intervals.get(id));
      this.intervals.delete(id);
    }
    const monitor = this.monitors.get(id);
    if (monitor) {
      monitor.isActive = false;
    }
  }

  // Check endpoint status
  async checkEndpoint(id) {
    const monitor = this.monitors.get(id);
    if (!monitor) return;

    const startTime = Date.now();
    const checkTime = new Date();
    
    try {
      const result = await this.makeRequest(monitor);
      const responseTime = Date.now() - startTime;
      
      const checkResult = {
        timestamp: checkTime,
        status: result.status === monitor.expectedStatus ? 'up' : 'down',
        responseTime,
        statusCode: result.status,
        error: result.status !== monitor.expectedStatus ? `Expected ${monitor.expectedStatus}, got ${result.status}` : null
      };

      this.addResult(id, checkResult);
      console.log(`[${checkTime.toISOString()}] ${monitor.name}: ${checkResult.status} (${responseTime}ms)`);
      
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const checkResult = {
        timestamp: checkTime,
        status: 'down',
        responseTime,
        statusCode: null,
        error: error.message
      };

      this.addResult(id, checkResult);
      console.log(`[${checkTime.toISOString()}] ${monitor.name}: ${checkResult.status} - ${error.message}`);
    }
  }

  // Make HTTP/HTTPS request
  makeRequest(monitor) {
    return new Promise((resolve, reject) => {
      const parsedUrl = url.parse(monitor.url);
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port,
        path: parsedUrl.path,
        method: monitor.method,
        timeout: monitor.timeout,
        headers: {
          'User-Agent': 'UptimeMonitor/1.0'
        }
      };

      const protocol = parsedUrl.protocol === 'https:' ? https : http;
      
      const req = protocol.request(options, (res) => {
        resolve({ status: res.statusCode });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.end();
    });
  }

  // Add result to history (keep last 100 results)
  addResult(id, result) {
    const results = this.results.get(id);
    results.push(result);
    if (results.length > 100) {
      results.shift();
    }
  }

  // Get monitor statistics
  getStats(id) {
    const monitor = this.monitors.get(id);
    const results = this.results.get(id) || [];
    
    if (!monitor || results.length === 0) {
      return null;
    }

    const upChecks = results.filter(r => r.status === 'up').length;
    const totalChecks = results.length;
    const uptime = totalChecks > 0 ? (upChecks / totalChecks) * 100 : 0;
    
    const responseTimes = results.filter(r => r.responseTime).map(r => r.responseTime);
    const avgResponseTime = responseTimes.length > 0 ? 
      responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length : 0;

    const lastCheck = results[results.length - 1];

    return {
      id: monitor.id,
      name: monitor.name,
      url: monitor.url,
      uptime: Math.round(uptime * 100) / 100,
      totalChecks,
      avgResponseTime: Math.round(avgResponseTime),
      lastCheck: lastCheck ? {
        timestamp: lastCheck.timestamp,
        status: lastCheck.status,
        responseTime: lastCheck.responseTime
      } : null,
      isActive: monitor.isActive
    };
  }

  // Get all monitors
  getAllMonitors() {
    return Array.from(this.monitors.values());
  }

  // Get all stats
  getAllStats() {
    return Array.from(this.monitors.keys()).map(id => this.getStats(id)).filter(Boolean);
  }
}

// Create HTTP server for API
class UptimeAPI {
  constructor() {
    this.monitor = new UptimeMonitor();
    this.server = http.createServer(this.handleRequest.bind(this));
  }

  handleRequest(req, res) {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    const parsedUrl = url.parse(req.url, true);
    const path = parsedUrl.pathname;
    const method = req.method;

    try {
      if (method === 'GET' && path === '/') {
        this.sendDashboard(res);
      } else if (method === 'GET' && path === '/api/monitors') {
        const query = parsedUrl.query;
        let stats = this.monitor.getAllStats();
        
        // Filter by URL if provided
        if (query.url) {
          stats = stats.filter(monitor => 
            monitor.url.toLowerCase().includes(query.url.toLowerCase())
          );
        }
        
        this.sendJSON(res, stats);
      } else if (method === 'POST' && path === '/api/monitors') {
        this.createMonitor(req, res);
      } else if (method === 'DELETE' && path.startsWith('/api/monitors/')) {
        const id = path.split('/')[3];
        this.deleteMonitor(id, res);
      } else if (method === 'GET' && path.startsWith('/api/monitors/') && path.endsWith('/stats')) {
        const id = path.split('/')[3];
        const stats = this.monitor.getStats(id);
        this.sendJSON(res, stats);
      } else {
        this.sendError(res, 404, 'Not Found');
      }
    } catch (error) {
      console.error('Request error:', error);
      this.sendError(res, 500, 'Internal Server Error');
    }
  }

  createMonitor(req, res) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const config = JSON.parse(body);
        if (!config.name || !config.url) {
          this.sendError(res, 400, 'Name and URL are required');
          return;
        }

        const id = Date.now().toString();
        const monitor = this.monitor.addMonitor(id, config);
        this.sendJSON(res, monitor, 201);
      } catch (error) {
        this.sendError(res, 400, 'Invalid JSON');
      }
    });
  }

  deleteMonitor(id, res) {
    if (this.monitor.monitors.has(id)) {
      this.monitor.removeMonitor(id);
      this.sendJSON(res, { message: 'Monitor deleted' });
    } else {
      this.sendError(res, 404, 'Monitor not found');
    }
  }

  sendJSON(res, data, status = 200) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data, null, 2));
  }

  sendError(res, status, message) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: message }));
  }

  sendDashboard(res) {
    const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Uptime Monitor Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .monitor-card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-up { color: #28a745; font-weight: bold; }
        .status-down { color: #dc3545; font-weight: bold; }
        .form { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .form input, .form button { margin: 5px; padding: 8px; }
        .form button { background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .delete-btn { background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 10px 0; }
        .stat { text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Uptime Monitor Dashboard</h1>
            <p>Monitor your websites and APIs</p>
        </div>

        <div class="form">
            <h3>Add New Monitor</h3>
            <input type="text" id="name" placeholder="Monitor Name" />
            <input type="url" id="url" placeholder="https://example.com" />
            <input type="number" id="interval" placeholder="Interval (ms)" value="300000" />
            <button onclick="addMonitor()">Add Monitor</button>
        </div>

        <div id="monitors"></div>
    </div>

    <script>
        function loadMonitors() {
            fetch('/api/monitors')
                .then(response => response.json())
                .then(monitors => {
                    const container = document.getElementById('monitors');
                    container.innerHTML = monitors.map(monitor => \`
                        <div class="monitor-card">
                            <h3>\${monitor.name}</h3>
                            <p><strong>URL:</strong> \${monitor.url}</p>
                            <div class="stats">
                                <div class="stat">
                                    <strong>Status:</strong><br>
                                    <span class="status-\${monitor.lastCheck?.status || 'down'}">\${(monitor.lastCheck?.status || 'Unknown').toUpperCase()}</span>
                                </div>
                                <div class="stat">
                                    <strong>Uptime:</strong><br>
                                    \${monitor.uptime}%
                                </div>
                                <div class="stat">
                                    <strong>Avg Response:</strong><br>
                                    \${monitor.avgResponseTime}ms
                                </div>
                                <div class="stat">
                                    <strong>Total Checks:</strong><br>
                                    \${monitor.totalChecks}
                                </div>
                            </div>
                            <p><strong>Last Check:</strong> \${monitor.lastCheck ? new Date(monitor.lastCheck.timestamp).toLocaleString() : 'Never'}</p>
                            <button class="delete-btn" onclick="deleteMonitor('\${monitor.id}')">Delete</button>
                        </div>
                    \`).join('');
                });
        }

        function addMonitor() {
            const name = document.getElementById('name').value;
            const url = document.getElementById('url').value;
            const interval = parseInt(document.getElementById('interval').value);

            if (!name || !url) {
                alert('Please fill in name and URL');
                return;
            }

            fetch('/api/monitors', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, url, interval })
            })
            .then(response => response.json())
            .then(() => {
                document.getElementById('name').value = '';
                document.getElementById('url').value = '';
                document.getElementById('interval').value = '300000';
                loadMonitors();
            });
        }

        function deleteMonitor(id) {
            if (confirm('Are you sure you want to delete this monitor?')) {
                fetch(\`/api/monitors/\${id}\`, { method: 'DELETE' })
                    .then(() => loadMonitors());
            }
        }

        // Load monitors on page load
        loadMonitors();
        
        // Refresh every 30 seconds
        setInterval(loadMonitors, 30000);
    </script>
</body>
</html>`;
    
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  }

  start(port = 5000) {
    this.server.listen(port, '0.0.0.0', () => {
      console.log(`Uptime Monitor API running on http://0.0.0.0:${port}`);
      console.log('Dashboard available at the root URL');
      
      // Add some example monitors
      setTimeout(() => {
        this.monitor.addMonitor('example1', {
          name: 'Google',
          url: 'https://www.google.com',
          interval: 60000
        });
        
        this.monitor.addMonitor('example2', {
          name: 'GitHub',
          url: 'https://github.com',
          interval: 120000
        });
      }, 1000);
    });
  }
}

// Start the server
const api = new UptimeAPI();
api.start();
