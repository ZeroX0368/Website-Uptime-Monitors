
const http = require('http');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Persistent storage helper
class Storage {
  constructor() {
    this.dataDir = path.join(__dirname, 'data');
    this.usersFile = path.join(this.dataDir, 'users.json');
    this.monitorsFile = path.join(this.dataDir, 'monitors.json');
    this.resultsFile = path.join(this.dataDir, 'results.json');
    
    // Create data directory if it doesn't exist
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir);
    }
    
    this.initializeFiles();
  }

  initializeFiles() {
    if (!fs.existsSync(this.usersFile)) {
      fs.writeFileSync(this.usersFile, '{}');
    }
    if (!fs.existsSync(this.monitorsFile)) {
      fs.writeFileSync(this.monitorsFile, '{}');
    }
    if (!fs.existsSync(this.resultsFile)) {
      fs.writeFileSync(this.resultsFile, '{}');
    }
  }

  loadUsers() {
    try {
      return JSON.parse(fs.readFileSync(this.usersFile, 'utf8'));
    } catch {
      return {};
    }
  }

  saveUsers(users) {
    fs.writeFileSync(this.usersFile, JSON.stringify(users, null, 2));
  }

  loadMonitors() {
    try {
      return JSON.parse(fs.readFileSync(this.monitorsFile, 'utf8'));
    } catch {
      return {};
    }
  }

  saveMonitors(monitors) {
    fs.writeFileSync(this.monitorsFile, JSON.stringify(monitors, null, 2));
  }

  loadResults() {
    try {
      return JSON.parse(fs.readFileSync(this.resultsFile, 'utf8'));
    } catch {
      return {};
    }
  }

  saveResults(results) {
    fs.writeFileSync(this.resultsFile, JSON.stringify(results, null, 2));
  }
}

class UptimeMonitor {
  constructor() {
    this.storage = new Storage();
    this.monitors = new Map();
    this.results = new Map();
    this.intervals = new Map();
    
    // Load data from storage
    this.loadFromStorage();
    
    // Save data periodically
    setInterval(() => this.saveToStorage(), 30000); // Save every 30 seconds
  }

  loadFromStorage() {
    const monitorsData = this.storage.loadMonitors();
    const resultsData = this.storage.loadResults();
    
    Object.entries(monitorsData).forEach(([id, monitor]) => {
      this.monitors.set(id, monitor);
      if (monitor.isActive) {
        this.startMonitoring(id);
      }
    });
    
    Object.entries(resultsData).forEach(([id, results]) => {
      this.results.set(id, results);
    });
  }

  saveToStorage() {
    const monitorsData = Object.fromEntries(this.monitors);
    const resultsData = Object.fromEntries(this.results);
    
    this.storage.saveMonitors(monitorsData);
    this.storage.saveResults(resultsData);
  }

  // Add a new monitor for a specific user
  addMonitor(id, config, username) {
    const monitor = {
      id,
      name: config.name,
      url: config.url,
      interval: config.interval || 300000, // 5 minutes default
      timeout: config.timeout || 30000, // 30 seconds default
      method: config.method || 'GET',
      expectedStatus: config.expectedStatus || 200,
      created: new Date(),
      isActive: true,
      username: username // Associate monitor with user
    };

    this.monitors.set(id, monitor);
    this.results.set(id, []);
    this.startMonitoring(id);
    this.saveToStorage();
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
    this.saveToStorage();
  }

  // Get monitors for a specific user
  getUserMonitors(username) {
    return Array.from(this.monitors.values()).filter(monitor => monitor.username === username);
  }

  // Get all stats for a specific user
  getUserStats(username) {
    const userMonitors = this.getUserMonitors(username);
    return userMonitors.map(monitor => this.getStats(monitor.id)).filter(Boolean);
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
      this.saveToStorage();
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
      console.log(`[${checkTime.toISOString()}] ${monitor.name} (${monitor.username}): ${checkResult.status} (${responseTime}ms)`);
      
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
      console.log(`[${checkTime.toISOString()}] ${monitor.name} (${monitor.username}): ${checkResult.status} - ${error.message}`);
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
    if (results) {
      results.push(result);
      if (results.length > 100) {
        results.shift();
      }
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
}

// User management system
class UserManager {
  constructor() {
    this.storage = new Storage();
    this.users = new Map();
    this.sessions = new Map();
    
    this.loadFromStorage();
    
    // Clean up expired sessions and inactive users every hour
    setInterval(() => {
      this.cleanupExpiredSessions();
      this.cleanupInactiveUsers();
    }, 3600000); // 1 hour
  }

  loadFromStorage() {
    const usersData = this.storage.loadUsers();
    Object.entries(usersData).forEach(([username, user]) => {
      // Convert date strings back to Date objects
      user.createdAt = new Date(user.createdAt);
      user.lastLogin = user.lastLogin ? new Date(user.lastLogin) : null;
      this.users.set(username, user);
    });
  }

  saveToStorage() {
    const usersData = Object.fromEntries(this.users);
    this.storage.saveUsers(usersData);
  }

  // Generate hash for password
  hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  // Generate session token
  generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  // Register new user
  register(username, password) {
    if (this.users.has(username)) {
      throw new Error('Username already exists');
    }

    const user = {
      username,
      password: this.hashPassword(password),
      createdAt: new Date(),
      lastLogin: new Date(),
      monitors: []
    };

    this.users.set(username, user);
    this.saveToStorage();
    return { username, createdAt: user.createdAt };
  }

  // Login user
  login(username, password) {
    const user = this.users.get(username);
    if (!user || user.password !== this.hashPassword(password)) {
      throw new Error('Invalid credentials');
    }

    // Update last login time
    user.lastLogin = new Date();
    this.saveToStorage();

    const sessionToken = this.generateSessionToken();
    this.sessions.set(sessionToken, {
      username,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
    });

    return { sessionToken, user: { username } };
  }

  // Validate session
  validateSession(sessionToken) {
    const session = this.sessions.get(sessionToken);
    if (!session || session.expiresAt < new Date()) {
      if (session) this.sessions.delete(sessionToken);
      return null;
    }
    return session;
  }

  // Logout
  logout(sessionToken) {
    this.sessions.delete(sessionToken);
  }

  // Get user by username
  getUser(username) {
    return this.users.get(username);
  }

  // Clean up expired sessions
  cleanupExpiredSessions() {
    const now = new Date();
    for (const [token, session] of this.sessions.entries()) {
      if (session.expiresAt < now) {
        this.sessions.delete(token);
      }
    }
  }

  // Clean up users who haven't logged in for 2 days
  cleanupInactiveUsers() {
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    const usersToDelete = [];
    
    for (const [username, user] of this.users.entries()) {
      if (user.lastLogin && user.lastLogin < twoDaysAgo) {
        usersToDelete.push(username);
      }
    }
    
    if (usersToDelete.length > 0) {
      console.log(`Cleaning up ${usersToDelete.length} inactive users: ${usersToDelete.join(', ')}`);
      
      for (const username of usersToDelete) {
        // Remove user's monitors
        const userMonitors = Array.from(this.users.get(username).monitors || []);
        userMonitors.forEach(monitorId => {
          // Remove from uptime monitor
          if (global.uptimeMonitor) {
            global.uptimeMonitor.removeMonitor(monitorId);
          }
        });
        
        // Remove user
        this.users.delete(username);
      }
      
      this.saveToStorage();
    }
  }
}

// Create HTTP server for API
class UptimeAPI {
  constructor() {
    this.monitor = new UptimeMonitor();
    this.userManager = new UserManager();
    this.server = http.createServer(this.handleRequest.bind(this));
    
    // Make monitor available globally for cleanup
    global.uptimeMonitor = this.monitor;
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
        this.sendDashboard(req, res);
      } else if (method === 'GET' && path === '/login') {
        this.sendLoginPage(res);
      } else if (method === 'POST' && path === '/api/register') {
        this.handleRegister(req, res);
      } else if (method === 'POST' && path === '/api/login') {
        this.handleLogin(req, res);
      } else if (method === 'POST' && path === '/api/logout') {
        this.handleLogout(req, res);
      } else if (method === 'GET' && path === '/api/user') {
        this.getCurrentUser(req, res);
      } else if (method === 'GET' && path === '/api/monitors') {
        this.getUserMonitors(req, res);
      } else if (method === 'POST' && path === '/api/monitors') {
        this.createMonitor(req, res);
      } else if (method === 'DELETE' && path.startsWith('/api/monitors/')) {
        const id = path.split('/')[3];
        this.deleteMonitor(req, id, res);
      } else if (method === 'GET' && path.startsWith('/api/monitors/') && path.endsWith('/stats')) {
        const id = path.split('/')[3];
        this.getMonitorStats(req, id, res);
      } else {
        this.sendError(res, 404, 'Not Found');
      }
    } catch (error) {
      console.error('Request error:', error);
      this.sendError(res, 500, 'Internal Server Error');
    }
  }

  // Get monitors for current user
  getUserMonitors(req, res) {
    const session = this.isAuthenticated(req);
    if (!session) {
      this.sendError(res, 401, 'Not authenticated');
      return;
    }

    const parsedUrl = url.parse(req.url, true);
    const query = parsedUrl.query;
    let stats = this.monitor.getUserStats(session.username);
    
    // Filter by URL if provided
    if (query.url) {
      stats = stats.filter(monitor => 
        monitor.url.toLowerCase().includes(query.url.toLowerCase())
      );
    }
    
    this.sendJSON(res, stats);
  }

  createMonitor(req, res) {
    const session = this.isAuthenticated(req);
    if (!session) {
      this.sendError(res, 401, 'Not authenticated');
      return;
    }

    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const config = JSON.parse(body);
        if (!config.name || !config.url) {
          this.sendError(res, 400, 'Name and URL are required');
          return;
        }

        const id = `${session.username}_${Date.now()}`;
        const monitor = this.monitor.addMonitor(id, config, session.username);
        
        // Add monitor ID to user's monitor list
        const user = this.userManager.getUser(session.username);
        if (user) {
          if (!user.monitors) user.monitors = [];
          user.monitors.push(id);
          this.userManager.saveToStorage();
        }
        
        this.sendJSON(res, monitor, 201);
      } catch (error) {
        this.sendError(res, 400, 'Invalid JSON');
      }
    });
  }

  deleteMonitor(req, id, res) {
    const session = this.isAuthenticated(req);
    if (!session) {
      this.sendError(res, 401, 'Not authenticated');
      return;
    }

    const monitor = this.monitor.monitors.get(id);
    if (!monitor) {
      this.sendError(res, 404, 'Monitor not found');
      return;
    }

    // Check if user owns this monitor
    if (monitor.username !== session.username) {
      this.sendError(res, 403, 'Access denied');
      return;
    }

    this.monitor.removeMonitor(id);
    
    // Remove monitor ID from user's monitor list
    const user = this.userManager.getUser(session.username);
    if (user && user.monitors) {
      user.monitors = user.monitors.filter(monitorId => monitorId !== id);
      this.userManager.saveToStorage();
    }
    
    this.sendJSON(res, { message: 'Monitor deleted' });
  }

  getMonitorStats(req, id, res) {
    const session = this.isAuthenticated(req);
    if (!session) {
      this.sendError(res, 401, 'Not authenticated');
      return;
    }

    const monitor = this.monitor.monitors.get(id);
    if (!monitor) {
      this.sendError(res, 404, 'Monitor not found');
      return;
    }

    // Check if user owns this monitor
    if (monitor.username !== session.username) {
      this.sendError(res, 403, 'Access denied');
      return;
    }

    const stats = this.monitor.getStats(id);
    this.sendJSON(res, stats);
  }

  // Extract session token from request
  getSessionToken(req) {
    const cookies = req.headers.cookie;
    if (!cookies) return null;
    
    const sessionCookie = cookies.split(';').find(c => c.trim().startsWith('session='));
    return sessionCookie ? sessionCookie.split('=')[1] : null;
  }

  // Check if user is authenticated
  isAuthenticated(req) {
    const sessionToken = this.getSessionToken(req);
    return sessionToken ? this.userManager.validateSession(sessionToken) : null;
  }

  // Handle user registration
  handleRegister(req, res) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { username, password } = JSON.parse(body);
        
        if (!username || !password) {
          this.sendError(res, 400, 'Username and password are required');
          return;
        }

        const user = this.userManager.register(username, password);
        this.sendJSON(res, { message: 'User registered successfully', user }, 201);
      } catch (error) {
        this.sendError(res, 400, error.message);
      }
    });
  }

  // Handle user login
  handleLogin(req, res) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { username, password } = JSON.parse(body);
        
        if (!username || !password) {
          this.sendError(res, 400, 'Username and password are required');
          return;
        }

        const result = this.userManager.login(username, password);
        
        // Set session cookie
        res.setHeader('Set-Cookie', `session=${result.sessionToken}; HttpOnly; Max-Age=86400; Path=/`);
        this.sendJSON(res, { message: 'Login successful', user: result.user });
      } catch (error) {
        this.sendError(res, 401, error.message);
      }
    });
  }

  // Handle user logout
  handleLogout(req, res) {
    const sessionToken = this.getSessionToken(req);
    if (sessionToken) {
      this.userManager.logout(sessionToken);
    }
    
    res.setHeader('Set-Cookie', 'session=; HttpOnly; Max-Age=0; Path=/');
    this.sendJSON(res, { message: 'Logout successful' });
  }

  // Get current user
  getCurrentUser(req, res) {
    const session = this.isAuthenticated(req);
    if (!session) {
      this.sendError(res, 401, 'Not authenticated');
      return;
    }

    const user = this.userManager.getUser(session.username);
    this.sendJSON(res, { 
      username: user.username,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin
    });
  }

  sendJSON(res, data, status = 200) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data, null, 2));
  }

  sendError(res, status, message) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: message }));
  }

  sendLoginPage(res) {
    const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Login - Uptime Monitor</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .login-container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-bottom: 10px; }
        .btn:hover { background: #0056b3; }
        .btn-secondary { background: #6c757d; }
        .btn-secondary:hover { background: #545b62; }
        .error { color: #dc3545; margin-top: 10px; }
        .success { color: #28a745; margin-top: 10px; }
        .toggle-form { text-align: center; margin-top: 20px; }
        .toggle-form a { color: #007bff; text-decoration: none; }
        h2 { text-align: center; margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div id="loginForm">
            <h2>Login to Uptime Monitor</h2>
            <form onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label for="loginUsername">Username:</label>
                    <input type="text" id="loginUsername" required />
                </div>
                <div class="form-group">
                    <label for="loginPassword">Password:</label>
                    <input type="password" id="loginPassword" required />
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
            <div class="toggle-form">
                <a href="#" onclick="showRegisterForm()">Don't have an account? Register here</a>
            </div>
        </div>

        <div id="registerForm" style="display: none;">
            <h2>Register for Uptime Monitor</h2>
            <form onsubmit="handleRegister(event)">
                <div class="form-group">
                    <label for="registerUsername">Username:</label>
                    <input type="text" id="registerUsername" required />
                </div>
                <div class="form-group">
                    <label for="registerPassword">Password:</label>
                    <input type="password" id="registerPassword" required />
                </div>
                <button type="submit" class="btn">Register</button>
            </form>
            <div class="toggle-form">
                <a href="#" onclick="showLoginForm()">Already have an account? Login here</a>
            </div>
        </div>

        <div id="message"></div>
    </div>

    <script>
        function showRegisterForm() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('registerForm').style.display = 'block';
            document.getElementById('message').innerHTML = '';
        }

        function showLoginForm() {
            document.getElementById('registerForm').style.display = 'none';
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('message').innerHTML = '';
        }

        function showMessage(message, isError = false) {
            const messageDiv = document.getElementById('message');
            messageDiv.innerHTML = \`<div class="\${isError ? 'error' : 'success'}">\${message}</div>\`;
        }

        function handleLogin(event) {
            event.preventDefault();
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;

            fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showMessage(data.error, true);
                } else {
                    showMessage('Login successful! Redirecting...');
                    setTimeout(() => window.location.href = '/', 1000);
                }
            })
            .catch(error => {
                showMessage('Login failed. Please try again.', true);
            });
        }

        function handleRegister(event) {
            event.preventDefault();
            const username = document.getElementById('registerUsername').value;
            const password = document.getElementById('registerPassword').value;

            fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showMessage(data.error, true);
                } else {
                    showMessage('Registration successful! Please login.');
                    showLoginForm();
                }
            })
            .catch(error => {
                showMessage('Registration failed. Please try again.', true);
            });
        }
    </script>
</body>
</html>`;
    
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  }

  sendDashboard(req, res) {
    const session = this.isAuthenticated(req);
    if (!session) {
      res.writeHead(302, { 'Location': '/login' });
      res.end();
      return;
    }

    const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Uptime Monitor Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
        .user-info { display: flex; align-items: center; gap: 15px; }
        .monitor-card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-up { color: #28a745; font-weight: bold; }
        .status-down { color: #dc3545; font-weight: bold; }
        .form { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .form input, .form button { margin: 5px; padding: 8px; }
        .form button { background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .delete-btn { background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; }
        .logout-btn { background: #dc3545; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 10px 0; }
        .stat { text-align: center; }
        .empty-state { text-align: center; padding: 40px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Uptime Monitor Dashboard</h1>
                <p>Monitor your websites and APIs</p>
            </div>
            <div class="user-info" id="userInfo">
                <span>Loading...</span>
            </div>
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
        let currentUser = null;

        function checkAuth() {
            fetch('/api/user')
                .then(response => {
                    if (response.ok) {
                        return response.json();
                    } else {
                        window.location.href = '/login';
                        throw new Error('Not authenticated');
                    }
                })
                .then(user => {
                    currentUser = user;
                    document.getElementById('userInfo').innerHTML = \`
                        <div>
                            <p style="margin: 0;"><strong>\${user.username}</strong></p>
                            <small>Last login: \${new Date(user.lastLogin).toLocaleString()}</small>
                        </div>
                        <button class="logout-btn" onclick="logout()">Logout</button>
                    \`;
                    loadMonitors();
                })
                .catch(error => {
                    console.error('Auth check failed:', error);
                });
        }

        function logout() {
            fetch('/api/logout', { method: 'POST' })
                .then(() => {
                    window.location.href = '/login';
                });
        }

        function loadMonitors() {
            fetch('/api/monitors')
                .then(response => response.json())
                .then(monitors => {
                    const container = document.getElementById('monitors');
                    
                    if (monitors.length === 0) {
                        container.innerHTML = \`
                            <div class="empty-state">
                                <h3>No monitors yet</h3>
                                <p>Add your first monitor above to start tracking uptime!</p>
                            </div>
                        \`;
                        return;
                    }
                    
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
                })
                .catch(error => {
                    console.error('Failed to load monitors:', error);
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
            .then(data => {
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    document.getElementById('name').value = '';
                    document.getElementById('url').value = '';
                    document.getElementById('interval').value = '300000';
                    loadMonitors();
                }
            })
            .catch(error => {
                console.error('Failed to add monitor:', error);
                alert('Failed to add monitor');
            });
        }

        function deleteMonitor(id) {
            if (confirm('Are you sure you want to delete this monitor?')) {
                fetch(\`/api/monitors/\${id}\`, { method: 'DELETE' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            alert('Error: ' + data.error);
                        } else {
                            loadMonitors();
                        }
                    })
                    .catch(error => {
                        console.error('Failed to delete monitor:', error);
                        alert('Failed to delete monitor');
                    });
            }
        }

        // Check authentication and load monitors on page load
        checkAuth();
        
        // Refresh every 30 seconds
        setInterval(() => {
            if (currentUser) loadMonitors();
        }, 30000);
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
    });
  }
}

// Start the server
const api = new UptimeAPI();
api.start();
