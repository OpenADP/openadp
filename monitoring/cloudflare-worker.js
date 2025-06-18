/**
 * OpenADP Health Monitoring Cloudflare Worker
 * 
 * This worker:
 * 1. Polls all servers in servers.json every 5 minutes
 * 2. Collects health metrics via GetServerInfo API
 * 3. Stores results in Cloudflare KV
 * 4. Optionally commits updated health data to GitHub
 * 5. Provides API endpoints for health dashboard
 * 6. Sends Discord/email alerts for server issues
 */

// Configuration - these should be set as environment variables in Cloudflare
const CONFIG = {
  SERVERS_JSON_URL: 'https://servers.openadp.org/api/servers.json',
  GITHUB_TOKEN: '', // Set via environment variable
  GITHUB_REPO: 'waywardgeek/servers.openadp.org',
  DISCORD_WEBHOOK_URL: '', // Set via environment variable
  POLL_INTERVAL_MINUTES: 5,
  ERROR_THRESHOLD_PERCENT: 15,
  ERROR_DURATION_MINUTES: 30,
};

/**
 * Main request handler
 */
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

/**
 * Scheduled event handler - runs every 5 minutes
 */
addEventListener('scheduled', event => {
  event.waitUntil(handleScheduled(event));
});

/**
 * Handle HTTP requests
 */
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS headers for browser requests
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    switch (path) {
      case '/':
        return handleDashboardEndpoint(corsHeaders);
      case '/health':
        return handleHealthEndpoint(corsHeaders);
      case '/health/servers':
        return handleServersHealthEndpoint(corsHeaders);
      case '/health/history':
        return handleHealthHistoryEndpoint(url.searchParams, corsHeaders);
      case '/health/trigger-check':
        return handleTriggerCheckEndpoint(corsHeaders);
      default:
        return new Response('Not Found', { status: 404, headers: corsHeaders });
    }
  } catch (error) {
    console.error('Request handler error:', error);
    return new Response('Internal Server Error', { 
      status: 500, 
      headers: corsHeaders 
    });
  }
}

/**
 * Handle scheduled monitoring check
 */
async function handleScheduled(event) {
  console.log('Starting scheduled health check');
  
  try {
    await performHealthCheck();
    console.log('Scheduled health check completed successfully');
  } catch (error) {
    console.error('Scheduled health check failed:', error);
  }
}

/**
 * Perform health check on all servers
 */
async function performHealthCheck() {
  // Fetch current server list
  const servers = await fetchServerList();
  if (!servers || servers.length === 0) {
    throw new Error('No servers found in servers.json');
  }

  console.log(`Checking health of ${servers.length} servers`);

  // Check each server in parallel
  const healthPromises = servers.map(server => checkServerHealth(server));
  const healthResults = await Promise.allSettled(healthPromises);

  // Process results
  const timestamp = new Date().toISOString();
  const healthData = {
    timestamp,
    servers: [],
    summary: {
      total: servers.length,
      healthy: 0,
      unhealthy: 0,
      errors: 0,
    }
  };

  healthResults.forEach((result, index) => {
    const server = servers[index];
    if (result.status === 'fulfilled') {
      healthData.servers.push(result.value);
      if (result.value.healthy) {
        healthData.summary.healthy++;
      } else {
        healthData.summary.unhealthy++;
      }
    } else {
      console.error(`Health check failed for ${server.url}:`, result.reason);
      healthData.servers.push({
        url: server.url,
        country: server.country,
        healthy: false,
        error: result.reason.message || 'Unknown error',
        timestamp,
      });
      healthData.summary.errors++;
    }
  });

  // Store results in KV
  await HEALTH_DATA.put('latest', JSON.stringify(healthData));
  await HEALTH_DATA.put(`history:${timestamp}`, JSON.stringify(healthData));

  // Check for alerts
  await checkAndSendAlerts(healthData);

  // Optionally commit to GitHub
  if (CONFIG.GITHUB_TOKEN) {
    await commitHealthDataToGitHub(healthData);
  }

  return healthData;
}

/**
 * Check health of a single server
 */
async function checkServerHealth(server) {
  const startTime = Date.now();
  
  try {
    // Call GetServerInfo API
    const response = await fetch(server.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'GetServerInfo',
        params: [],
        id: 1,
      }),
      // 10 second timeout
      signal: AbortSignal.timeout(10000),
    });

    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    
    if (data.error) {
      throw new Error(`RPC Error: ${data.error.message}`);
    }

    const serverInfo = data.result;
    
    return {
      url: server.url,
      country: server.country,
      healthy: true,
      responseTime,
      timestamp: new Date().toISOString(),
      version: serverInfo.version,
      capabilities: serverInfo.capabilities,
      monitoring: serverInfo.monitoring || null,
    };

  } catch (error) {
    return {
      url: server.url,
      country: server.country,
      healthy: false,
      error: error.message,
      responseTime: Date.now() - startTime,
      timestamp: new Date().toISOString(),
    };
  }
}

/**
 * Fetch server list from servers.json
 */
async function fetchServerList() {
  try {
    const response = await fetch(CONFIG.SERVERS_JSON_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch servers.json: ${response.statusText}`);
    }
    
    const data = await response.json();
    return data.servers || [];
  } catch (error) {
    console.error('Failed to fetch server list:', error);
    throw error;
  }
}

/**
 * Check for alert conditions and send notifications
 */
async function checkAndSendAlerts(healthData) {
  const unhealthyServers = healthData.servers.filter(s => !s.healthy);
  
  if (unhealthyServers.length === 0) {
    return; // All servers healthy
  }

  // Check if we should send alerts
  for (const server of unhealthyServers) {
    const alertKey = `alert:${server.url}`;
    const lastAlert = await HEALTH_DATA.get(alertKey);
    
    const shouldAlert = !lastAlert || 
      (Date.now() - new Date(lastAlert).getTime()) > (CONFIG.ERROR_DURATION_MINUTES * 60 * 1000);

    if (shouldAlert) {
      await sendServerAlert(server);
      await HEALTH_DATA.put(alertKey, new Date().toISOString());
    }
  }

  // Send summary alert if many servers are down
  const downPercentage = (unhealthyServers.length / healthData.summary.total) * 100;
  if (downPercentage >= 50) { // Alert if >50% of servers are down
    await sendNetworkAlert(healthData);
  }
}

/**
 * Send alert for individual server
 */
async function sendServerAlert(server) {
  const message = `🚨 **OpenADP Server Alert**\n\n` +
    `**Server**: ${server.url}\n` +
    `**Country**: ${server.country}\n` +
    `**Status**: Down\n` +
    `**Error**: ${server.error}\n` +
    `**Time**: ${server.timestamp}\n\n` +
    `Please check the server and resolve the issue.`;

  if (CONFIG.DISCORD_WEBHOOK_URL) {
    await sendDiscordAlert(message);
  }
}

/**
 * Send network-wide alert
 */
async function sendNetworkAlert(healthData) {
  const message = `🚨 **OpenADP Network Alert**\n\n` +
    `**Servers Down**: ${healthData.summary.unhealthy}/${healthData.summary.total}\n` +
    `**Percentage**: ${Math.round((healthData.summary.unhealthy / healthData.summary.total) * 100)}%\n` +
    `**Time**: ${healthData.timestamp}\n\n` +
    `Multiple servers are experiencing issues. Please investigate.`;

  if (CONFIG.DISCORD_WEBHOOK_URL) {
    await sendDiscordAlert(message);
  }
}

/**
 * Send Discord notification
 */
async function sendDiscordAlert(message) {
  try {
    await fetch(CONFIG.DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        content: message,
      }),
    });
  } catch (error) {
    console.error('Failed to send Discord alert:', error);
  }
}

/**
 * Commit health data to GitHub repository
 */
async function commitHealthDataToGitHub(healthData) {
  try {
    const fileName = 'health/latest.json';
    const content = JSON.stringify(healthData, null, 2);
    const encodedContent = btoa(content);

    // Get current file SHA (needed for updates)
    let sha = null;
    try {
      const getResponse = await fetch(
        `https://api.github.com/repos/${CONFIG.GITHUB_REPO}/contents/${fileName}`,
        {
          headers: {
            'Authorization': `token ${CONFIG.GITHUB_TOKEN}`,
            'User-Agent': 'OpenADP-Health-Monitor',
          },
        }
      );
      
      if (getResponse.ok) {
        const fileData = await getResponse.json();
        sha = fileData.sha;
      }
    } catch (error) {
      // File might not exist yet, that's okay
    }

    // Create or update file
    const commitData = {
      message: `Update health data - ${healthData.timestamp}`,
      content: encodedContent,
    };

    if (sha) {
      commitData.sha = sha;
    }

    const response = await fetch(
      `https://api.github.com/repos/${CONFIG.GITHUB_REPO}/contents/${fileName}`,
      {
        method: 'PUT',
        headers: {
          'Authorization': `token ${CONFIG.GITHUB_TOKEN}`,
          'Content-Type': 'application/json',
          'User-Agent': 'OpenADP-Health-Monitor',
        },
        body: JSON.stringify(commitData),
      }
    );

    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.statusText}`);
    }

    console.log('Successfully committed health data to GitHub');
  } catch (error) {
    console.error('Failed to commit to GitHub:', error);
  }
}

/**
 * Handle / endpoint (dashboard)
 */
async function handleDashboardEndpoint(corsHeaders) {
  const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenADP Network Health Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
            color: white;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }

        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }

        .dashboard {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }

        .card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
        }

        .card h2 {
            font-size: 1.5rem;
            margin-bottom: 20px;
            color: #4a5568;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .status-overview {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .stat {
            text-align: center;
            padding: 15px;
            border-radius: 10px;
            background: #f8f9fa;
        }

        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 0.9rem;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .healthy { color: #10b981; }
        .unhealthy { color: #ef4444; }
        .warning { color: #f59e0b; }

        .servers-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }

        .server-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            border-left: 4px solid #e5e7eb;
            transition: all 0.3s ease;
        }

        .server-card.healthy {
            border-left-color: #10b981;
        }

        .server-card.unhealthy {
            border-left-color: #ef4444;
        }

        .server-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 15px;
        }

        .server-url {
            font-weight: 600;
            color: #1f2937;
            font-size: 1.1rem;
        }

        .server-status {
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 500;
            font-size: 0.9rem;
        }

        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        .status-dot.healthy {
            background: #10b981;
        }

        .status-dot.unhealthy {
            background: #ef4444;
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        .server-metrics {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 15px;
        }

        .metric {
            text-align: center;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 8px;
        }

        .metric-value {
            font-size: 1.3rem;
            font-weight: bold;
            color: #4a5568;
        }

        .metric-label {
            font-size: 0.8rem;
            color: #6b7280;
            margin-top: 2px;
        }

        .error-message {
            background: #fef2f2;
            color: #dc2626;
            padding: 10px;
            border-radius: 8px;
            font-size: 0.9rem;
            margin-top: 10px;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: white;
        }

        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(255,255,255,0.3);
            border-top: 4px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .refresh-btn {
            background: #4f46e5;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.3s ease;
            margin: 20px auto;
            display: block;
        }

        .refresh-btn:hover {
            background: #4338ca;
        }

        .last-updated {
            text-align: center;
            color: rgba(255,255,255,0.8);
            font-size: 0.9rem;
            margin-top: 20px;
        }

        .country-flag {
            font-size: 1.2rem;
            margin-right: 8px;
        }

        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .servers-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .container {
                padding: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ OpenADP Network Health</h1>
            <p>Real-time monitoring of OpenADP servers worldwide</p>
        </div>

        <div id="loading" class="loading">
            <div class="loading-spinner"></div>
            <p>Loading server health data...</p>
        </div>

        <div id="dashboard" class="dashboard" style="display: none;">
            <div class="card">
                <h2>📊 Network Overview</h2>
                <div class="status-overview">
                    <div class="stat">
                        <div class="stat-number healthy" id="healthy-count">-</div>
                        <div class="stat-label">Healthy</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number unhealthy" id="unhealthy-count">-</div>
                        <div class="stat-label">Down</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" id="total-count">-</div>
                        <div class="stat-label">Total</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" id="avg-response">-</div>
                        <div class="stat-label">Avg Response</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>🌍 Geographic Distribution</h2>
                <div id="geo-stats" class="status-overview">
                    <!-- Geographic stats will be populated here -->
                </div>
            </div>
        </div>

        <div id="servers-container" style="display: none;">
            <div class="servers-grid" id="servers-grid">
                <!-- Server cards will be populated here -->
            </div>
        </div>

        <button class="refresh-btn" onclick="loadHealthData()">🔄 Refresh Data</button>
        <div class="last-updated" id="last-updated"></div>
    </div>

    <script>
        const API_BASE = window.location.origin;
        
        // Country code to flag emoji mapping
        const countryFlags = {
            'US': '🇺🇸',
            'CA': '🇨🇦',
            'GB': '🇬🇧',
            'DE': '🇩🇪',
            'FR': '🇫🇷',
            'JP': '🇯🇵',
            'AU': '🇦🇺',
            'BR': '🇧🇷',
            'IN': '🇮🇳',
            'SG': '🇸🇬'
        };

        async function loadHealthData() {
            try {
                showLoading(true);
                
                const response = await fetch(\`\${API_BASE}/health\`);
                if (!response.ok) {
                    throw new Error(\`HTTP \${response.status}: \${response.statusText}\`);
                }
                
                const data = await response.json();
                displayHealthData(data);
                
            } catch (error) {
                console.error('Failed to load health data:', error);
                showError(\`Failed to load health data: \${error.message}\`);
            } finally {
                showLoading(false);
            }
        }

        function displayHealthData(data) {
            // Update overview stats
            document.getElementById('healthy-count').textContent = data.summary.healthy;
            document.getElementById('unhealthy-count').textContent = data.summary.unhealthy;
            document.getElementById('total-count').textContent = data.summary.total;
            
            // Calculate average response time
            const healthyServers = data.servers.filter(s => s.healthy && s.responseTime);
            const avgResponse = healthyServers.length > 0 
                ? Math.round(healthyServers.reduce((sum, s) => sum + s.responseTime, 0) / healthyServers.length)
                : 0;
            document.getElementById('avg-response').textContent = avgResponse > 0 ? \`\${avgResponse}ms\` : 'N/A';

            // Update geographic distribution
            displayGeographicStats(data.servers);

            // Display server cards
            displayServers(data.servers);

            // Update timestamp
            const timestamp = new Date(data.timestamp);
            document.getElementById('last-updated').textContent = 
                \`Last updated: \${timestamp.toLocaleString()}\`;

            // Show dashboard
            document.getElementById('dashboard').style.display = 'grid';
            document.getElementById('servers-container').style.display = 'block';
        }

        function displayGeographicStats(servers) {
            const geoStats = {};
            servers.forEach(server => {
                const country = server.country || 'Unknown';
                if (!geoStats[country]) {
                    geoStats[country] = { total: 0, healthy: 0 };
                }
                geoStats[country].total++;
                if (server.healthy) {
                    geoStats[country].healthy++;
                }
            });

            const geoContainer = document.getElementById('geo-stats');
            geoContainer.innerHTML = '';

            Object.entries(geoStats).forEach(([country, stats]) => {
                const flag = countryFlags[country] || '🌍';
                const healthyPercent = Math.round((stats.healthy / stats.total) * 100);
                
                const statDiv = document.createElement('div');
                statDiv.className = 'stat';
                statDiv.innerHTML = \`
                    <div class="stat-number">\${flag}</div>
                    <div class="stat-label">\${country}</div>
                    <div style="font-size: 0.8rem; margin-top: 5px; color: \${healthyPercent === 100 ? '#10b981' : '#f59e0b'}">
                        \${stats.healthy}/\${stats.total} (\${healthyPercent}%)
                    </div>
                \`;
                geoContainer.appendChild(statDiv);
            });
        }

        function displayServers(servers) {
            const container = document.getElementById('servers-grid');
            container.innerHTML = '';

            servers.forEach(server => {
                const serverCard = createServerCard(server);
                container.appendChild(serverCard);
            });
        }

        function createServerCard(server) {
            const card = document.createElement('div');
            card.className = \`server-card \${server.healthy ? 'healthy' : 'unhealthy'}\`;
            
            const flag = countryFlags[server.country] || '🌍';
            const url = new URL(server.url);
            const domain = url.hostname;

            let metricsHTML = '';
            if (server.healthy) {
                const uptime = server.monitoring?.uptime_start 
                    ? formatUptime(server.monitoring.uptime_start) 
                    : 'Unknown';
                
                metricsHTML = \`
                    <div class="server-metrics">
                        <div class="metric">
                            <div class="metric-value">\${server.responseTime}ms</div>
                            <div class="metric-label">Response Time</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value">\${uptime}</div>
                            <div class="metric-label">Uptime</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value">\${server.monitoring?.queries_current_hour || 0}</div>
                            <div class="metric-label">Queries/Hour</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value">\${server.monitoring?.error_rate_percent || 0}%</div>
                            <div class="metric-label">Error Rate</div>
                        </div>
                    </div>
                \`;
            } else {
                metricsHTML = \`
                    <div class="error-message">
                        ❌ \${server.error || 'Server is not responding'}
                    </div>
                \`;
            }

            card.innerHTML = \`
                <div class="server-header">
                    <div>
                        <div class="server-url">
                            <span class="country-flag">\${flag}</span>
                            \${domain}
                        </div>
                        <div style="font-size: 0.9rem; color: #6b7280; margin-top: 2px;">
                            \${server.country} • v\${server.version || 'Unknown'}
                        </div>
                    </div>
                    <div class="server-status">
                        <div class="status-dot \${server.healthy ? 'healthy' : 'unhealthy'}"></div>
                        \${server.healthy ? 'Online' : 'Offline'}
                    </div>
                </div>
                \${metricsHTML}
            \`;

            return card;
        }

        function formatUptime(uptimeStart) {
            const start = new Date(uptimeStart);
            const now = new Date();
            const diffMs = now - start;
            
            const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
            const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            
            if (days > 0) {
                return \`\${days}d \${hours}h\`;
            } else if (hours > 0) {
                return \`\${hours}h\`;
            } else {
                return '< 1h';
            }
        }

        function showLoading(show) {
            document.getElementById('loading').style.display = show ? 'block' : 'none';
            if (!show) {
                document.getElementById('dashboard').style.display = 'grid';
                document.getElementById('servers-container').style.display = 'block';
            }
        }

        function showError(message) {
            document.getElementById('loading').innerHTML = \`
                <div style="color: #ef4444;">
                    <h3>❌ Error</h3>
                    <p>\${message}</p>
                    <button class="refresh-btn" onclick="loadHealthData()" style="margin-top: 20px;">
                        Try Again
                    </button>
                </div>
            \`;
        }

        // Auto-refresh every 5 minutes
        setInterval(loadHealthData, 5 * 60 * 1000);

        // Load initial data
        loadHealthData();
    </script>
</body>
</html>`;

  return new Response(dashboardHTML, {
    headers: {
      ...corsHeaders,
      'Content-Type': 'text/html',
    },
  });
}

/**
 * Handle /health endpoint
 */
async function handleHealthEndpoint(corsHeaders) {
  try {
    const latestData = await HEALTH_DATA.get('latest');
    if (!latestData) {
      return new Response('No health data available', { 
        status: 404, 
        headers: corsHeaders 
      });
    }

    return new Response(latestData, {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=60', // Cache for 1 minute
      },
    });
  } catch (error) {
    console.error('Health endpoint error:', error);
    return new Response('Internal Server Error', { 
      status: 500, 
      headers: corsHeaders 
    });
  }
}

/**
 * Handle /health/servers endpoint (server list with health status)
 */
async function handleServersHealthEndpoint(corsHeaders) {
  try {
    const latestData = await HEALTH_DATA.get('latest');
    if (!latestData) {
      return new Response('No health data available', { 
        status: 404, 
        headers: corsHeaders 
      });
    }

    const data = JSON.parse(latestData);
    
    // Format for server selection UI
    const servers = data.servers.map(server => ({
      url: server.url,
      country: server.country,
      healthy: server.healthy,
      responseTime: server.responseTime,
      uptime: server.monitoring?.uptime_start ? 
        calculateUptime(server.monitoring.uptime_start) : null,
      queriesPerHour: server.monitoring?.queries_current_hour || 0,
      errorRate: server.monitoring?.error_rate_percent || 0,
    }));

    return new Response(JSON.stringify({ servers }), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=60',
      },
    });
  } catch (error) {
    console.error('Servers health endpoint error:', error);
    return new Response('Internal Server Error', { 
      status: 500, 
      headers: corsHeaders 
    });
  }
}

/**
 * Handle /health/history endpoint
 */
async function handleHealthHistoryEndpoint(searchParams, corsHeaders) {
  try {
    const hours = parseInt(searchParams.get('hours') || '24');
    const limit = Math.min(hours * 12, 288); // Max 24 hours of 5-minute intervals

    // List recent history keys
    const historyKeys = await HEALTH_DATA.list({ prefix: 'history:' });
    const sortedKeys = historyKeys.keys
      .sort((a, b) => b.name.localeCompare(a.name))
      .slice(0, limit);

    // Fetch history data
    const historyPromises = sortedKeys.map(key => HEALTH_DATA.get(key.name));
    const historyData = await Promise.all(historyPromises);

    const history = historyData
      .filter(data => data !== null)
      .map(data => JSON.parse(data));

    return new Response(JSON.stringify({ history }), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=300', // Cache for 5 minutes
      },
    });
  } catch (error) {
    console.error('History endpoint error:', error);
    return new Response('Internal Server Error', { 
      status: 500, 
      headers: corsHeaders 
    });
  }
}

/**
 * Handle /health/trigger-check endpoint (for manual testing)
 */
async function handleTriggerCheckEndpoint(corsHeaders) {
  try {
    const healthData = await performHealthCheck();
    return new Response(JSON.stringify(healthData), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
      },
    });
  } catch (error) {
    console.error('Trigger check error:', error);
    return new Response('Internal Server Error', { 
      status: 500, 
      headers: corsHeaders 
    });
  }
}

/**
 * Calculate uptime duration
 */
function calculateUptime(uptimeStart) {
  const start = new Date(uptimeStart);
  const now = new Date();
  const diffMs = now - start;
  
  const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  
  if (days > 0) {
    return `${days}d ${hours}h`;
  } else {
    return `${hours}h`;
  }
} 