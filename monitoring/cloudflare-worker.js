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