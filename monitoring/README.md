# OpenADP Health Monitoring System

This directory contains the health monitoring infrastructure for the OpenADP network, built on Cloudflare Workers.

## Overview

The monitoring system:
- **Polls all OpenADP servers** every 5 minutes via the `GetServerInfo` API
- **Collects health metrics** including uptime, response times, and query rates
- **Stores data** in Cloudflare KV for fast global access
- **Sends alerts** via Discord for server issues
- **Commits health data** to GitHub for transparency
- **Provides APIs** for health dashboards

## Architecture

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│ Cloudflare      │    │ OpenADP      │    │ GitHub          │
│ Worker          │───▶│ Servers      │    │ Repository      │
│ (Scheduler)     │    │              │    │                 │
└─────────────────┘    └──────────────┘    └─────────────────┘
         │                       │                    ▲
         │                       │                    │
         ▼                       ▼                    │
┌─────────────────┐    ┌──────────────┐              │
│ Cloudflare KV   │    │ Discord      │              │
│ (Health Data)   │    │ Alerts       │              │
└─────────────────┘    └──────────────┘              │
         │                                            │
         │                                            │
         ▼                                            │
┌─────────────────┐                                   │
│ Health          │                                   │
│ Dashboard       │───────────────────────────────────┘
│ (Public API)    │
└─────────────────┘
```

## Features

### 🔍 **Server Health Monitoring**
- **Availability checks** - Tests if servers respond to `GetServerInfo`
- **Response time tracking** - Measures API response latency
- **Error rate monitoring** - Tracks failed requests over time
- **Query rate analysis** - Monitors server load and usage patterns

### 📊 **Data Collection**
- **Real-time metrics** from server `monitoring` field in `GetServerInfo`
- **Historical data** stored with 5-minute granularity
- **Geographic distribution** tracking by country
- **Server capability** monitoring (encryption, features)

### 🚨 **Alerting System**
- **Discord notifications** for server outages
- **Configurable thresholds** (>15% error rate for 30+ minutes)
- **Network-wide alerts** when >50% of servers are down
- **Rate limiting** to prevent alert spam

### 🌐 **Public APIs**
- `GET /health` - Latest health summary
- `GET /health/servers` - Server list with health status  
- `GET /health/history?hours=24` - Historical health data
- `POST /health/trigger-check` - Manual health check

### 📁 **GitHub Integration**
- **Automatic commits** of health data to repository
- **Transparent monitoring** - public access to health metrics
- **Version control** of health data for analysis

## Deployment

### 🚀 Quick Start (Recommended)

We provide automated deployment scripts to make setup easy:

**1. Check Configuration Requirements:**
```bash
cd monitoring/
./config-helper.sh
```
This guides you through setting up GitHub tokens and Discord webhooks.

**2. Run Automated Deployment:**
```bash
./deploy.sh
```
This script will:
- ✅ Check prerequisites (Node.js, npm, git)
- ✅ Install Wrangler CLI if needed
- ✅ Authenticate with Cloudflare
- ✅ Create KV namespaces automatically
- ✅ Configure secrets securely
- ✅ Deploy the worker
- ✅ Test the deployment
- ✅ Provide next steps

**3. Development Setup** (for testing):
```bash
./dev-setup.sh
```

### 🔧 Manual Deployment

If you prefer manual setup:

#### Prerequisites
- Cloudflare account with Workers and KV enabled
- GitHub repository for health data storage
- Discord webhook URL for alerts
- Wrangler CLI installed (`npm install -g wrangler`)

#### Step 1: Setup Cloudflare KV
```bash
# Create KV namespace for health data
wrangler kv:namespace create "HEALTH_DATA"
wrangler kv:namespace create "HEALTH_DATA" --preview

# Note the namespace IDs and update wrangler.toml
```

#### Step 2: Configure Environment
```bash
# Set secrets (sensitive data)
wrangler secret put GITHUB_TOKEN
# Enter your GitHub Personal Access Token with repo write access

wrangler secret put DISCORD_WEBHOOK_URL  
# Enter your Discord webhook URL

# Environment variables are set in wrangler.toml
```

#### Step 3: Deploy Worker
```bash
# Deploy to Cloudflare
wrangler deploy

# Test the deployment
curl https://your-worker.your-subdomain.workers.dev/health/trigger-check
```

#### Step 4: Setup Custom Domain (Optional)
```bash
# Add custom domain in Cloudflare dashboard
# Update wrangler.toml with your domain
# Deploy again
wrangler deploy
```

## Configuration

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `SERVERS_JSON_URL` | URL to fetch server list | `https://servers.openadp.org/api/servers.json` |
| `GITHUB_REPO` | GitHub repo for health data | `waywardgeek/servers.openadp.org` |
| `POLL_INTERVAL_MINUTES` | How often to check servers | `5` |
| `ERROR_THRESHOLD_PERCENT` | Error rate for alerts | `15` |
| `ERROR_DURATION_MINUTES` | Duration before alerting | `30` |

### Secrets
| Secret | Description | Format |
|--------|-------------|---------|
| `GITHUB_TOKEN` | GitHub Personal Access Token | `github_pat_...` |
| `DISCORD_WEBHOOK_URL` | Discord webhook for alerts | `https://discord.com/api/webhooks/...` |

## API Documentation

### GET /health
Returns the latest health check results for all servers.

**Response:**
```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "servers": [
    {
      "url": "https://server1.openadp.org",
      "country": "US",
      "healthy": true,
      "responseTime": 45,
      "version": "1.0.0",
      "monitoring": {
        "queries_current_hour": 1245,
        "queries_last_24h": 28934,
        "uptime_start": "2024-01-15T08:00:00Z",
        "response_time_avg_ms": 45,
        "error_rate_percent": 0.2
      }
    }
  ],
  "summary": {
    "total": 4,
    "healthy": 3,
    "unhealthy": 1,
    "errors": 0
  }
}
```

### GET /health/servers
Returns server list formatted for end-user server selection.

**Response:**
```json
{
  "servers": [
    {
      "url": "https://server1.openadp.org",
      "country": "US", 
      "healthy": true,
      "responseTime": 45,
      "uptime": "2d 14h",
      "queriesPerHour": 1245,
      "errorRate": 0.2
    }
  ]
}
```

### GET /health/history?hours=24
Returns historical health data for the specified time period.

**Parameters:**
- `hours` (optional) - Number of hours of history to return (default: 24, max: 24)

**Response:**
```json
{
  "history": [
    {
      "timestamp": "2024-01-15T10:30:00.000Z",
      "servers": [...],
      "summary": {...}
    }
  ]
}
```

### POST /health/trigger-check
Manually triggers a health check of all servers (for testing).

**Response:**
Same format as `/health` endpoint.

## Health Dashboard Integration

### For End Users (Server Selection)
```javascript
// Fetch servers with health status
fetch('https://health.openadp.org/health/servers')
  .then(response => response.json())
  .then(data => {
    data.servers.forEach(server => {
      console.log(`${server.url}: ${server.healthy ? 'Healthy' : 'Down'}`);
      console.log(`  Response time: ${server.responseTime}ms`);
      console.log(`  Uptime: ${server.uptime}`);
      console.log(`  Error rate: ${server.errorRate}%`);
    });
  });
```

### For Volunteers (Detailed Monitoring)
```javascript
// Fetch detailed health data
fetch('https://health.openadp.org/health')
  .then(response => response.json())
  .then(data => {
    console.log(`Network Status: ${data.summary.healthy}/${data.summary.total} servers healthy`);
    
    data.servers.forEach(server => {
      if (!server.healthy) {
        console.error(`${server.url} is down: ${server.error}`);
      }
    });
  });

// Fetch historical data for trends
fetch('https://health.openadp.org/health/history?hours=24')
  .then(response => response.json())
  .then(data => {
    // Process historical data for charts/graphs
    data.history.forEach(snapshot => {
      console.log(`${snapshot.timestamp}: ${snapshot.summary.healthy}/${snapshot.summary.total} healthy`);
    });
  });
```

## Monitoring and Alerts

### Discord Alerts
The system sends Discord notifications for:
- **Individual server outages** - When a server goes down
- **Network-wide issues** - When >50% of servers are unhealthy
- **Rate limiting** - Alerts are limited to prevent spam

### Alert Format
```
🚨 **OpenADP Server Alert**

**Server**: https://server1.openadp.org
**Country**: US
**Status**: Down
**Error**: HTTP 500: Internal Server Error
**Time**: 2024-01-15T10:30:00.000Z

Please check the server and resolve the issue.
```

### GitHub Integration
Health data is automatically committed to the GitHub repository:
- **File location**: `health/latest.json`
- **Commit message**: `Update health data - 2024-01-15T10:30:00.000Z`
- **Public access** for transparency

## Development

### Local Testing
```bash
# Install dependencies
npm install -g wrangler

# Test locally (requires cloudflare account)
wrangler dev

# Test specific endpoints
curl http://localhost:8787/health/trigger-check
```

### Debugging
```bash
# View logs
wrangler tail

# Check KV data
wrangler kv:key list --binding=HEALTH_DATA
wrangler kv:key get --binding=HEALTH_DATA "latest"
```

### Adding New Features
1. Update `cloudflare-worker.js` with new functionality
2. Test locally with `wrangler dev`
3. Deploy with `wrangler deploy`
4. Update this documentation

## Troubleshooting

### Common Issues

**Worker not running on schedule:**
- Check cron trigger configuration in `wrangler.toml`
- Verify worker is deployed and active in Cloudflare dashboard

**GitHub commits failing:**
- Verify `GITHUB_TOKEN` has correct permissions
- Check repository name in configuration
- Review worker logs for specific error messages

**Discord alerts not sending:**
- Verify `DISCORD_WEBHOOK_URL` is correct
- Test webhook URL manually with curl
- Check Discord server webhook settings

**KV storage issues:**
- Verify KV namespace IDs in `wrangler.toml`
- Check KV namespace exists in Cloudflare dashboard
- Ensure worker has KV permissions

### Health Check Failures
If servers appear unhealthy but are actually working:
- Check server `GetServerInfo` API is responding
- Verify JSON-RPC format is correct
- Test server manually with curl:
```bash
curl -X POST https://server.openadp.org \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"GetServerInfo","params":[],"id":1}'
```

## Future Enhancements

- [ ] **Email alerts** for node operators
- [ ] **Grafana dashboard** integration
- [ ] **SLA tracking** and reporting
- [ ] **Predictive alerting** based on trends
- [ ] **Mobile app** for monitoring on-the-go

## Contributing

1. Fork the repository
2. Make changes to monitoring system
3. Test with `wrangler dev`
4. Submit pull request with description
5. Update documentation as needed

---

**For questions or support, join the OpenADP Discord community.** 