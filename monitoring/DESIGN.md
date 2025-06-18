# OpenADP Health Monitoring System - Design Document

## Overview

The OpenADP Health Monitoring System is designed to provide real-time visibility into the health and performance of the distributed OpenADP network. It serves two primary stakeholders: volunteer operators who manage the infrastructure, and end users who need to select trustworthy servers for their secret shares.

## Goals

### Primary Goals
1. **Volunteer Operations Dashboard**: Enable volunteers to monitor network health, respond to incidents (like DDoS attacks), and maintain service quality
2. **End User Server Selection**: Provide transparency data to help users make informed decisions about which servers to trust

### Secondary Goals
- Build trust through transparency
- Enable rapid incident response
- Provide historical performance data
- Support network growth and scaling decisions

## Architecture

### High-Level Components

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│ OpenADP Servers │    │ Cloudflare   │    │ GitHub          │
│ (GetServerInfo) │◄───┤ Worker       │───►│ (Health Data)   │
│                 │    │ (Monitor)    │    │                 │
└─────────────────┘    └──────────────┘    └─────────────────┘
                                │                    
                                ▼                    
                       ┌──────────────┐              
                       │ Cloudflare   │              
                       │ KV Store     │              
                       │ (Real-time)  │              
                       └──────────────┘              
                                │                    
                                ▼                    
                       ┌──────────────┐              
                       │ Health       │              
                       │ Dashboard    │              
                       │ (Public UI)  │              
                       └──────────────┘              
```

### Component Details

#### 1. Enhanced GetServerInfo API
**Purpose**: Extend existing server API to include monitoring metrics
**Location**: OpenADP servers (`pkg/server/`)
**Key Design Decisions**:
- Minimal overhead - reuse existing API endpoint
- Backward compatible - monitoring data is optional
- Real-time metrics collection via `MonitoringTracker`

#### 2. Cloudflare Worker Monitor
**Purpose**: Centralized monitoring service that polls all servers
**Location**: `monitoring/cloudflare-worker.js`
**Key Design Decisions**:
- Cloudflare Workers for global edge deployment
- 5-minute polling interval (balance between freshness and load)
- Parallel server health checks for efficiency
- Built-in rate limiting and error handling

#### 3. Data Storage Strategy
**Primary**: Cloudflare KV (real-time access)
**Secondary**: GitHub repository (transparency/backup)
**Key Design Decisions**:
- KV for fast global access with 1-minute cache
- GitHub for transparency and historical analysis
- 5-minute granularity for reasonable storage costs

#### 4. Alert System
**Discord Integration**: Real-time notifications for volunteers
**Key Design Decisions**:
- 15% error rate threshold over 30 minutes (avoid false positives)
- Network-wide alerts when >50% servers down
- Rate limiting to prevent alert spam

## Data Model

### Server Health Record
```json
{
  "url": "https://server.example.com",
  "country": "US",
  "healthy": true,
  "responseTime": 45,
  "timestamp": "2024-01-15T10:30:00.000Z",
  "version": "1.0.0",
  "capabilities": ["register_secret", "recover_secret", ...],
  "monitoring": {
    "queries_current_hour": 1245,
    "queries_last_24h": 28934,
    "uptime_start": "2024-01-15T08:00:00Z",
    "response_time_avg_ms": 45.2,
    "error_rate_percent": 0.2,
    "last_hour_histogram": [12, 15, 18, ...] // optional
  }
}
```

### Network Summary
```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "servers": [...], // array of server health records
  "summary": {
    "total": 4,
    "healthy": 3,
    "unhealthy": 1,
    "errors": 0
  }
}
```

## Design Decisions & Rationale

### 1. Why Cloudflare Workers?
- **Global Edge Deployment**: Monitoring from multiple geographic locations
- **Serverless**: No infrastructure to manage
- **Built-in Scheduling**: Cron triggers for regular polling
- **KV Integration**: Fast global data storage
- **Cost Effective**: Pay-per-use model suitable for this workload

### 2. Why 5-Minute Polling Interval?
- **Balance**: Fresh enough for operational needs, not too frequent to overload servers
- **Cost**: Reasonable KV write operations and worker invocations
- **Alert Timing**: Allows 30-minute error threshold with 6 data points

### 3. Why GitHub Integration?
- **Transparency**: Public access to historical health data
- **Trust**: Users can verify monitoring data independently
- **Backup**: Redundant storage for monitoring data
- **Version Control**: Track changes in network health over time

### 4. Why Extend GetServerInfo vs New Endpoint?
- **Minimal Changes**: Reuse existing authentication and infrastructure
- **Backward Compatibility**: Monitoring data is optional
- **Simplicity**: One endpoint to maintain instead of two

### 5. Why Discord for Alerts?
- **Real-time**: Instant notifications for volunteers
- **Mobile**: Discord mobile apps for on-the-go alerts
- **Community**: Aligns with existing OpenADP community platform
- **Rich Formatting**: Embed links, status indicators, etc.

## Security Considerations

### 1. Data Exposure
- **Public Monitoring Data**: Health metrics are intentionally public for transparency
- **No Sensitive Data**: No user data, secrets, or internal server details exposed
- **Rate Limiting**: Prevent abuse of monitoring endpoints

### 2. DDoS Protection
- **Cloudflare Protection**: Built-in DDoS mitigation for monitoring infrastructure
- **Request Histogram**: Optional data to help identify attack patterns
- **Alert System**: Rapid notification for coordinated response

### 3. Authentication
- **Read-Only**: Public monitoring endpoints require no authentication
- **Write Operations**: GitHub commits require token authentication
- **Alert Configuration**: Discord webhook URLs kept as secrets

## Scalability Considerations

### 1. Server Growth
- **Parallel Processing**: Worker handles multiple servers concurrently
- **KV Scaling**: Cloudflare KV scales automatically
- **Cost Model**: Linear scaling with number of servers

### 2. Data Retention
- **KV Storage**: Keep latest + 24 hours of history (288 records max)
- **GitHub Storage**: Long-term historical data
- **Cleanup**: Automatic pruning of old KV data

### 3. Geographic Distribution
- **Edge Deployment**: Monitoring from multiple Cloudflare edge locations
- **Regional Servers**: Can monitor servers worldwide efficiently

## Monitoring the Monitor

### 1. Worker Health
- **Cloudflare Analytics**: Worker execution metrics and errors
- **GitHub Commits**: Verify continuous operation via commit history
- **Discord Alerts**: Self-monitoring alerts if worker fails

### 2. Data Quality
- **Timestamp Validation**: Ensure fresh data in KV store
- **Server Response Validation**: Check for malformed responses
- **Alert Validation**: Test alert system periodically

## Future Enhancements

### 1. Advanced Analytics
- **Trend Analysis**: Identify patterns in server performance
- **Predictive Alerts**: Alert before servers become unhealthy
- **SLA Tracking**: Formal uptime guarantees and reporting

### 2. Enhanced Dashboards
- **Grafana Integration**: Advanced visualization and alerting
- **Mobile App**: Dedicated mobile app for volunteers
- **Historical Analysis**: Deep dive into long-term trends

### 3. Additional Integrations
- **Email Alerts**: For node operators when their servers are down
- **Slack Integration**: Alternative to Discord for some teams
- **PagerDuty**: Enterprise-grade incident management

## Implementation Timeline

### Phase 1: Core Monitoring (Completed)
- ✅ Enhanced GetServerInfo API
- ✅ Cloudflare Worker implementation
- ✅ Basic health dashboard
- ✅ Discord alerts

### Phase 2: Production Deployment (Next)
- Deploy Cloudflare Worker
- Configure environment variables
- Set up custom domain
- Test end-to-end functionality

### Phase 3: Optimization (Future)
- Performance tuning based on real-world usage
- Enhanced error handling and edge cases
- Additional metrics and insights

## Success Metrics

### Operational
- **MTTR**: Mean time to resolution for server issues
- **Alert Accuracy**: Ratio of actionable vs false positive alerts
- **Volunteer Response Time**: How quickly issues are addressed

### User Experience
- **Dashboard Usage**: Number of users checking server health
- **Server Selection**: Distribution of user choices across servers
- **Trust Metrics**: User feedback on transparency

### Technical
- **System Uptime**: Monitoring system availability
- **Data Freshness**: Percentage of up-to-date health data
- **Performance**: Response times for dashboard and APIs

---

This design provides a robust, scalable foundation for OpenADP network monitoring while maintaining simplicity and cost-effectiveness. 