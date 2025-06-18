# Setting up health.openadp.org Custom Domain ✅ COMPLETED

**🎉 SUCCESS: The custom domain is now live at https://health.openadp.org/**

This guide walks you through setting up `health.openadp.org` as a custom domain for the OpenADP Health Monitoring dashboard.

## Prerequisites

- ✅ **Cloudflare Workers** deployed and working
- ✅ **Domain ownership** of `openadp.org` 
- ✅ **Cloudflare account** with the domain managed

## Method 1: Cloudflare Dashboard (Recommended)

### Step 1: Add Custom Domain in Cloudflare Dashboard

1. **Go to Cloudflare Dashboard**: https://dash.cloudflare.com
2. **Select your account** (the one with the Worker)
3. **Navigate to Workers & Pages** → **Overview**
4. **Click on your worker**: `openadp-health-monitor`
5. **Go to Settings** → **Triggers** → **Custom Domains**
6. **Click "Add Custom Domain"**
7. **Enter domain**: `health.openadp.org`
8. **Click "Add Domain"**

Cloudflare will automatically:
- ✅ Generate SSL certificate
- ✅ Set up DNS records
- ✅ Configure routing

### Step 2: DNS Configuration

If `openadp.org` is **managed by Cloudflare**:
- DNS records are automatically created
- No action needed!

If `openadp.org` is **managed elsewhere**:
- Add CNAME record: `health.openadp.org` → `openadp-health-monitor.waywardgeek.workers.dev`
- Or follow Cloudflare's specific DNS instructions

### Step 3: Verification

Wait 5-10 minutes, then test:

```bash
# Test the custom domain
curl https://health.openadp.org/health

# Should return the same JSON as:
curl https://openadp-health-monitor.waywardgeek.workers.dev/health
```

## Method 2: DNS CNAME Only (Alternative)

If you prefer a simple CNAME without Cloudflare's custom domain features:

### DNS Configuration

Add this CNAME record in your DNS provider:

```
Name: health
Type: CNAME  
Value: openadp-health-monitor.waywardgeek.workers.dev
TTL: 300 (or Auto)
```

**Pros:**
- ✅ Simple setup
- ✅ Works with any DNS provider

**Cons:**
- ❌ Shows Workers URL in browser redirects
- ❌ No automatic SSL certificate management
- ❌ Less control over routing

## Method 3: Cloudflare Zone Setup (Advanced)

If `openadp.org` is not yet on Cloudflare:

### Step 1: Add Domain to Cloudflare

1. **Go to Cloudflare Dashboard**
2. **Click "Add a Site"**
3. **Enter**: `openadp.org`
4. **Select plan** (Free is fine)
5. **Review DNS records**
6. **Update nameservers** at your registrar

### Step 2: Follow Method 1

Once the domain is active on Cloudflare, follow Method 1 above.

## Verification & Testing

### Health Check URLs

Once set up, these URLs should work:

```bash
# Main dashboard
https://health.openadp.org/

# API endpoints  
https://health.openadp.org/health
https://health.openadp.org/health/servers
https://health.openadp.org/health/trigger-check
https://health.openadp.org/health/history?hours=24
```

### SSL Certificate Check

```bash
# Verify SSL certificate
curl -I https://health.openadp.org/

# Should show:
# HTTP/2 200 
# server: cloudflare
```

### DNS Propagation Check

```bash
# Check DNS resolution
nslookup health.openadp.org

# Or use online tools:
# - https://www.whatsmydns.net/
# - https://dnschecker.org/
```

## Troubleshooting

### Common Issues

**1. "Domain not found" error**
- Wait 5-10 minutes for DNS propagation
- Check DNS records are correct
- Verify domain spelling

**2. SSL certificate errors**
- Wait up to 24 hours for certificate generation
- Check domain is properly configured in Cloudflare
- Try HTTP first, then HTTPS

**3. Worker not responding**
- Verify worker is deployed and working at original URL
- Check custom domain configuration in dashboard
- Review worker logs: `wrangler tail`

**4. DNS propagation delays**
- Can take up to 48 hours globally
- Test from different locations/networks
- Use DNS checker tools

### Getting Help

If you encounter issues:

1. **Check Cloudflare Dashboard** for any error messages
2. **Review DNS settings** in your domain registrar
3. **Test original Worker URL** to ensure it's working
4. **Contact Cloudflare Support** for custom domain issues

## Security Considerations

### HTTPS Only

The custom domain automatically enforces HTTPS:
- HTTP requests redirect to HTTPS
- Modern SSL/TLS certificates
- Perfect Forward Secrecy

### CORS Headers

The worker includes proper CORS headers for:
- Cross-origin API access
- Browser-based integrations
- Mobile app compatibility

## Performance Benefits

Custom domain provides:
- ✅ **Faster DNS resolution** (Cloudflare's global network)
- ✅ **Edge caching** for static assets
- ✅ **Global CDN** distribution
- ✅ **DDoS protection** built-in

## Next Steps

Once `health.openadp.org` is working:

1. **Update documentation** with the new URL
2. **Share with community** for testing
3. **Monitor performance** via Cloudflare Analytics
4. **Consider additional subdomains** (e.g., `api.openadp.org`)

---

**Need help?** Feel free to ask in the OpenADP Discord community! 