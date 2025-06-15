# Keycloak HTTPS Proxy Configuration

This document summarizes all the configuration changes made to support Keycloak running behind Cloudflare's HTTPS proxy.

## Problem

Keycloak was configured to run on HTTP internally but needed to advertise HTTPS URLs in its discovery document since clients access it through `https://auth.openadp.org` via Cloudflare.

## Solution

Configure Keycloak to know it's behind an HTTPS proxy so it advertises the correct URLs.

## Files Updated

### 1. `setup-openadp-realm.py`
**Changes:**
- Updated default `KEYCLOAK_URL` to use environment variable with `https://auth.openadp.org` fallback
- Updated default admin password to production value
- Added `forceBackendUrlToFrontendUrl: "true"` to realm attributes
- Enhanced hostname configuration

**Key Configuration:**
```python
"sslRequired": "external",
"attributes": {
    "frontendUrl": "https://auth.openadp.org",
    "forceBackendUrlToFrontendUrl": "true",
    "hostname": "auth.openadp.org",
    "hostnameStrict": "true",
    "hostnameStrictHttps": "true"
}
```

### 2. `recreate-realm.py`
**Changes:**
- Updated default `KEYCLOAK_URL` to use environment variable
- Changed `sslRequired` from "none" to "external"
- Added complete proxy-aware realm attributes

### 3. `fix-realm.py`
**Changes:**
- Updated default `KEYCLOAK_URL` to use environment variable

### 4. `fix-proxy-config.py` (NEW)
**Purpose:** Script to fix existing realm configuration for HTTPS proxy
**Key Features:**
- Tests current discovery endpoint
- Updates realm configuration with proxy-aware settings
- Validates that HTTPS URLs are advertised after changes

### 5. `keycloak.env.example`
**Changes:**
- Added `KEYCLOAK_URL` environment variable
- Documented options for local vs production deployment

### 6. `docker-compose.keycloak.yml`
**Changes:**
- Added Keycloak proxy configuration environment variables:
  - `KC_PROXY: "edge"` - Tells Keycloak it's behind a proxy
  - `KC_HOSTNAME: "auth.openadp.org"` - Sets the external hostname
  - `KC_HOSTNAME_STRICT_HTTPS: "true"` - Enforces HTTPS in URLs

### 7. `cloudflare-tunnel-config.yml`
**Changes:**
- Added proxy headers to forward proper information to Keycloak:
  - `X-Forwarded-Proto: https`
  - `X-Forwarded-For: $remote_addr`
  - `X-Forwarded-Host: auth.openadp.org`

## Environment Variables

All scripts now support environment variable configuration:

```bash
# For production (default)
export KEYCLOAK_URL=https://auth.openadp.org
export ADMIN_PASSWORD=mZMENyzLWI0g

# For local development
export KEYCLOAK_URL=http://localhost:8081
export ADMIN_PASSWORD=admin
```

## Testing

After applying these changes, test with:

```bash
# Test discovery endpoint
curl -s "https://auth.openadp.org/realms/openadp/.well-known/openid-configuration" | jq '.issuer, .token_endpoint'

# Should return HTTPS URLs:
# "https://auth.openadp.org/realms/openadp"
# "https://auth.openadp.org/realms/openadp/protocol/openid-connect/token"
```

## Deployment Steps

1. **Update Keycloak Configuration:**
   ```bash
   cd prototype/deployment/keycloak
   python fix-proxy-config.py
   ```

2. **For New Deployments:**
   - Use updated `docker-compose.keycloak.yml`
   - Use updated Cloudflare tunnel config
   - Run `setup-openadp-realm.py` with environment variables

3. **Test Authentication:**
   ```bash
   cd prototype/tools
   python encrypt.py test.txt --password test123
   ```

## Key Insights

1. **Keycloak Proxy Settings:** The `KC_PROXY=edge` setting tells Keycloak to trust proxy headers
2. **Frontend URL:** Must be set to the external HTTPS URL clients will use
3. **Force Backend to Frontend:** Ensures all URLs use the frontend URL
4. **Cloudflare Headers:** Must forward the proper protocol and host information

## Troubleshooting

If authentication still fails:

1. Check discovery endpoint returns HTTPS URLs
2. Verify Cloudflare tunnel is forwarding headers
3. Restart Keycloak after configuration changes
4. Check Keycloak logs for proxy-related errors

## Success Criteria

✅ Discovery document returns HTTPS URLs  
✅ Client authentication works through Cloudflare  
✅ No 405 Method Not Allowed errors  
✅ Token exchange succeeds  

This configuration ensures that Keycloak properly handles being behind an HTTPS proxy while running on HTTP internally. 