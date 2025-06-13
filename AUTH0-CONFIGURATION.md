# Auth0 Configuration for OpenADP Production

## Overview

OpenADP has been configured to use **Auth0** as the production identity provider for authentication with your distributed servers. This replaces the local Docker Keycloak that was used for development.

## Configuration Details

### Auth0 Application Settings
- **Domain**: `dev-ofq24vi3c6obh8fz.us.auth0.com`
- **Client ID**: `r1A7UEYuVIKO8fP3Oe8dAmRsLyJkgK08`
- **Application Type**: Native Application
- **Issuer URL**: `https://dev-ofq24vi3c6obh8fz.us.auth0.com/`

### Required Auth0 Configuration

Make sure your Auth0 native application has these settings:

1. **Grant Types**:
   - ✅ Device Code
   - ✅ Refresh Token

2. **Token Endpoint Authentication Method**: None (for native apps)

3. **Allowed Callback URLs**: Not needed for Device Code flow

4. **Advanced Settings** > **Grant Types**: Ensure "Device Code" is enabled

## Usage

### Production Mode (Default)
```bash
# Uses Auth0 automatically
python3 encrypt.py myfile.txt
python3 decrypt.py myfile.txt.enc
```

### Development Mode (Local Keycloak)
```bash
# Use --local-dev flag to use local Keycloak
python3 encrypt.py --local-dev myfile.txt
python3 decrypt.py --local-dev myfile.txt.enc
```

### Environment Variables (Optional)
You can override defaults with environment variables:
```bash
export OPENADP_ISSUER_URL="https://your-custom-domain.auth0.com/"
export OPENADP_CLIENT_ID="your-client-id"
```

### Custom Configuration
```bash
# Override issuer and client ID manually
python3 encrypt.py --issuer https://custom.auth0.com/ --client-id custom-client-id myfile.txt
```

## Authentication Flow

1. **Device Code Flow**: User runs encrypt/decrypt command
2. **Browser Prompt**: User is prompted to visit Auth0 URL
3. **Device Code Entry**: User enters device code in browser
4. **Auth0 Login**: User logs into Auth0 (Google, GitHub, etc.)
5. **Token Exchange**: Tool receives DPoP-bound access token
6. **Encrypted Authentication**: Token sent over Noise-NK encrypted channel to servers

## Benefits

✅ **Production Ready**: No dependency on local Docker containers  
✅ **Multi-Server Support**: Your 3 distributed servers can all authenticate against Auth0  
✅ **Social Login**: Support for Google, GitHub, email/password via Auth0  
✅ **Token Security**: DPoP binding prevents token theft/replay  
✅ **Encrypted Channels**: All authentication data encrypted end-to-end via Noise-NK  

## Troubleshooting

### Auth0 Setup Issues
- Verify Device Code grant type is enabled in Auth0 dashboard
- Check that application type is set to "Native"
- Ensure no callback URLs are required (Device Code flow doesn't use them)

### Network Issues
- Ensure your servers can reach `dev-ofq24vi3c6obh8fz.us.auth0.com`
- Check firewall rules allow outbound HTTPS (port 443)

### Authentication Failures
- Clear cached tokens: `rm -rf ~/.openadp/`
- Try with `--local-dev` flag to test local Keycloak
- Check Auth0 logs in dashboard for authentication attempts

## Next Steps

1. **Test with one server**: Try encrypt/decrypt with your production servers
2. **Configure Auth0 users**: Add users or enable social login providers
3. **Production deployment**: Deploy to all 3 servers with Auth0 configuration 