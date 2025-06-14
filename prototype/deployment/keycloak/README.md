# Keycloak Deployment for OpenADP

This directory contains the deployment configuration for running Keycloak as the Identity Provider (IdP) for OpenADP's distributed authentication system.

## 🎯 Purpose

Keycloak serves as the central authentication server for the OpenADP network, providing:
- **OAuth 2.0 + PKCE** authentication flows
- **DPoP (Proof-of-Possession)** token binding
- **JWT token issuance** with user identity claims
- **WebAuthn/Passkey** support (future)

## 📁 Files

- **`docker-compose.keycloak.yml`** - Docker Compose configuration with PostgreSQL backend
- **`keycloak.env.example`** - Environment variables template (copy to `.env`)
- **`setup-keycloak.sh`** - Automated deployment script
- **`cloudflare-tunnel-config.yml`** - Example Cloudflare tunnel configuration
- **`README.md`** - This file

## 🚀 Quick Deployment

### Prerequisites
- Docker and Docker Compose installed
- Cloudflare tunnel configured (optional, for public access)

### Deploy to Server

```bash
# 1. Clone the project and navigate to deployment directory
git clone https://github.com/your-org/openadp.git
cd openadp/prototype/deployment/keycloak

# 2. Run the setup script
./setup-keycloak.sh

# 3. Note the generated admin password
# 4. Configure your Cloudflare tunnel (if using)
```

### Manual Deployment

```bash
# 1. Create environment file
cp keycloak.env.example .env
# Edit .env with secure passwords

# 2. Start services
docker-compose -f docker-compose.keycloak.yml up -d

# 3. Check status
docker-compose -f docker-compose.keycloak.yml ps
```

## 🌐 Access

- **Local**: `http://localhost:8081`
- **Public**: `https://auth.openadp.org` (with Cloudflare tunnel)
- **Admin Console**: `/admin` (username: `admin`)

## ⚙️ Configuration

### Keycloak Setup

1. **Access admin console**: `https://auth.openadp.org/admin`
2. **Create realm**: `openadp`
3. **Create client**: `cli-test`
4. **Configure client**:
   - Client ID: `cli-test`
   - Client Protocol: `openid-connect`
   - Access Type: `public`
   - Standard Flow Enabled: `ON`
   - Valid Redirect URIs: `http://localhost:8888/callback`, `http://localhost:8889/callback`
   - DPoP Bound Access Tokens: `ON`
   - PKCE Code Challenge Method: `S256`

### Environment Variables

Key settings in `.env`:
- `DB_PASSWORD` - PostgreSQL database password
- `ADMIN_PASSWORD` - Keycloak admin password
- `JAVA_OPTS_APPEND` - JVM memory settings (adjust for your hardware)

## 🔧 Management Commands

```bash
# View logs
docker-compose -f docker-compose.keycloak.yml logs -f

# Restart services
docker-compose -f docker-compose.keycloak.yml restart

# Stop services
docker-compose -f docker-compose.keycloak.yml down

# Update images
docker-compose -f docker-compose.keycloak.yml pull
docker-compose -f docker-compose.keycloak.yml up -d
```

## 🔒 Security Notes

- **Change default passwords** in `.env` file
- **Use HTTPS** in production (handled by Cloudflare tunnel)
- **Regular backups** of PostgreSQL data volume
- **Monitor logs** for authentication attempts
- **Update images** regularly for security patches

## 🌍 Production Deployment

For production OpenADP networks:

1. **Use managed PostgreSQL** (AWS RDS, Google Cloud SQL, etc.)
2. **Enable SSL/TLS** termination
3. **Configure backup strategy** for Keycloak data
4. **Set up monitoring** (Prometheus metrics enabled)
5. **Use secrets management** (Kubernetes secrets, HashiCorp Vault, etc.)

## 📊 Monitoring

Keycloak exposes metrics at:
- **Health**: `/health`
- **Metrics**: `/metrics` (Prometheus format)

## 🆘 Troubleshooting

### Common Issues

**Services won't start:**
```bash
# Check logs
docker-compose -f docker-compose.keycloak.yml logs

# Check disk space
df -h

# Check memory usage
free -h
```

**Can't access admin console:**
- Verify port 8081 is accessible
- Check Cloudflare tunnel configuration
- Verify admin password in `.env` file

**Database connection errors:**
- Check PostgreSQL container health
- Verify database credentials in `.env`
- Check Docker network connectivity

## 🔗 Integration

Once deployed, update OpenADP clients to use:
```bash
--issuer https://auth.openadp.org/realms/openadp
```

## 📚 References

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [OpenADP Authentication Design](../../../docs/authn-authz-design.md) 