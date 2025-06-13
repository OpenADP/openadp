#!/bin/bash
set -e

# Configuration
KEYCLOAK_URL="http://localhost:8080"
ADMIN_USER="admin"
ADMIN_PASS="admin"
REALM_NAME="openadp"
CLIENT_ID="cli-test"

echo "🔧 Setting up OpenADP realm in Keycloak..."

# Wait for Keycloak to be ready
echo "⏳ Waiting for Keycloak to be ready..."
while ! curl -s "${KEYCLOAK_URL}/health/ready" > /dev/null; do
    echo "Waiting for Keycloak..."
    sleep 5
done
echo "✅ Keycloak is ready!"

# Get admin token
echo "🔑 Getting admin token..."
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${ADMIN_USER}" \
    -d "password=${ADMIN_PASS}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "❌ Failed to get admin token"
    exit 1
fi
echo "✅ Got admin token"

# Create realm
echo "🏰 Creating OpenADP realm..."
curl -s -X POST "${KEYCLOAK_URL}/admin/realms" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "realm": "'${REALM_NAME}'",
        "enabled": true,
        "displayName": "OpenADP",
        "accessTokenLifespan": 300,
        "refreshTokenMaxReuse": 0,
        "ssoSessionIdleTimeout": 7776000,
        "ssoSessionMaxLifespan": 7776000,
        "offlineSessionIdleTimeout": 7776000,
        "offlineSessionMaxLifespanEnabled": true,
        "offlineSessionMaxLifespan": 7776000
    }' || echo "Realm might already exist"

# Create public client for CLI
echo "📱 Creating CLI client..."
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "clientId": "'${CLIENT_ID}'",
        "name": "OpenADP CLI Client",
        "enabled": true,
        "publicClient": true,
        "standardFlowEnabled": false,
        "directAccessGrantsEnabled": false,
        "serviceAccountsEnabled": false,
        "attributes": {
            "oauth2.device.authorization.grant.enabled": "true"
        },
        "redirectUris": ["http://localhost:*"],
        "webOrigins": ["http://localhost:*"]
    }' || echo "Client might already exist"

# Create test users
echo "👥 Creating test users..."

# User 1: alice
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "alice",
        "email": "alice@example.com",
        "firstName": "Alice",
        "lastName": "Test",
        "enabled": true,
        "emailVerified": true,
        "credentials": [{
            "type": "password",
            "value": "password123",
            "temporary": false
        }]
    }' || echo "User alice might already exist"

# User 2: bob
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "bob",
        "email": "bob@example.com",
        "firstName": "Bob",
        "lastName": "Test",
        "enabled": true,
        "emailVerified": true,
        "credentials": [{
            "type": "password",
            "value": "password123",
            "temporary": false
        }]
    }' || echo "User bob might already exist"

echo ""
echo "🎉 Keycloak setup complete!"
echo ""
echo "📋 Configuration Summary:"
echo "  Keycloak URL: ${KEYCLOAK_URL}"
echo "  Admin Console: ${KEYCLOAK_URL}/admin"
echo "  Admin User: ${ADMIN_USER}"
echo "  Admin Password: ${ADMIN_PASS}"
echo ""
echo "  Realm: ${REALM_NAME}"
echo "  Client ID: ${CLIENT_ID}"
echo "  Test Users: alice/password123, bob/password123"
echo ""
echo "🔗 Important URLs:"
echo "  OIDC Discovery: ${KEYCLOAK_URL}/realms/${REALM_NAME}/.well-known/openid-configuration"
echo "  JWKS: ${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/certs"
echo "  Device Auth: ${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/auth/device"
echo "  Token Endpoint: ${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/token"
echo "" 