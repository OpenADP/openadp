#!/bin/bash

# OpenADP Keycloak Setup Script for Raspberry Pi
# This script sets up Keycloak with PostgreSQL for auth.openadp.org

set -e

echo "🚀 Setting up Keycloak for OpenADP on Raspberry Pi"
echo "=================================================="

# Check if running on Pi
if ! grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
    echo "⚠️  Warning: This doesn't appear to be a Raspberry Pi"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check Docker installation
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first:"
    echo "   curl -fsSL https://get.docker.com -o get-docker.sh"
    echo "   sudo sh get-docker.sh"
    echo "   sudo usermod -aG docker $USER"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Installing..."
    sudo apt update
    sudo apt install -y docker-compose
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cp keycloak.env.example .env
    
    # Generate secure passwords
    DB_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    ADMIN_PASS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)
    
    sed -i "s/your-secure-db-password-here/$DB_PASS/" .env
    sed -i "s/your-secure-admin-password-here/$ADMIN_PASS/" .env
    
    echo "✅ Generated secure passwords in .env file"
    echo "📋 Admin password: $ADMIN_PASS"
    echo "   (Save this password - you'll need it to access Keycloak admin)"
else
    echo "✅ Using existing .env file"
fi

# Create data directories
echo "📁 Creating data directories..."
sudo mkdir -p /opt/keycloak/{data,logs}
sudo chown -R $USER:$USER /opt/keycloak

# Pull images
echo "📦 Pulling Docker images..."
docker-compose -f docker-compose.keycloak.yml pull

# Start services
echo "🚀 Starting Keycloak services..."
docker-compose -f docker-compose.keycloak.yml up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check health
echo "🔍 Checking service health..."
if docker-compose -f docker-compose.keycloak.yml ps | grep -q "Up (healthy)"; then
    echo "✅ Keycloak is running and healthy!"
else
    echo "⚠️  Services are starting but may not be fully ready yet"
    echo "   Check status with: docker-compose -f docker-compose.keycloak.yml ps"
fi

# Display connection info
echo ""
echo "🎉 Keycloak Setup Complete!"
echo "=========================="
echo "🌐 Local URL: http://localhost:8081"
echo "🌍 Public URL: https://auth.openadp.org (once Cloudflare tunnel is configured)"
echo "👤 Admin User: admin"
echo "🔑 Admin Password: $(grep ADMIN_PASSWORD .env | cut -d'=' -f2)"
echo ""
echo "📋 Next Steps:"
echo "1. Configure your Cloudflare tunnel to route auth.openadp.org to localhost:8081"
echo "2. Access the admin console and create the 'openadp' realm"
echo "3. Configure the 'cli-test' client with DPoP support"
echo ""
echo "🔧 Useful Commands:"
echo "   View logs: docker-compose -f docker-compose.keycloak.yml logs -f"
echo "   Stop: docker-compose -f docker-compose.keycloak.yml down"
echo "   Restart: docker-compose -f docker-compose.keycloak.yml restart"
echo ""
echo "📊 Monitor with: docker-compose -f docker-compose.keycloak.yml ps" 