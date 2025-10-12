#!/bin/bash
set -euo pipefail

# ===== VARIABLES =====
MAVEN_VERSION="3.9.9"
SONARQUBE_VERSION="10.5.1.90531"
POSTGRES_USER="ddsonar"
POSTGRES_DB="ddsonarqube"
POSTGRES_PASSWORD="Team@123"

# ===== BETTER TRAP FOR DEBUGGING =====
trap 'echo "❌ ERROR at line $LINENO"; exit 1' ERR

echo "=========================================="
echo "  Starting SonarQube & dependencies setup"
echo "=========================================="

# ===== UPDATE SYSTEM =====
echo "=== Updating system packages ==="
sudo apt-get update -y

# ===== INSTALL BASE PACKAGES =====
echo "=== Installing base dependencies ==="
sudo apt-get install -y wget unzip curl zip gnupg lsb-release openjdk-17-jdk tar postgresql postgresql-contrib

# ===== INSTALL kubectl =====
install_kubectl() {
  if ! command -v kubectl &>/dev/null; then
    echo "Installing kubectl..."
    curl -fsSL -o kubectl "https://s3.us-west-2.amazonaws.com/amazon-eks/1.31.7/2025-04-17/bin/linux/amd64/kubectl"
    chmod +x ./kubectl
    sudo mv ./kubectl /usr/local/bin/kubectl
    echo "✓ kubectl installed"
  else
    echo "✓ kubectl already installed"
  fi
  kubectl version --client
}

# ===== INSTALL AWS CLI =====
install_aws_cli() {
  if ! command -v aws &>/dev/null; then
    echo "Installing AWS CLI v2..."
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
    unzip -o awscliv2.zip
    sudo ./aws/install
    rm -rf awscliv2.zip aws
    echo "✓ AWS CLI installed"
  else
    echo "✓ AWS CLI already installed"
  fi
  aws --version
}

# ===== INSTALL MAVEN =====
install_maven() {
  # Check if Maven is already installed with correct version
  if [ -f /opt/maven/bin/mvn ]; then
    if /opt/maven/bin/mvn -version 2>/dev/null | grep -q "$MAVEN_VERSION"; then
      echo "✓ Maven $MAVEN_VERSION already installed"
      /opt/maven/bin/mvn -version
      return 0
    else
      echo "Different Maven version found, upgrading to $MAVEN_VERSION..."
    fi
  else
    echo "Maven not found, installing $MAVEN_VERSION..."
  fi

  echo "Downloading Maven ${MAVEN_VERSION}..."
  cd /tmp
  
  # Use Apache archive for reliable downloads
  MAVEN_TAR="apache-maven-${MAVEN_VERSION}-bin.tar.gz"
  MAVEN_URL="https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/${MAVEN_TAR}"
  
  wget -nv "$MAVEN_URL" -O "$MAVEN_TAR"

  if [ ! -f "$MAVEN_TAR" ]; then
    echo "❌ Maven download failed!"
    exit 1
  fi

  echo "Extracting Maven..."
  sudo tar -xzf "$MAVEN_TAR" -C /opt/
  
  # Remove old Maven directory/symlink if exists
  if [ -d /opt/maven ] && [ ! -L /opt/maven ]; then
    echo "Removing old Maven directory..."
    sudo rm -rf /opt/maven
  elif [ -L /opt/maven ]; then
    echo "Removing old Maven symlink..."
    sudo rm -f /opt/maven
  fi
  
  # Create new symlink
  sudo ln -sfn "/opt/apache-maven-${MAVEN_VERSION}" /opt/maven
  sudo chmod -R 755 "/opt/apache-maven-${MAVEN_VERSION}"
  rm -f "$MAVEN_TAR"

  echo "Configuring Maven environment..."
  sudo tee /etc/profile.d/maven.sh > /dev/null <<EOF
export M2_HOME=/opt/maven
export MAVEN_HOME=/opt/maven
export PATH=\$M2_HOME/bin:\$PATH
EOF

  sudo chmod +x /etc/profile.d/maven.sh

  # Add to current user's bashrc
  if ! grep -q "/etc/profile.d/maven.sh" ~/.bashrc; then
    echo 'if [ -f /etc/profile.d/maven.sh ]; then source /etc/profile.d/maven.sh; fi' >> ~/.bashrc
  fi

  # Export for current session
  export M2_HOME=/opt/maven
  export MAVEN_HOME=/opt/maven
  export PATH=$M2_HOME/bin:$PATH
  
  # For GitHub Actions
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "/opt/maven/bin" >> "$GITHUB_PATH"
  fi
  
  echo "✓ Maven installed successfully"
  /opt/maven/bin/mvn -version
  
  cd - > /dev/null
}

# ===== SYSCTL CONFIG FOR ELASTICSEARCH =====
echo "=== Configuring system parameters ==="
sudo sysctl -w vm.max_map_count=262144
sudo sysctl -w fs.file-max=131072

grep -q "vm.max_map_count=262144" /etc/sysctl.conf || echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
grep -q "fs.file-max=131072" /etc/sysctl.conf || echo 'fs.file-max=131072' | sudo tee -a /etc/sysctl.conf

echo "✓ System parameters configured"

# ===== INSTALL POSTGRESQL =====
echo "=== Configuring PostgreSQL ==="

# Enable & start service
sudo systemctl enable --now postgresql

# Configure authentication
PG_HBA="$(sudo -u postgres psql -tAc "SHOW hba_file;")"
if ! sudo grep -Eq '^[[:space:]]*host[[:space:]]+all[[:space:]]+all[[:space:]]+127\.0\.0\.1/32[[:space:]]+(md5|scram-sha-256)' "$PG_HBA"; then
  echo "Configuring PostgreSQL authentication..."
  sudo sed -i '1ihost    all             all             127.0.0.1/32            md5' "$PG_HBA"
  sudo systemctl restart postgresql
fi

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
for i in {1..30}; do
  if sudo -u postgres psql -tAc "SELECT 1" >/dev/null 2>&1; then
    echo "✓ PostgreSQL is ready"
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "❌ PostgreSQL timeout"
    exit 1
  fi
done

# Create database and user
echo "Creating database and user..."
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$POSTGRES_USER'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE USER $POSTGRES_USER WITH ENCRYPTED PASSWORD '$POSTGRES_PASSWORD';"

sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$POSTGRES_DB'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_USER;"

sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO $POSTGRES_USER;"

echo "✓ PostgreSQL configured"

# ===== INSTALL SONARQUBE =====
echo "=== Installing SonarQube ==="

if [ -d "/opt/sonarqube" ] && [ -f "/opt/sonarqube/bin/linux-x86-64/sonar.sh" ]; then
  echo "✓ SonarQube already installed"
else
  sudo mkdir -p /opt/sonarqube
  
  echo "Downloading SonarQube ${SONARQUBE_VERSION}..."
  cd /tmp
  sudo wget -nv "https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-${SONARQUBE_VERSION}.zip"
  
  echo "Extracting SonarQube..."
  sudo unzip -q "sonarqube-${SONARQUBE_VERSION}.zip"
  
  echo "Installing SonarQube..."
  sudo mv "sonarqube-${SONARQUBE_VERSION}"/* /opt/sonarqube/
  sudo rmdir "sonarqube-${SONARQUBE_VERSION}"
  sudo rm "sonarqube-${SONARQUBE_VERSION}.zip"
  
  echo "✓ SonarQube extracted"
  cd - > /dev/null
fi

# Create user and group
echo "Configuring SonarQube user..."
getent group ddsonar >/dev/null || sudo groupadd ddsonar
id -u ddsonar &>/dev/null || sudo useradd --system --gid ddsonar --home /opt/sonarqube --shell /bin/false ddsonar

# Set permissions
sudo chown -R ddsonar:ddsonar /opt/sonarqube
sudo chmod +x /opt/sonarqube/bin/linux-x86-64/sonar.sh

# Configure SonarQube
echo "Configuring SonarQube..."
sudo tee /opt/sonarqube/conf/sonar.properties > /dev/null <<EOF
# Database Configuration
sonar.jdbc.username=${POSTGRES_USER}
sonar.jdbc.password=${POSTGRES_PASSWORD}
sonar.jdbc.url=jdbc:postgresql://localhost:5432/${POSTGRES_DB}

# Web Server Configuration
sonar.web.host=0.0.0.0
sonar.web.port=9000

# Elasticsearch Storage
sonar.path.data=/opt/sonarqube/data
sonar.path.temp=/opt/sonarqube/temp
EOF

sudo chmod 640 /opt/sonarqube/conf/sonar.properties
sudo chown ddsonar:ddsonar /opt/sonarqube/conf/sonar.properties

# Configure system limits
sudo tee /etc/security/limits.d/99-sonarqube.conf > /dev/null <<EOF
ddsonar   -   nofile   65536
ddsonar   -   nproc    4096
EOF

echo "✓ SonarQube configured"

# ===== CREATE SYSTEMD SERVICE =====
echo "=== Creating SonarQube service ==="
sudo tee /etc/systemd/system/sonar.service > /dev/null <<EOF
[Unit]
Description=SonarQube service
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=forking
ExecStart=/opt/sonarqube/bin/linux-x86-64/sonar.sh start
ExecStop=/opt/sonarqube/bin/linux-x86-64/sonar.sh stop
User=ddsonar
Group=ddsonar
Restart=on-failure
RestartSec=10
LimitNOFILE=65536
LimitNPROC=4096
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

echo "Starting SonarQube..."
sudo systemctl daemon-reload
sudo systemctl enable sonar.service
sudo systemctl restart sonar.service

# ===== INSTALL ADDITIONAL TOOLS =====
echo ""
echo "=== Installing additional tools ==="
install_kubectl
install_aws_cli
install_maven

# ===== VERIFY SONARQUBE =====
echo ""
echo "=== Verifying SonarQube installation ==="

# Give SonarQube time to start
sleep 10

if sudo systemctl is-active --quiet sonar.service; then
  echo "✓ SonarQube service is running"
  
  SERVER_IP=$(hostname -I | awk '{print $1}')
  
  echo ""
  echo "=========================================="
  echo "  ✅ Setup Complete!"
  echo "=========================================="
  echo ""
  echo "📊 SonarQube URL: http://${SERVER_IP}:9000"
  echo "   Login: admin / admin"
  echo ""
  echo "⚠️  IMPORTANT: SonarQube takes 30-60 seconds to fully start"
  echo ""
  echo "📝 Next Steps:"
  echo "   1. Wait 60 seconds for SonarQube to start"
  echo "   2. Access: http://${SERVER_IP}:9000"
  echo "   3. Login and change default password"
  echo "   4. Generate token: My Account > Security > Generate Token"
  echo "   5. Add GitHub Secrets:"
  echo "      • SONAR_HOST_URL: http://${SERVER_IP}:9000"
  echo "      • SONAR_TOKEN: <your-generated-token>"
  echo ""
  echo "🔍 Useful Commands:"
  echo "   • Status:  sudo systemctl status sonar.service"
  echo "   • Logs:    sudo journalctl -u sonar.service -f"
  echo "   • Restart: sudo systemctl restart sonar.service"
  echo "   • Maven:   mvn -version"
  echo ""
  echo "🔄 For new terminal sessions: source ~/.bashrc"
  echo ""
else
  echo "❌ SonarQube service failed to start"
  echo ""
  echo "Check logs: sudo journalctl -u sonar.service -xe"
  exit 1
fi