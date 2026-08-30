#cloud-config
package_update: true
package_upgrade: true

# Install dependencies
packages:
  - apt-transport-https
  - ca-certificates
  - curl
  - gnupg
  - lsb-release
  - git
  - openssl
  - jq

# Write files before running command line actions
write_files:
  # Nginx TLS Certificates (Generated locally and passed securely via OpenTofu variables)
  - path: /opt/heillmpot/certs/ca.crt
    owner: root:root
    permissions: '0644'
    content: |
      ${indent(6, ssl_ca_cert)}

  - path: /opt/heillmpot/certs/server.crt
    owner: root:root
    permissions: '0644'
    content: |
      ${indent(6, ssl_server_crt)}

  - path: /opt/heillmpot/certs/server.key
    owner: root:root
    permissions: '0600'
    content: |
      ${indent(6, ssl_server_key)}

  # Environment secrets for docker compose stack
  - path: /opt/heillmpot/.env
    owner: root:root
    permissions: '0600'
    content: |
      DB_NAME=${db_name}
      DB_USER=${db_user}
      DB_PASSWORD=${db_password}
      JWT_SECRET=${jwt_secret}
      TF_VAR_orchestrator_api_key=${orchestrator_api_key}
      
      # Local port bindings
      ORCHESTRATOR_API_PORT=8080
      ORCHESTRATOR_HTTP_PORT=80
      ORCHESTRATOR_HTTPS_PORT=443
      DASHBOARD_PORT=8090

runcmd:
  # 1. Install Docker & Docker Compose Plugin
  - mkdir -p /etc/apt/keyrings
  - curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  - echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  - apt-get update
  - apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  # 2. Clone the repository
  - git clone -b ${git_branch} ${git_repo} /app

  # 3. Inject configuration & certificates
  - cp /opt/heillmpot/.env /app/.env
  - mkdir -p /app/certs
  - cp /opt/heillmpot/certs/ca.crt /app/certs/ca.crt
  - cp /opt/heillmpot/certs/server.crt /app/certs/server.crt
  - cp /opt/heillmpot/certs/server.key /app/certs/server.key
  - chmod 600 /app/certs/server.key

  # 4. Generate DH parameters if needed, or pre-create folder structures
  - mkdir -p /app/orchestrator/config

  # 5. Start the stack (building from sources on node)
  - echo "heiLLMpot orchestrator starting..."
  - cd /app && docker compose up --build -d orchestrator dashboard nginx
  - echo "heiLLMpot orchestrator finished building and starting"
