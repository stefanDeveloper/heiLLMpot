#cloud-config
# ──────────────────────────────────────────────────────────────────────────────
# heiLLMpot honeybot — cloud-init bootstrap
#
# This script runs once on first boot.  It:
#   1. Installs Docker and helper tools.
#   2. Registers the node with the orchestrator API to obtain a JWT.
#   3. Writes the honeybot configuration file.
#   4. Starts the honeybot container.
# ──────────────────────────────────────────────────────────────────────────────

package_update: true

packages:
  - docker.io
  - curl
  - jq

write_files:
  - path: /app/certs/ca.crt
    owner: root:root
    permissions: '0644'
    content: |
      ${indent(6, ssl_ca_cert)}

  - path: /app/certs/client.crt
    owner: root:root
    permissions: '0644'
    content: |
      ${indent(6, ssl_client_crt)}

  - path: /app/certs/client.key
    owner: root:root
    permissions: '0600'
    content: |
      ${indent(6, ssl_client_key)}

runcmd:
  # ── Enable Docker ──────────────────────────────────────────────────────────
  - systemctl enable docker
  - systemctl start docker

  # ── Create application directories ─────────────────────────────────────────
  - mkdir -p /app/config /app/generated_sites /app/certs /app/logs

  # ── Register with the orchestrator ─────────────────────────────────────────
  - |
    while true; do
      RESPONSE=$(curl -skf --cacert /app/certs/ca.crt --cert /app/certs/client.crt --key /app/certs/client.key \
        -X POST "${orchestrator_url}/api/v1/nodes/register" \
        -H "Content-Type: application/json" \
        -d "{
          \"node_id\": \"${node_id}\",
          \"region\":  \"${region}\",
          \"api_key\": \"${api_key}\"
        }")

      if [ $? -eq 0 ]; then
        JWT_TOKEN=$(echo "$RESPONSE" | jq -r '.jwt_token // empty')
        if [ -n "$JWT_TOKEN" ]; then
          break
        fi
      fi
      
      echo "Orchestrator is not ready, honeybots are waiting..."
      sleep 60
    done

    echo "$JWT_TOKEN" > /app/config/honeypot.token
    echo "[heiLLMpot] Node registered successfully: ${node_id}"

  # ── Write honeybot configuration ───────────────────────────────────────────
  - |
    cat > /app/config/honeypot.json <<HONEYCFG
    {
      "log_file": "/app/logs/honeypot.jsonl",
      "http": {
        "enabled": true,
        "listen_addr": "0.0.0.0",
        "http_port": 8081,
        "https_port": 8443,
        "enable_https": true,
        "sites_dir": "/app/generated_sites",
        "fingerprint_profile": "apache_2_4",
        "jitter_min_ms": 20,
        "jitter_max_ms": 200,
        "active_site": "${active_site}"
      },
      "ssh": {
        "enabled": ${ssh_enabled},
        "listen_addr": "0.0.0.0",
        "port": 2222
      },
      "orchestrator": {
        "enabled": true,
        "url": "${orchestrator_url}",
        "node_id": "${node_id}",
        "jwt_token": "$JWT_TOKEN",
        "client_cert": "/app/certs/client.crt",
        "client_key": "/app/certs/client.key",
        "ca_cert": "/app/certs/ca.crt",
        "batch_size": 50,
        "flush_interval_sec": 10,
        "max_retries": 3
      }
    }
    HONEYCFG

  # ── Start the honeybot container ───────────────────────────────────────────
  - |
    echo "Honeybots are pulling the image now..."
    docker pull ${honeybot_image}

    docker run -d \
      --name honeybot \
      --restart unless-stopped \
      -p 80:8081 \
      -p 443:8443 \
      -p 2222:2222 \
      -v /app/config/honeypot.json:/app/config/honeypot.json:ro \
      -v /app/generated_sites:/app/generated_sites:ro \
      -v /app/logs:/app/logs \
      -v /app/certs:/app/certs:ro \
      ${honeybot_image}

    echo "[heiLLMpot] Honeybot container started for node: ${node_id}"

final_message: "heiLLMpot honeybot bootstrap complete for node ${node_id}."
