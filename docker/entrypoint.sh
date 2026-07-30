#!/bin/bash
#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

set -e

echo "=========================================="
echo "  Starting LogstashAgent"
echo "=========================================="

# LOGSTASH_URL / LOGSTASH_UI_URL set via compose or Dockerfile ENV
echo "LOGSTASH_URL: ${LOGSTASH_URL:-unset}"
echo "LOGSTASH_UI_URL: ${LOGSTASH_UI_URL:-unset}"

# Ensure log directory exists and has proper permissions
echo "Setting up log directory..."
mkdir -p /var/log/logstash
chmod 755 /var/log/logstash

# Verify log4j2.properties exists
if [ -f /etc/logstash/log4j2.properties ]; then
    echo "+ log4j2.properties found at /etc/logstash/log4j2.properties"
else
    echo "- WARNING: log4j2.properties not found!"
fi

# logstashagent will start and supervise Logstash via Python
echo "Starting agent FastAPI (HTTPS when product-CA cert is issued)..."
echo "=========================================="
echo "  LogstashAgent starting..."
echo "  - Logstash supervised by agent (embedded)"
echo "  - Logstash API: http://localhost:9560"
echo "  - Simulation HTTP Input: http://localhost:9449"
echo "  - Agent API: https://localhost:9500 (TLS when cert ready)"
echo "=========================================="

cd /app
# Use package main so server cert issue + uvicorn SSL kwargs apply
# (bare uvicorn logstashagent.main:app would stay HTTP-only)
export PYTHONPATH="${PYTHONPATH:-/app/src}"
exec python3 -m logstashagent.main --mode embedded
