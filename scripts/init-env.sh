#!/bin/sh
# Creates .env with fresh random secrets and copies the example configs. It never
# overwrites existing files. .env and config/*.yaml (other than the examples) are
# ignored by git.
set -eu
cd "$(dirname "$0")/.."

rand() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }

if [ -e .env ]; then
  echo ".env already exists, leaving it alone"
else
  (
    umask 077
    {
      echo "SWEETCAPTCHA_MASTER_KEY=$(rand 32)"
      echo "SWEETCAPTCHA_ADMIN_TOKEN=$(rand 24)"
      echo "SWEETCAPTCHA_DEMO_SECRET=$(rand 24)"
      echo "SWEETCAPTCHA_DEMO_STRICT_SECRET=$(rand 24)"
    } > .env
  )
  echo "created .env"
fi
# The configs hold only ${VAR} references, and the container user must read them.
for name in sweetcaptcha sweetcaptcha.strict; do
  if [ ! -e "config/$name.yaml" ]; then
    cp "config/$name.example.yaml" "config/$name.yaml"
    chmod 644 "config/$name.yaml"
  fi
done
echo "ready: docker compose up -d --build, then open http://localhost:8787/demo/"
