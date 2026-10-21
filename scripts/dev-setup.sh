#!/bin/sh
set -eu
umask 077
# Creates new development-only secrets; never overwrites existing key directories.
go run ./cmd/secondfactor keygen --dir secrets
openssl rand -hex 32 > secrets/database-password
openssl rand -hex 24 > secrets/demo-password
openssl req -x509 -newkey rsa:2048 -nodes -keyout secrets/dev.key -out secrets/dev.crt -days 7 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,DNS:api,DNS:demo,IP:127.0.0.1' -addext 'basicConstraints=critical,CA:TRUE'
python3 - <<'PYTHON'
import json, pathlib, os
p=pathlib.Path('secrets');password=(p/'database-password').read_text().strip()
for suffix,host,port in [('compose','postgres',5432),('local','127.0.0.1',15433)]:
 (p/('database-url-'+suffix)).write_text(f'postgres://secondfactor:{password}@{host}:{port}/secondfactor?sslmode=disable')
 cfg={'database_url_file':'secrets/database-url-'+suffix,'listen':':8443','audience':'secondfactor-local','active_key_id':'enc1','encryption_keys':{'enc1':'secrets/encryption.key'},'service_key_id':'service1','service_key_file':'secrets/service.seed','applications':{'demo':{'issuer':'SecondFactor Example','signing_keys':{'app1':'secrets/application.seed.pub'},'event_signing_keys':{'events1':'secrets/event.seed.pub'},'callback_url':'https://demo:9443/callback' if suffix=='compose' else 'https://localhost:9443/callback','allowed_cidrs':['172.29.87.0/24'] if suffix=='compose' else ['127.0.0.1/32','::1/128'],'ca_file':'secrets/dev.crt'}},'tls_cert':'secrets/dev.crt','tls_key':'secrets/dev.key','allow_http':False}
 pathlib.Path('config.'+suffix+'.json').write_text(json.dumps(cfg,indent=2)+'\n')
pathlib.Path('.env').write_text(f'LOCAL_UID={os.getuid()}\nLOCAL_GID={os.getgid()}\n')
PYTHON
printf '%s\n' 'Development files created. Password: read secrets/demo-password locally. Do not commit secrets.'
