import json
import sys
import os

dir_path = sys.argv[1]
with open(os.path.join(dir_path, 'metadata.json')) as f:
    meta = json.load(f)
with open(os.path.join(dir_path, 'routes.json')) as f:
    routes = json.load(f)
with open(os.path.join(dir_path, 'tls.json')) as f:
    tls = json.load(f)
with open(os.path.join(dir_path, 'ssh_profile.json')) as f:
    ssh = json.load(f)

site = {
    "site_id": meta.get("site_id", "unknown"),
    "model": meta.get("model", "unknown"),
    "app_spec": {
        "app_name": meta.get("app_name", ""),
        "domain": meta.get("domain", ""),
    },
    "server_profile": meta.get("server_profile", ""),
    "tls": tls,
    "ssh_profile": ssh,
    "routes": {}
}

for path, info in routes.items():
    site["routes"][path] = {}
    for method, body in info.get("responses", {}).items():
        site["routes"][path][method] = body

with open(sys.argv[2], 'w') as f:
    json.dump(site, f)
