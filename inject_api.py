import json
import os

site_dir = "/root/heiLLMpot/generated_sites/northminster_bank_plc_c2123b3a-d03c-4ce2-bd38-7bdff4ccefd6"
api_routes_file = os.path.join(site_dir, "api_routes.json")

with open(api_routes_file, "r") as f:
    api = json.load(f)

# Inject vulnerable API endpoint
api["/api/v1/users/{id}"] = {
    "auth_required": False,
    "idor_enabled": True,
    "user_responses": {
        "1": {"id": 1, "username": "admin", "role": "admin"},
        "2": {"id": 2, "username": "guest", "role": "user"}
    }
}

with open(api_routes_file, "w") as f:
    json.dump(api, f, indent=4)

print("Injected /api/v1/users/{id} into api_routes.json")
