import json
import os

site_dir = "/root/heiLLMpot/generated_sites/northminster_bank_plc_c2123b3a-d03c-4ce2-bd38-7bdff4ccefd6"
routes_file = os.path.join(site_dir, "routes.json")

with open(routes_file, "r") as f:
    routes = json.load(f)

# Inject WP Login route
routes["/wp-login.php"] = {
    "GET": "<!DOCTYPE html><html><head><title>WordPress &rsaquo; Log In</title></head><body><form name='loginform' id='loginform' action='/wp-login.php' method='post'><p><label for='user_login'>Username</label><br /><input type='text' name='log' id='user_login' class='input' value='' size='20' /></p><p><label for='user_pass'>Password</label><br /><input type='password' name='pwd' id='user_pass' class='input' value='' size='20' /></p><p><input type='submit' name='wp-submit' id='wp-submit' class='button button-primary button-large' value='Log In' /></p></form></body></html>",
    "POST": "<!DOCTYPE html><html><head><title>WordPress &rsaquo; Error</title></head><body><div id='login_error'><strong>ERROR</strong>: The password you entered for the username is incorrect.</div></body></html>",
    "auth_required": False
}

with open(routes_file, "w") as f:
    json.dump(routes, f, indent=4)

print("Injected /wp-login.php into routes.json")
