-- Test file for env_loader.lua
local env_loader = require("../env_loader")

print("Testing env_loader module...")

-- Test loading environment variables
local recaptcha_key = env_loader.get_recaptcha_site_key()
print("RECAPTCHA_V3_SITE_KEY:", recaptcha_key)

local base_url = env_loader.get_base_url()
print("BASE_URL:", base_url)

local debug_mode = env_loader.is_debug_mode()
print("DEBUG:", debug_mode)

-- Validate that keys are properly loaded
if recaptcha_key == "YOUR_RECAPTCHA_SITE_KEY_HERE" then
  print("[WARN] reCAPTCHA site key is not properly configured")
else
  print("[INFO] reCAPTCHA site key is configured")
end

print("env_loader test completed")
