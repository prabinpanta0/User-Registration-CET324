-- env_loader.lua
-- Module to load environment variables from .env file for Lapis frontend

local env_loader = {}
local cached_env = {}

-- Function to load .env file
local function load_env_file(filename)
  filename = filename or ".env"
  local file = io.open(filename, "r")
  if not file then
    print("[WARN] Could not open " .. filename .. " file")
    return {}
  end
  
  local env_vars = {}
  for line in file:lines() do
    -- Skip empty lines and comments
    if line:match("^%s*$") or line:match("^%s*#") then
      goto continue
    end
    
    -- Parse KEY=VALUE format
    local key, value = line:match("^%s*([^=]+)%s*=%s*(.*)%s*$")
    if key and value then
      -- Remove quotes if present
      value = value:gsub("^[\"'](.*)([\"'])$", "%1")
      env_vars[key] = value
    end
    ::continue::
  end
  
  file:close()
  return env_vars
end

-- Get environment variable with fallback to .env file
function env_loader.get(key, default)
  -- First check if already cached
  if cached_env[key] then
    return cached_env[key]
  end
  
  -- Check system environment
  local value = os.getenv(key)
  if value then
    cached_env[key] = value
    return value
  end
  
  -- If not cached, load .env file
  if not cached_env._loaded then
    local env_vars = load_env_file(".env")
    for k, v in pairs(env_vars) do
      cached_env[k] = v
    end
    cached_env._loaded = true
  end
  
  -- Return from cache or default
  return cached_env[key] or default
end

-- Get reCAPTCHA site key
function env_loader.get_recaptcha_site_key()
  return env_loader.get("RECAPTCHA_V3_SITE_KEY", "YOUR_RECAPTCHA_SITE_KEY_HERE")
end

-- Get base URL
function env_loader.get_base_url()
  return env_loader.get("BASE_URL", "http://localhost:8080")
end

return env_loader
