local lapis = require("lapis")
local http = require("socket.http")
local app = lapis.Application()

-- Simple authentication check - just check if session cookie exists
local function is_authenticated(cookies)
  return cookies and cookies.session and cookies.session ~= ""
end

-- Backend health check function
local function check_backend_health()
  local response, status = http.request{
    url = "http://127.0.0.1:5000/health",
    method = "GET",
    timeout = 2
  }
  return status == 200
end

-- Enhanced template renderer with backend health check
local function render_template_with_health_check(template_name, req)
  -- First check if backend is available
  if not check_backend_health() then
    -- If backend is down, serve the maintenance page
    -- Resolve absolute path to maintenance.html based on script location
    local script_dir = debug.getinfo(1, "S").source:match("@(.*/)")
    local maintenance_path = (script_dir or "./") .. "static/maintenance.html"
    local file = io.open(maintenance_path, "r")
    if file then
      local content = file:read("*a")
      file:close()
      return content, 502  -- Return with 502 status
    else
      -- Fallback error message if maintenance page is missing
      return [[
        <!DOCTYPE html>
        <html>
        <head><title>Service Unavailable</title></head>
        <body>
          <h1>Service Temporarily Unavailable</h1>
          <p>The authentication service is currently down. Please try again later.</p>
          <script>setTimeout(function(){ window.location.reload(); }, 30000);</script>
        </body>
        </html>
      ]], 502
    end
  end

  -- Backend is healthy, proceed with normal template rendering
  local file_path = "views/" .. template_name .. ".lp"
  print("Attempting to render template: " .. file_path)
  
  local file = io.open(file_path, "r")
  if not file then
    print("Template file not found: " .. file_path)
    return "Template not found: " .. template_name
  end
  local content = file:read("*a")
  file:close()
  
  -- For login and register templates, substitute the reCAPTCHA site key
  if template_name == "login" or template_name == "register" then
    local env_loader = require("env_loader")
    local recaptcha_site_key = env_loader.get_recaptcha_site_key()
    print("[DEBUG] Substituting reCAPTCHA site key: " .. tostring(recaptcha_site_key))
    -- Replace the new template syntax
    content = content:gsub("<%%= recaptcha_site_key %%>", recaptcha_site_key)
    -- Also replace the old syntax if any remain
    content = content:gsub("<%%-?%s*self%.recaptcha_site_key%s*%%-?>", recaptcha_site_key)
  end
  
  print("Template rendered successfully: " .. template_name)
  return content
end

-- Simple template renderer with variable substitution
local function render_template(template_name, req)
  -- For critical backend-dependent pages, check health first
  if template_name == "login" or template_name == "register" or template_name == "dashboard" then
    local content, status = render_template_with_health_check(template_name, req)
    if status == 502 then
      return { status = 502 }, content
    end
    return content
  end

  -- For other templates, use simple rendering
  local file_path = "views/" .. template_name .. ".lp"
  print("Attempting to render template: " .. file_path)
  
  local file = io.open(file_path, "r")
  if not file then
    print("Template file not found: " .. file_path)
    return "Template not found: " .. template_name
  end
  local content = file:read("*a")
  file:close()
  
  -- For login and register templates, substitute the reCAPTCHA site key
  if template_name == "login" or template_name == "register" then
    local env_loader = require("env_loader")
    local recaptcha_site_key = env_loader.get_recaptcha_site_key()
    print("[DEBUG] Substituting reCAPTCHA site key: " .. tostring(recaptcha_site_key))
    -- Replace the new template syntax
    content = content:gsub("<%%= recaptcha_site_key %%>", recaptcha_site_key)
    -- Also replace the old syntax if any remain
    content = content:gsub("<%%-?%s*self%.recaptcha_site_key%s*%%-?>", recaptcha_site_key)
  end
  
  print("Template rendered successfully: " .. template_name)
  return content
end

-- Frontend page routes
app:get("/", function(self)
  -- Always render login page; client-side will handle redirect after session-check
  return render_template("login")
end)

app:get("/login", function(self)
  -- Always render login page to allow session validation or renewal
  return render_template("login")
end)

app:get("/register", function(self)
  -- Always render register page
  return render_template("register")
end)

app:get("/dashboard", function(self)
  print("Dashboard route hit (no trailing slash)")
  if not is_authenticated(self.cookies) then
    return { redirect_to = "/login" }
  end
  return render_template("dashboard")
end)

app:get("/dashboard/", function(self)
  print("Dashboard route hit (with trailing slash)")
  if not is_authenticated(self.cookies) then
    return { redirect_to = "/login" }
  end
  return render_template("dashboard")
end)

app:get("/mfa/setup", function(self)
  print("[DEBUG] MFA setup route accessed")
  -- Don't check authentication here - let the backend MFA routes handle it
  -- This allows newly verified users to access the MFA setup page
  print("[DEBUG] Serving MFA setup page (no auth check)")
  return render_template("mfa_setup")
end)

app:get("/email-verification", function(self)
  -- Email verification page doesn't require authentication
  return render_template("email_verification")
end)

app:get("/forgot-password", function(self)
  -- Render forgot password page
  return render_template("forgot_password")
end)

-- Static file serving
app:get("/static/(.*)", function(self)
  local file_path = "static/" .. self.params[1]
  local file = io.open(file_path, "rb")
  if not file then
    return {status = 404}, "File not found"
  end
  
  local content = file:read("*a")
  file:close()
  
  -- Set content type based on extension
  local ext = file_path:match("%.([^%.]+)$")
  if ext == "css" then
    self.res.headers["Content-Type"] = "text/css"
  elseif ext == "js" then
    self.res.headers["Content-Type"] = "application/javascript"
  elseif ext == "png" then
    self.res.headers["Content-Type"] = "image/png"
  elseif ext == "jpg" or ext == "jpeg" then
    self.res.headers["Content-Type"] = "image/jpeg"
  elseif ext == "svg" then
    self.res.headers["Content-Type"] = "image/svg+xml"
  end
  
  return content
end)

return app
