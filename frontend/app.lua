local lapis = require("lapis")
local app = lapis.Application()

-- Simple authentication check - just check if session cookie exists
local function is_authenticated(cookies)
  return cookies and cookies.session and cookies.session ~= ""
end

-- Simple template renderer with variable substitution
local function render_template(template_name, req)
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
  if is_authenticated(self.cookies) then
    return { redirect_to = "/dashboard" }
  end
  return render_template("login")
end)

app:get("/login", function(self)
  if is_authenticated(self.cookies) then
    return { redirect_to = "/dashboard" }
  end
  return render_template("login")
end)

app:get("/register", function(self)
  if is_authenticated(self.cookies) then
    return { redirect_to = "/dashboard" }
  end
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
