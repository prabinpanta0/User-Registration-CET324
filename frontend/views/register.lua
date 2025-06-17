local lapis_config = require("lapis.config")
local html = require("lapis.html")

local Register = html.Widget:extend("Register", {
  content = function(self)
    -- Get HCAPTCHA_SITE_KEY_FRONTEND from environment or Lapis config
    -- For this example, directly using os.getenv.
    -- In a full app, this might come from lapis.config.custom.hcaptcha_site_key
    local site_key = os.getenv("HCAPTCHA_SITE_KEY_FRONTEND")
    if not site_key or site_key == "" then
      print("[WARN] HCAPTCHA_SITE_KEY_FRONTEND is not set. hCaptcha widget will not work.")
      site_key = "YOUR_HCAPTCHA_SITE_KEY_HERE" -- Placeholder for safety
    end

    return html.render("register.lp", self, {
      hcaptcha_site_key = site_key,
      csrf_token = self.csrf_token -- Assuming csrf_token is passed to the widget if needed
    })
  end
})

return function(req)
  -- This function is what Lapis calls for a route.
  -- It should instantiate and return the widget's response.
  -- If CSRF token needs to be generated per request for the form:
  -- local csrf_token_value = require("utils.csrf").generate_csrf_token(req.session) -- Example
  -- return Register({ csrf_token = csrf_token_value })
  return Register() -- Simpler instantiation if CSRF is handled differently or via JS API call
end
