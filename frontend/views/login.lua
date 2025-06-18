local lapis_config = require("lapis.config")
local html = require("lapis.html")

local Login = html.Widget:extend("Login", {
  content = function(self)
    -- Get HCAPTCHA_SITE_KEY_FRONTEND from environment
    local site_key = os.getenv("HCAPTCHA_SITE_KEY_FRONTEND")
    if not site_key or site_key == "" then
      print("[WARN] HCAPTCHA_SITE_KEY_FRONTEND is not set. hCaptcha widget will not work.")
      site_key = "YOUR_HCAPTCHA_SITE_KEY_HERE" -- Placeholder for safety
    end

    return html.render("login.lp", self, {
      hcaptcha_site_key = site_key,
      csrf_token = self.csrf_token -- Assuming csrf_token is passed to the widget if needed
    })
  end
})

return function(req)
  return Login()
end
