local lapis_config = require("lapis.config")
local html = require("lapis.html")
local env_loader = require("env_loader")

local Login = html.Widget:extend("Login", {
  content = function(self)
    -- Get reCAPTCHA v3 site key from environment
    local recaptcha_site_key = env_loader.get_recaptcha_site_key()
    if recaptcha_site_key == "YOUR_RECAPTCHA_SITE_KEY_HERE" then
      print("[WARN] RECAPTCHA_V3_SITE_KEY is not set. reCAPTCHA v3 will not work.")
    end

    return html.render("login.lp", self, {
      recaptcha_site_key = recaptcha_site_key,
      csrf_token = self.csrf_token
    })
  end
})

return function(req)
  return Login()
end
