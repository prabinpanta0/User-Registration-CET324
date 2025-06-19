local lapis_config = require("lapis.config")
local html = require("lapis.html")
local env_loader = require("env_loader")

local Register = html.Widget:extend("Register", {
  content = function(self)
    -- Get reCAPTCHA v3 site key from environment
    local recaptcha_site_key = env_loader.get_recaptcha_site_key()
    if recaptcha_site_key == "YOUR_RECAPTCHA_SITE_KEY_HERE" then
      print("[WARN] RECAPTCHA_V3_SITE_KEY is not set. reCAPTCHA v3 will not work.")
    end

    -- Set the recaptcha_site_key as a property of self so it's available in the template
    self.recaptcha_site_key = recaptcha_site_key
    
    return self:_render_lp("views/register.lp", {
      recaptcha_site_key = recaptcha_site_key
    })
  end
})

return function(req)
  return Register()
end
