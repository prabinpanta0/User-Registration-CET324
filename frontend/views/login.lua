local Widget = require("lapis.html").Widget

local Login = Widget:extend(function(self)
  return self:_render_lp("views/login.lp")
end)

return Login
