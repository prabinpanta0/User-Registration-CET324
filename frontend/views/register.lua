local Widget = require("lapis.html").Widget

local Register = Widget:extend("Register")

function Register:content()
  return self:render("register.lp")
end

return Register
