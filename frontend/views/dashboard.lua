local Widget = require("lapis.html").Widget

local Dashboard = Widget:extend("Dashboard")

function Dashboard:content()
  return self:render("dashboard.lp")
end

return Dashboard
