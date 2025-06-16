local config = require("lapis.config")

config("development", {
  server = "nginx",
  code_cache = "off",
  num_workers = "1",
  lua_package_path = "./?.lua;./?/init.lua",
  session_name = "lapis_session",
  secret = "myappsecretkey123456",  -- Change this in production
  port = 8080
})
