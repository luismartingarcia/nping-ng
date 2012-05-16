description = [[
Enumerates the installed Drupal modules by using a list of known modules.

The script works by requesting /sites/all/modules/MODULE_NAME/LICENSE.txt.
If the response status code is 200, it means that the module is installed.
By default, the script checks for the top 100 modules (by downloads), given the huge number of existing modules (~10k).
]]

---
-- @args http-drupal-modules.root The base path. Defaults to <code>/</code>.
-- @args http-drupal-modules.number Number of modules to check.
-- Use this option with a number or "all" as an argument to test for all modules.
-- Defaults to <code>100</code>.
-- @args http-drupal-modules.modules_path The path to the modules folder. If not set, the script will try to
-- find the path or default to <code>sites/all/modules/</code>
--
-- @usage
-- nmap --script=http-drupal-modules --script-arg http-drupal-modules.root="/path/",http-drupal-modules.number=1000 <targets>
--
--@output
-- Interesting ports on my.woot.blog (123.123.123.123):
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-drupal-modules: 
-- |   views
-- |   token
-- |   cck
-- |   pathauto
-- |   ctools
-- |   admin_menu
-- |   imageapi
-- |   filefield
-- |   date
-- |   imagecache
-- |   imagefield
-- |   google_analytics
-- |   webform
-- |   jquery_ui
-- |_  link

author = "Hani Benhabiles"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}

require 'http'
require 'stdnse'
require 'shortport'
require 'pcre'

portrule = shortport.service("http")

--- Attempts to find modules path 
--@param host nmap host table
--@param port nmap port table
--@param root Where to grep for the modules base path
local get_modules_path = function(host, port, root)
  local default_path = "sites/all/modules/"
  local modules_path = stdnse.get_script_args(SCRIPT_NAME .. '.modules_path')
  
  if modules_path == nil then
    -- greps response body for sign of the modules path
    local pathregex = "sites/[a-zA-Z0-9.-]*/modules/"
    local body = http.get(host, port, root).body
    local regex = pcre.new(pathregex, 0, "C")
    local limit, limit2, matches = regex:match(body)
    if limit ~= nil then
      modules_path = body:sub(limit, limit2)
    end
  end
  return modules_path or default_path
end


action = function(host, port)
  local root = stdnse.get_script_args(SCRIPT_NAME .. '.root') or "/"
  local result = {}
  local all = {}
  local requests = {}
  local count = 0

  -- Default number of modules to be checked.
  local modules_limit = stdnse.get_script_args(SCRIPT_NAME .. '.number')
  if modules_limit == 'all' then
     modules_limit = nil
  elseif modules_limit == nil then
     modules_limit = 100
  else
     modules_limit = tonumber(modules_limit)
  end
 
  local modules_path = get_modules_path(host, port, root)
  
  --Check modules list
  local drupal_modules_list = nmap.fetchfile("nselib/data/drupal-modules.lst")
  if not drupal_modules_list then
    return false, "Couldn't find nselib/data/drupal-modules.lst"
  end

  for module_name in io.lines(drupal_modules_list) do 
    count = count + 1
    if modules_limit and count>modules_limit then break end

    -- add request to pipeline
    all = http.pipeline_add(root .. modules_path.. module_name .. "/LICENSE.txt",
                                nil, all, "HEAD")
    -- add to requests buffer
    table.insert(requests, module_name)
  end

  -- send requests
  local pipeline_responses = http.pipeline_go(host, port, all)
  if not pipeline_responses then
    stdnse.print_debug(1, "No answers from pipelined requests", SCRIPT_NAME)
    return nil
  end
  
  for i, response in pairs(pipeline_responses) do
    -- if response status = 200, then module exists
    if response.status == 200 then
      table.insert(result, requests[i])
    end
  end

  return stdnse.format_output(true,result)
end
