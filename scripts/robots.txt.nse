description = [[
Checks for disallowed entries in <code>robots.txt</code>.

The higher the verbosity or debug level, the more disallowed entries are shown.
]]

---
--@output
-- 80/tcp  open   http    syn-ack
-- |  robots.txt: has 156 disallowed entries (40 shown)
-- |  /news?output=xhtml& /search /groups /images /catalogs
-- |  /catalogues /news /nwshp /news?btcid=*& /news?btaid=*&
-- |  /setnewsprefs? /index.html? /? /addurl/image? /pagead/ /relpage/
-- |  /relcontent /sorry/ /imgres /keyword/ /u/ /univ/ /cobrand /custom
-- |  /advanced_group_search /googlesite /preferences /setprefs /swr /url /default
-- |  /m? /m/? /m/lcb /m/news? /m/setnewsprefs? /m/search? /wml?
-- |_ /wml/? /wml/search?


require('shortport')
require('strbuf')
require('http')

author = "Eddie Bell <ejlbell@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
runlevel = 1.0

portrule = shortport.port_or_service({80, 8080}, {"http"})
local last_len = 0

-- split the output in 50 character length lines 
local function buildOutput(output, w)

	if w:len() == 0 then
		return nil
	end

	-- check for duplicates
	for i,v in ipairs(output) do
		if w == v or w == v:sub(2, v:len()) then 
			return nil 
		end
	end
	
	-- format lines
	if last_len == 0 or last_len + w:len() <= 50 then
		last_len = last_len + w:len()
		nl = ''
	else
		last_len = 0
		nl = '\n'
	end

	output = output .. (nl .. w)
end

-- parse all disallowed entries in body and add them to a strbuf
local function parse_robots(body, output)
	for line in body:gmatch("[^\r\n]+") do 
		for w in line:gmatch('[Dd]isallow:%s*(.*)') do 
			w = w:gsub("%s*#.*", "")
			buildOutput(output, w)
		end
	end

	return #output
end

action = function(host, port)
	local answer = http.get(host, port, "/robots.txt" )

	if answer.status ~= 200 then
		return nil
	end

	local v_level = nmap.verbosity() + (nmap.debugging()*2)
	local output = strbuf.new()
	local detail = 15

	dis_count = parse_robots(answer.body, output)

	if dis_count == 0 then 
		return
	end

	-- verbose/debug mode, print 50 entries
	if v_level > 1 and v_level < 5 then 
		detail = 40 
	-- double debug mode, print everything
	elseif v_level >= 5 then
		detail = dis_count
	end

	-- check we have enough entries
	if detail > dis_count then 
		detail = dis_count
	end

	noun = dis_count == 1 and "entry " or "entries "

	shown = (detail == 0 or detail == dis_count) 
                 and "\n" or '(' .. detail .. ' shown)\n'

	return "has " .. dis_count .. " disallowed " .. noun ..
		shown .. table.concat(output, ' ', 1, detail) 
end
