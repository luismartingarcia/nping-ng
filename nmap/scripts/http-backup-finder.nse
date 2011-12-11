description = [[
Spiders a website and attempts to identify backup copies of existing files.
It does so by requesting a number of different combinations of the filename,
such as eg.: index.bak, index.html~, copy of index.html etc.
]]

---
-- @usage
-- nmap --script=http-backup-finder <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-backup-finder: 
-- | Spidering limited to: maxdepth=3; maxpagecount=20; withindomain=example.com
-- |   http://example.com/index.bak
-- |   http://example.com/login.php~
-- |   http://example.com/index.php~
-- |_  http://example.com/help.bak
--
-- @args http-backup-finder.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-backup-finder.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-backup-finder.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-backup-finder.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-backup-finder.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'httpspider'
require 'shortport'
require 'url'

portrule = shortport.http

local function backupNames(filename)
	local function createBackupNames()
		local dir = filename:match("^(.*/)") or ""
		local basename, suffix = filename:match("([^/]*)%.(.*)$")
	
		local backup_names = {
			"{basename}.bak", -- generic bak file
			"{basename}.{suffix}~", -- emacs
			"{basename} copy.{suffix}", -- mac copy
			"Copy of {basename}.{suffix}", -- windows copy
			"Copy (2) of {basename}.{suffix}", -- windows second copy of
			"{basename}.{suffix}.1", -- generic backup
		}
	
		local replace_patterns = {
			["{filename}"] = filename,
			["{basename}"] = basename,
			["{suffix}"] = suffix,
		}

		for _, name in ipairs(backup_names) do
			local backup_name = name
			for p, v in pairs(replace_patterns) do
				backup_name = backup_name:gsub(p,v)
			end
			coroutine.yield(dir .. backup_name)
		end
	end
	return coroutine.wrap(createBackupNames)
end

action = function(host, port)

	local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME } )
	crawler:set_timeout(10000)

	local backups = {}
	while(true) do
		local status, r = crawler:crawl()
		-- if the crawler fails it can be due to a number of different reasons
		-- most of them are "legitimate" and should not be reason to abort
		if ( not(status) ) then
			if ( r.err ) then
				return stdnse.format_output(true, "ERROR: %s", r.reason)
			else
				break
			end
		end

		-- parse the returned url
		local parsed = url.parse(tostring(r.url))
		
		-- only pursue links that have something looking as a file
		if ( parsed.path:match(".*%.*.$") ) then
			-- iterate over possible backup files
			for link in backupNames(parsed.path) do
				local host, port = parsed.host, parsed.port
			
				-- if no port was found, try to deduce it from the scheme
				if ( not(port) ) then
					port = (parsed.scheme == 'https') and 443
					port = port or ((parsed.scheme == 'http') and 80)
				end

				-- the url.escape doesn't work here as it encodes / to %2F
				-- which results in 400 bad request, so we simple do a space
				-- replacement instead.
				local escaped_link = link:gsub(" ", "%%20")

				-- attempt a HEAD-request against each of the backup files
				local response = http.head(host, port, escaped_link)
				if ( response.status == 200 ) then
					if ( not(parsed.port) ) then
						table.insert(backups, 
							("%s://%s%s"):format(parsed.scheme, host, link))
					else
						table.insert(backups, 
							("%s://%s:%d%s"):format(parsed.scheme, host, port, link))
					end
				end
			end
		end
	end
	
	if ( #backups > 0 ) then
		backups.name = crawler:getLimitations()
		return stdnse.format_output(true, backups)
	end
end