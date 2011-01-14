description = [[
Listens for the LAN sync information broadcasts that the Dropbox.com client broadcasts every 20 seconds, then prints all the discovered client IP addresses, port numbers, version numbers, display names, and more.

If the <code>newtargets</code> script argument is given, all discovered Dropbox clients will be added to the Nmap target list rather than just listed in the output.
]]

-- @usage
-- nmap --script=broadcast-dropbox-listener
-- nmap --script=broadcast-dropbox-listener --script-args=newtargets -Pn
-- @output
-- Pre-scan script results:
-- | broadcast-dropbox-listener: 
-- | displayname  ip             port   version  host_int  namespaces
-- |_noob         192.168.0.110  17500  1.8      34176083  26135075
--
-- Pre-scan script results:
-- | broadcast-dropbox-listener: 
-- | displayname  ip             port   version  host_int  namespaces
-- |_noob         192.168.0.110  17500  1.8      34176083  26135075
-- Nmap scan report for 192.168.0.110
-- Host is up (0.00073s latency).
-- Not shown: 997 filtered ports
-- PORT     STATE SERVICE
-- 139/tcp  open  netbios-ssn
-- 445/tcp  open  microsoft-ds
-- 1047/tcp open  neod1

author = "Ron Bowes, Mak Kolybabi, Andrew Orr, Russ Tait Milne"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}

require("json")
require("shortport")
require("stdnse")
require("tab")
require("target")

local DROPBOX_BROADCAST_PERIOD = 20
local DROPBOX_PORT = 17500

prerule = function()
	return true
end

action = function()
	-- Start listening for broadcasts.
	local sock = nmap.new_socket("udp")
	sock:set_timeout(2 * DROPBOX_BROADCAST_PERIOD * 1000)
	local status, result = sock:bind(nil, DROPBOX_PORT)
	if not status then
		stdnse.print_debug(1, "Could not bind on port %d: %s", DROPBOX_PORT, result)
		sock:close()
		return
	end

	-- Keep track of the IDs we've already seen.
	local ids = {}

	-- Initialize the output table.
	results = tab.new(6)
	tab.addrow(
		results,
		'displayname',
		'ip',
		'port',
		'version',
		'host_int',
		'namespaces'
	)

	local status, result = sock:receive()
	while status do
		-- Parse JSON.
		local status, info = json.parse(result)
		if status then
			-- Get IP address of broadcasting host.
			local status, _, _, ip, _ = sock:get_info()
			if not status then
				stdnse.print_debug(1, "Failed to get socket info.")
				break
			end
			stdnse.print_debug(1, "Received broadcast from host %s (%s).", info.displayname, ip)

			-- Check if we've already seen this ID.
			if ids[info.host_int] then
				break
			end
			ids[info.host_int] = true

			-- Add host scan list.
			if target.ALLOW_NEW_TARGETS then
				target.add(ip)
			end

			-- Add host to list.
			for _, key1 in pairs({"namespaces", "version"}) do
				for key2, val in pairs(info[key1]) do
					info[key1][key2] = tostring(info[key1][key2])
				end
			end
			tab.addrow(
				results,
				info.displayname,
				ip,
				info.port,
				stdnse.strjoin(".", info.version),
				info.host_int,
				stdnse.strjoin(", ", info.namespaces)
			)

			stdnse.print_debug(1, "Added host %s.", info.displayname)
		end

		status, result = sock:receive()
	end

	sock:close()

	-- If no broadcasts received, don't output anything.
	if table.maxn(ids) == 0 then
		 return
	end

	-- Format table, without trailing newline.
	results = tab.dump(results)
	results = results:sub(1, #results - 1)

	return "\n" .. results
end
