description = [[
Retrieves information from an Apache Hadoop secondary NameNode HTTP status page.

Information gathered:
 * Date/time the service was started
 * Hadoop version
 * Hadoop compile date
 * Hostname or IP address and port of the master NameNode server 
 * Last time a checkpoint was taken
 * How often checkpoints are taken (in seconds)
 * Log directory (relative to http://host:port/)
 * File size of current checkpoint
 
For more information about Hadoop, see:
 * http://hadoop.apache.org/
 * http://en.wikipedia.org/wiki/Apache_Hadoop
 * http://wiki.apache.org/hadoop/NameNode
]]

---
-- @usage
-- nmap --script  hadoop-secondary-namenode-info -p 50090 host
--
-- @output
-- PORT      STATE  SERVICE REASON
-- 50090/tcp open   unknown syn-ack
-- | hadoop-secondary-namenode-info: 
-- |   Start: Wed May 11 22:33:44 PDT 2011
-- |   Version: 0.20.2, f415ef415ef415ef415ef415ef415ef415ef415e
-- |   Compiled: Wed May 11 22:33:44 PDT 2011 by bob from unknown
-- |   Log: /logs/
-- |   namenode: namenode1.example.com/192.0.1.1:8020
-- |   Last Checkpoint: Wed May 11 22:33:44 PDT 2011
-- |   Checkpoint Period: 3600 seconds
-- |_  Checkpoint Size: 12345678 MB
--

author = "john.r.bond@gmail.com"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}

require ("shortport")
require ("target")
require ("http")

portrule = shortport.port_or_service ({50090}, "hadoop-secondary-namenode", {"tcp"})

action = function( host, port )

        local result = {}
	local uri = "/status.jsp"
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host.targetname or host.ip, port.number, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Resposne"))  
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		local stats = {}
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))  
		port.version.name = "hadoop-secondary-namenode"
                port.version.product = "Apache Hadoop"
		-- Page isn't valid html :(
                for i in string.gmatch(body,"\n[%w%s]+:%s+[^][\n]+") do
			table.insert(stats,i:match(":%s+([^][\n]+)"))
		end
		stdnse.print_debug(1, ("%s: namenode %s"):format(SCRIPT_NAME,stats[1]))
		stdnse.print_debug(1, ("%s: Start %s"):format(SCRIPT_NAME,stats[2]))
		stdnse.print_debug(1, ("%s: Last Checkpoint %s"):format(SCRIPT_NAME,stats[3]))
		stdnse.print_debug(1, ("%s: Checkpoint Period %s"):format(SCRIPT_NAME,stats[4]))
		stdnse.print_debug(1, ("%s: Checkpoint Size %s"):format(SCRIPT_NAME,stats[5]))
		table.insert(result, ("Start: %s"):format(stats[2]))
		if body:match("Version:%s*</td><td>([^][\n]+)") then
			local version = body:match("Version:%s*</td><td>([^][\n]+)")
			stdnse.print_debug(1, ("%s: Version %s"):format(SCRIPT_NAME,version))  
			table.insert(result, ("Version: %s"):format(version))
			port.version.version = version
		end
		if body:match("Compiled:%s*</td><td>([^][\n]+)") then
			local compiled = body:match("Compiled:%s*</td><td>([^][\n]+)")
			stdnse.print_debug(1, ("%s: Compiled %s"):format(SCRIPT_NAME,compiled))  
			table.insert(result, ("Compiled: %s"):format(compiled))
		end
                if body:match("([^][\"]+)\">Logs") then
                        local logs = body:match("([^][\"]+)\">Logs")
                        stdnse.print_debug(1, ("%s: Logs %s"):format(SCRIPT_NAME,logs))  
                        table.insert(result, ("Logs: %s"):format(logs))
                end
		table.insert(result, ("Namenode: %s"):format(stats[1]))
		table.insert(result, ("Last Checkpoint: %s"):format(stats[3]))
		table.insert(result, ("Checkpoint Period: %s"):format(stats[4]))
		table.insert(result, ("Checkpoint: Size %s"):format(stats[5]))
		if target.ALLOW_NEW_TARGETS then
			if stats[1]:match("([^][/]+)") then
				local newtarget = stats[1]:match("([^][/]+)")
				stdnse.print_debug(1, ("%s: Added target: %s"):format(SCRIPT_NAME, newtarget))
				local status,err = target.add(newtarget)
			end
		end
		
	end
	return stdnse.format_output(true, result)
end
