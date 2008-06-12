id = "SMTP version"

description = "Simple script which queries and prints the version of an SMTP server."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"demo"}

require "comm"
require "shortport"

portrule = shortport.port_or_service(25, "smtp")

action = function(host, port)
	local status, result = comm.get_banner(host, port, {lines=1})

	if not status then
		return
	end

	return string.gsub(result, "\n", "")
end

