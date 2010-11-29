---
-- Standard Nmap Scripting Engine functions. This module contains various handy
-- functions that are too small to justify modules of their own.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

local assert = assert;
local error = error;
local pairs = pairs
local ipairs = ipairs
local tonumber = tonumber;
local type = type
local select = select
local unpack = unpack

local ceil = math.ceil
local max = math.max
local format = string.format;
local rep = string.rep
local concat = table.concat;
local insert = table.insert;
local os = os
local math = math
local string = string

local io = require 'io'; -- TODO: Remove

local nmap = require "nmap";

local c_funcs = require "stdnse.c";

local EMPTY = {}; -- Empty constant table

module(... or "stdnse");

-- Load C functions from stdnse.c into this namespace.
for k, v in pairs(c_funcs) do
  _M[k] = v
end
-- Remove visibility of the stdnse.c table.
c = nil

--- Sleeps for a given amount of time.
--
-- This causes the program to yield control and not regain it until the time
-- period has elapsed. The time may have a fractional part. Internally, the
-- timer provides millisecond resolution.
-- @name sleep
-- @class function
-- @param t Time to sleep, in seconds.
-- @usage stdnse.sleep(1.5)

-- sleep is a C function defined in nse_nmaplib.cc.

---
-- Prints a formatted debug message if the current verbosity level is greater
-- than or equal to a given level.
-- 
-- This is a convenience wrapper around
-- <code>nmap.log_write</code>. The first optional numeric
-- argument, <code>level</code>, is used as the debugging level necessary
-- to print the message (it defaults to 1 if omitted). All remaining arguments
-- are processed with Lua's <code>string.format</code> function.
-- @param level Optional debugging level.
-- @param fmt Format string.
-- @param ... Arguments to format.
print_debug = function(level, fmt, ...)
  local l, d = tonumber(level), nmap.debugging();
  if l and l <= d then
    nmap.log_write("stdout", format(fmt, ...));
  elseif not l and 1 <= d then
    nmap.log_write("stdout", format(level, fmt, ...));
  end
end

--- Join a list of strings with a separator string.
-- 
-- This is Lua's <code>table.concat</code> function with the parameters
-- swapped for coherence.
-- @usage
-- stdnse.strjoin(", ", {"Anna", "Bob", "Charlie", "Dolores"})
-- --> "Anna, Bob, Charlie, Dolores"
-- @param delimiter String to delimit each element of the list.
-- @param list Array of strings to concatenate.
-- @return Concatenated string.
function strjoin(delimiter, list)
  assert(type(delimiter) == "string" or type(delimiter) == nil, "delimiter is of the wrong type! (did you get the parameters backward?)")
    
  return concat(list, delimiter);
end

--- Split a string at a given delimiter, which may be a pattern.
-- @usage
-- stdnse.strsplit(",%s*", "Anna, Bob, Charlie, Dolores")
-- --> { "Anna", "Bob", "Charlie", "Dolores" }
-- @param pattern Pattern that separates the desired strings.
-- @param text String to split.
-- @return Array of substrings without the separating pattern.
function strsplit(pattern, text)
  local list, pos = {}, 1;

  assert(pattern ~= "", "delimiter matches empty string!");

  while true do
    local first, last, match = text:find(pattern, pos);
    if first then -- found?
      list[#list+1] = text:sub(pos, first-1);
      pos = last+1;
    else
      list[#list+1] = text:sub(pos);
      break;
    end
  end
  return list;
end

--- Return a wrapper closure around a socket that buffers socket reads into
-- chunks separated by a pattern.
-- 
-- This function operates on a socket attempting to read data. It separates the
-- data by <code>sep</code> and, for each invocation, returns a piece of the
-- separated data. Typically this is used to iterate over the lines of data
-- received from a socket (<code>sep = "\r?\n"</code>). The returned string
-- does not include the separator. It will return the final data even if it is
-- not followed by the separator. Once an error or EOF is reached, it returns
-- <code>nil, msg</code>. <code>msg</code> is what is returned by
-- <code>nmap.receive_lines</code>.
-- @param socket Socket for the buffer.
-- @param sep Separator for the buffered reads.
-- @return Data from socket reads or <code>nil</code> on EOF or error.
-- @return Error message, as with <code>receive_lines</code>.
function make_buffer(socket, sep)
  local point, left, buffer, done, msg = 1, "";
  local function self()
    if done then
      return nil, msg; -- must be nil for stdnse.lines (below)
    elseif not buffer then
      local status, str = socket:receive();
      if not status then
        if #left > 0 then
          done, msg = not status, str;
          return left;
        else
          return status, str;
        end
      else
        buffer = left..str;
        return self();
      end
    else
      local i, j = buffer:find(sep, point);
      if i then
        local ret = buffer:sub(point, i-1);
        point = j + 1;
        return ret;
      else
        point, left, buffer = 1, buffer:sub(point), nil;
        return self();
      end
    end
  end
  return self;
end

--[[ This function may be usable in Lua 5.2
function lines(socket)
  return make_buffer(socket, "\r?\n"), nil, nil;
end --]]

do
  local t = {
    ["0"] = "0000",
    ["1"] = "0001",
    ["2"] = "0010",
    ["3"] = "0011",
    ["4"] = "0100",
    ["5"] = "0101",
    ["6"] = "0110",
    ["7"] = "0111",
    ["8"] = "1000",
    ["9"] = "1001",
    a = "1010",
    b = "1011",
    c = "1100",
    d = "1101",
    e = "1110",
    f = "1111"
  };

--- Converts the given number, n, to a string in a binary number format (12
-- becomes "1100").
-- @param n Number to convert.
-- @return String in binary format.
  function tobinary(n)
    assert(tonumber(n), "number expected");
    return (("%x"):format(n):gsub("%w", t):gsub("^0*", ""));
  end
end

--- Converts the given number, n, to a string in an octal number format (12
-- becomes "14").
-- @param n Number to convert.
-- @return String in octal format.
function tooctal(n)
  assert(tonumber(n), "number expected");
  return ("%o"):format(n)
end

--- Encode a string or number in hexadecimal (12 becomes "c", "AB" becomes
-- "4142").
--
-- An optional second argument is a table with formatting options. The possible
-- fields in this table are
-- * <code>separator</code>: A string to use to separate groups of digits.
-- * <code>group</code>: The size of each group of digits between separators. Defaults to 2, but has no effect if <code>separator</code> is not also given.
-- @usage
-- stdnse.tohex("abc") --> "616263"
-- stdnse.tohex("abc", {separator = ":"}) --> "61:62:63"
-- stdnse.tohex("abc", {separator = ":", group = 4}) --> "61:6263"
-- stdnse.tohex(123456) --> "1e240"
-- stdnse.tohex(123456, {separator = ":"}) --> "1:e2:40"
-- stdnse.tohex(123456, {separator = ":", group = 4}) --> "1:e240"
-- @param s String or number to be encoded.
-- @param options Table specifiying formatting options.
-- @return String in hexadecimal format.
function tohex( s, options ) 
  options = options or EMPTY
  local separator = options.separator
  local hex

  if type( s ) == "number" then
    hex = ("%x"):format(s)
  elseif type( s ) == 'string' then
    hex = ("%02x"):rep(#s):format(s:byte(1,#s))
  else
    error( "Type not supported in tohex(): " .. type(s), 2 )
  end

  -- format hex if we got a separator
  if separator then
    local group = options.group or 2
    local fmt_table = {}
    -- split hex in group-size chunks
    for i=#hex,1,-group do
      -- table index must be consecutive otherwise table.concat won't work
      fmt_table[ceil(i/group)] = hex:sub(max(i-group+1,1),i)
    end

    hex = concat( fmt_table, separator )
  end

  return hex
end

---Either return the string itself, or return "<blank>" (or the value of the second parameter) if the string
-- was blank or nil.
--
--@param string The base string.
--@param blank  The string to return if <code>string</code> was blank
--@return Either <code>string</code> or, if it was blank, <code>blank</code>
function string_or_blank(string, blank)
  if(string == nil or string == "") then
    if(blank == nil) then
      return "<blank>"
    else
      return blank
    end
  else
    return string
  end
end

---
-- Parses a time duration specification, which is a number followed by a
-- unit, and returns a number of seconds. The unit is optional and
-- defaults to seconds. The possible units (case-insensitive) are
-- * <code>ms</code>: milliseconds,
-- * <code>s</code>: seconds,
-- * <code>m</code>: minutes,
-- * <code>h</code>: hours.
-- In case of a parsing error, the function returns <code>nil</code>
-- followed by an error message.
--
-- @usage
-- parse_timespec("10") --> 10
-- parse_timespec("10ms") --> 0.01
-- parse_timespec("10s") --> 10
-- parse_timespec("10m") --> 600
-- parse_timespec("10h") --> 36000
-- parse_timespec("10z") --> nil, "Can't parse time specification \"10z\" (bad unit \"z\")"
--
-- @param timespec A time specification string.
-- @return A number of seconds, or <code>nil</code> followed by an error
-- message.
function parse_timespec(timespec)
  local n, unit, t, m
  local multipliers = {[""] = 1, s = 1, m = 60, h = 60 * 60, ms = 0.001}

  n, unit = string.match(timespec, "^([%d.]+)(.*)$")
  if not n then
    return nil, string.format("Can't parse time specification \"%s\"", timespec)
  end

  t = tonumber(n)
  if not t then
    return nil, string.format("Can't parse time specification \"%s\" (bad number \"%s\")", timespec, n)
  end

  m = multipliers[unit]
  if not m then
    return nil, string.format("Can't parse time specification \"%s\" (bad unit \"%s\")", timespec, unit)
  end

  return t * m
end

--- Format the difference between times <code>t2</code> and <code>t1</code>
-- into a string in one of the forms (signs may vary):
-- * 0s
-- * -4s
-- * +2m38s
-- * -9h12m34s
-- * +5d17h05m06s
-- * -2y177d10h13m20s
-- The string shows <code>t2</code> relative to <code>t1</code>; i.e., the
-- calculation is <code>t2</code> minus <code>t1</code>.
function format_difftime(t2, t1)
  local d, s, sign, yeardiff

  d = os.difftime(os.time(t2), os.time(t1))
  if d > 0 then
    sign = "+"
  elseif d < 0 then
    sign = "-"
    t2, t1 = t1, t2
    d = -d
  else
    sign = ""
  end
  -- t2 is always later than or equal to t1 here.

  -- The year is a tricky case because it's not a fixed number of days
  -- the way a day is a fixed number of hours or an hour is a fixed
  -- number of minutes. For example, the difference between 2008-02-10
  -- and 2009-02-10 is 366 days because 2008 was a leap year, but it
  -- should be printed as 1y0d0h0m0s, not 1y1d0h0m0s. We advance t1 to be
  -- the latest year such that it is still before t2, which means that its
  -- year will be equal to or one less than t2's. The number of years
  -- skipped is stored in yeardiff.
  if t2.year > t1.year then
    local tmpyear = t1.year
    -- Put t1 in the same year as t2.
    t1.year = t2.year
    d = os.difftime(os.time(t2), os.time(t1))
    if d < 0 then
      -- Too far. Back off one year.
      t1.year = t2.year - 1
      d = os.difftime(os.time(t2), os.time(t1))
    end
    yeardiff = t1.year - tmpyear
    t1.year = tmpyear
  else
    yeardiff = 0
  end

  local s, sec, min
  s = ""
  -- Seconds (pad to two digits).
  sec = d % 60
  d = math.floor(d / 60)
  if d == 0 and yeardiff == 0 then
    return sign .. string.format("%gs", sec) .. s
  end
  s = string.format("%02gs", sec) .. s
  -- Minutes (pad to two digits).
  min = d % 60
  d = math.floor(d / 60)
  if d == 0 and yeardiff == 0 then
    return sign .. string.format("%dm", min) .. s
  end
  s = string.format("%02dm", min) .. s
  -- Hours.
  s = string.format("%dh", d % 24) .. s
  d = math.floor(d / 24)
  if d == 0 and yeardiff == 0 then
    return sign .. s
  end
  -- Days.
  s = string.format("%dd", d) .. s
  if yeardiff == 0 then return sign .. s end
  -- Years.
  s = string.format("%dy", yeardiff) .. s
  return sign .. s
end

--- Returns the current time in milliseconds since the epoch
-- @return The current time in milliseconds since the epoch
function clock_ms()
  return nmap.clock() * 1000
end

--- Returns the current time in microseconds since the epoch
-- @return The current time in microseconds since the epoch
function clock_us()
  return nmap.clock() * 1000000
end

---Get the indentation symbols at a given level. 
local function format_get_indent(indent, at_end)
  local str = ""
  local had_continue = false

  if(not(at_end)) then
    str = rep('  ', #indent) -- Was: "|  "
  else
    for i = #indent, 1, -1 do
      if(indent[i] and not(had_continue)) then
        str = str .. "  " -- Was: "|_ "
      else
        had_continue = true
        str = str .. "  " -- Was: "|  "
      end
    end
  end

  return str
end

-- A helper for format_output (see below).
local function format_output_sub(status, data, indent)
  if (#data == 0) then
    return ""
  end

  -- Return a single line of output as-is (assuming it's top-level and a string)
  if(indent == nil and #data == 1 and type(data) == 'string' and not(data['name']) and not(data['warning'])) then
    return data[1]
  end

  -- Used to put 'ERROR: ' in front of all lines on error messages
  local prefix = ""
  -- Initialize the output string to blank (or, if we're at the top, add a newline)
  local output = ""
  if(not(indent)) then
    output = '\n'
  end

  if(not(status)) then
    if(nmap.debugging() < 1) then
      return nil
    end
    prefix = "ERROR: "
  end

  -- If a string was passed, turn it into a table
  if(type(data) == 'string') then
    data = {data}
  end

  -- Make sure we have an indent value
  indent = indent or {}

  if(data['name']) then
    if(data['warning'] and nmap.debugging() > 0) then
      output = output .. format("%s%s%s (WARNING: %s)\n", format_get_indent(indent), prefix, data['name'], data['warning'])
    else
      output = output .. format("%s%s%s\n", format_get_indent(indent), prefix, data['name'])
    end
  elseif(data['warning'] and nmap.debugging() > 0) then
      output = output .. format("%s%s(WARNING: %s)\n", format_get_indent(indent), prefix, data['warning'])
  end

  for i, value in ipairs(data) do
    if(type(value) == 'table') then
      -- Do a shallow copy of indent
      local new_indent = {}
      for _, v in ipairs(indent) do
        insert(new_indent, v)
      end

      if(i ~= #data) then
        insert(new_indent, false)
      else
        insert(new_indent, true)
      end

      output = output .. format_output_sub(status, value, new_indent)
        
    elseif(type(value) == 'string') then
      if(i ~= #data) then
        output = output .. format("%s  %s%s\n", format_get_indent(indent, false), prefix, value)
      else
        output = output .. format("%s  %s%s\n", format_get_indent(indent, true), prefix, value)
      end
    end
  end

  return output
end

---Takes a table of output on the commandline and formats it for display to the 
-- user. This is basically done by converting an array of nested tables into a 
-- string. In addition to numbered array elements, each table can have a 'name' 
-- and a 'warning' value. The 'name' will be displayed above the table, and 
-- 'warning' will be displayed, with a 'WARNING' tag, if and only if debugging
-- is enabled. 
-- 
-- Here's an example of a table:
-- <code>
--   local domains = {}
--   domains['name'] = "DOMAINS"
--   table.insert(domains, 'Domain 1')
--   table.insert(domains, 'Domain 2')
-- 
--   local names = {}
--   names['name'] = "NAMES"
--   names['warning'] = "Not all names could be determined!"
--   table.insert(names, "Name 1")
-- 
--   local response = {}
--   table.insert(response, "Apple pie")
--   table.insert(response, domains)
--   table.insert(response, names)
-- 
--   return stdnse.format_output(true, response)
-- </code>
--
-- With debugging enabled, this is the output:
-- <code>
--   Host script results:
--   |  smb-enum-domains:
--   |    Apple pie
--   |    DOMAINS
--   |      Domain 1
--   |      Domain 2
--   |    NAMES (WARNING: Not all names could be determined!)
--   |_     Name 1
-- </code>
--
--@param status A boolean value dictating whether or not the script succeeded. 
--              If status is false, and debugging is enabled, 'ERROR' is prepended
--              to every line. If status is false and ebugging is disabled, no output
--              occurs. 
--@param data   The table of output. 
--@param indent Used for indentation on recursive calls; should generally be set to
--              nil when callling from a script. 
-- @return <code>nil</code>, if <code>data</code> is empty, otherwise a
-- multiline string.
function format_output(status, data, indent)
  -- If data is nil, die with an error (I keep doing that by accident)
  assert(data, "No data was passed to format_output()")

  -- Don't bother if we don't have any data
  if (#data == 0) then
    return nil
  end

  local result = format_output_sub(status, data, indent)

  -- Check for an empty result
  if(result == nil or #result == "" or result == "\n" or result == "\n") then
    return nil
  end

  return result
end

-- Get the value of a script argument, or nil if the script argument was not
-- given. This works also for arguments given as top-level array values, like
-- --script-args=unsafe; for these it returns the value 1.
local function arg_value(argname)
  if nmap.registry.args[argname] then
    return nmap.registry.args[argname]
  end
  for _, v in ipairs(nmap.registry.args) do
    if v == argname then
      return 1
    end
  end
end

--- Parses the script arguments passed to the --script-args option.
--
-- @usage
-- --script-args 'script.arg1=value,script.arg3,script-x.arg=value'
-- local arg1, arg2, arg3 = get_script_args('script.arg1','script.arg2','script.arg3')
--      => arg1 = value
--      => arg2 = nil
--      => arg3 = 1
--
-- --script-args 'displayall,unsafe,script-x.arg=value,script-y.arg=value'
-- local displayall, unsafe = get_script_args('displayall','unsafe')
--      => displayall = 1
--      => unsafe     = 1
--
-- --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={host1,host2}'
-- local mode, domains = get_script_args('dns-cache-snoop.mode',
--                                       'dns-cache-snoop.domains')
--      => mode    = 'timed'
--      => domains = {host1,host2}
--
-- @param Arguments  Script arguments to check.
-- @return Arguments values.
function get_script_args (...)
  local args = {}

  for i, set in ipairs({...}) do 
    if type(set) == "string" then
      set = {set}
    end
    for _, test in ipairs(set) do
      local v = arg_value(test)
      if v then
        args[i] = v
        break
      end
    end
  end

  return unpack(args, 1, select("#", ...))
end

---Get the best possible hostname for the given host. This can be the target as given on 
-- the commandline, the reverse dns name, or simply the ip address. 
--@param host The host table (or a string that'll simply be returned). 
--@return The best possible hostname, as a string. 
function get_hostname(host)
  if type(host) == "table" then
    return host.targetname or ( host.name ~= '' and host.name ) or host.ip
  else
    return host
  end
end

---Retrieve an item from the registry, checking if each sub-key exists. If any key doesn't
-- exist, return nil. 
function registry_get(subkeys)
  local registry = nmap.registry
  local i = 1

  while(subkeys[i]) do
    if(not(registry[subkeys[i]])) then
      return nil
    end

    registry = registry[subkeys[i]]

    i = i + 1
  end

  return registry
end

--Check if the given element exists in the registry. If 'key' is nil, it isn't checked. 
function registry_exists(subkeys, key, value)
  local subkey = registry_get(subkeys)

  if(not(subkey)) then
    return false
  end

  for k, v in pairs(subkey) do
    if((key == nil or key == k) and (v == value)) then -- TODO: if 'value' is a table, this fails
      return true
    end
  end

  return false
end

---Add an item to an array in the registry, creating all sub-keys if necessary. 
-- For example, calling:
-- <code>registry_add_array({'192.168.1.100', 'www', '80', 'pages'}, 'index.html')</code>
-- Will create nmap.registry['192.168.1.100'] as a table, if necessary, then add a table
-- under the 'www' key, and so on. 'pages', finally, is treated as an array and the value
-- given is added to the end. 
function registry_add_array(subkeys, value, allow_duplicates)
  local registry = nmap.registry
  local i = 1

  -- Unless the user wants duplicates, make sure there aren't any
  if(allow_duplicates ~= true) then
    if(registry_exists(subkeys, nil, value)) then
      return
    end
  end

  while(subkeys[i]) do
    if(not(registry[subkeys[i]])) then
      registry[subkeys[i]] = {}
    end
    registry = registry[subkeys[i]]
    i = i + 1
  end

  -- Make sure the value isn't already in the table
  for _, v in pairs(registry) do
    if(v == value) then
      return
    end
  end
  insert(registry, value)
end

---Similar to <code>registry_add_array</code>, except instead of adding a value to the
-- end of an array, it adds a key:value pair to the table. 
function registry_add_table(subkeys, key, value)
  local registry = nmap.registry
  local i = 1

  -- Unless the user wants duplicates, make sure there aren't any
  if(allow_duplicates ~= true) then
    if(registry_exists(subkeys, key, value)) then
      return
    end
  end

  while(subkeys[i]) do
    if(not(registry[subkeys[i]])) then
      registry[subkeys[i]] = {}
    end
    registry = registry[subkeys[i]]
    i = i + 1
  end

  registry[key] = value
end


--- This function allows you to create worker threads that may perform
-- network tasks in parallel with your script thread.
--
-- Any network task (e.g. <code>socket:connect(...)</code>) will cause the
-- running thread to yield to NSE. This allows network tasks to appear to be
-- blocking while being able to run multiple network tasks at once.
-- While this is useful for running multiple separate scripts, it is
-- unfortunately difficult for a script itself to perform network tasks in
-- parallel. In order to allow scripts to also have network tasks running in
-- parallel, we provide this function, <code>stdnse.new_thread</code>, to
-- create a new thread that can perform its own network related tasks
-- in parallel with the script.
--
-- The script launches the worker thread by calling the <code>new_thread</code>
-- function with the parameters:
-- * The main Lua function for the script to execute, similar to the script action function.
-- * The variable number of arguments to be passed to the worker's main function.
--
-- The <code>stdnse.new_thread</code> function will return two results:
-- * The worker thread's base (main) coroutine (useful for tracking status).
-- * A status query function (described below).
--
-- The status query function shall return two values:
-- * The result of coroutine.status using the worker thread base coroutine.
-- * The error object thrown that ended the worker thread or <code>nil</code> if no error was thrown. This is typically a string, like most Lua errors.
--
-- Note that NSE discards all return values of the worker's main function. You
-- must use function parameters, upvalues or environments to communicate
-- results.
--
-- You should use the condition variable (<code>nmap.condvar</code>)
-- and mutex (<code>nmap.mutex</code>) facilities to coordinate with your
-- worker threads. Keep in mind that Nmap is single threaded so there are
-- no (memory) issues in synchronization to worry about; however, there
-- is resource contention. Your resources are usually network
-- bandwidth, network sockets, etc. Condition variables are also useful if the
-- work for any single thread is dynamic. For example, a web server spider
-- script with a pool of workers will initially have a single root html
-- document. Following the retrieval of the root document, the set of
-- resources to be retrieved (the worker's work) will become very large
-- (an html document adds many new hyperlinks (resources) to fetch).
--@name new_thread
--@class function
--@param main The main function of the worker thread.
--@param ... The arguments passed to the main worker thread.
--@return co The base coroutine of the worker thread.
--@return info A query function used to obtain status information of the worker.
--@usage
--local requests = {"/", "/index.html", --[[ long list of objects ]]}
--
--function thread_main (host, port, responses, ...)
--  local condvar = nmap.condvar(responses);
--  local what = {n = select("#", ...), ...};
--  local allReqs = nil;
--  for i = 1, what.n do
--    allReqs = http.pGet(host, port, what[i], nil, nil, allReqs);
--  end
--  local p = assert(http.pipeline(host, port, allReqs));
--  for i, response in ipairs(p) do responses[#responses+1] = response end
--  condvar "signal";
--end
--
--function many_requests (host, port)
--  local threads = {};
--  local responses = {};
--  local condvar = nmap.condvar(responses);
--  local i = 1;
--  repeat
--    local j = math.min(i+10, #requests);
--    local co = stdnse.new_thread(thread_main, host, port, responses,
--        unpack(requests, i, j));
--    threads[co] = true;
--    i = j+1;
--  until i > #requests;
--  repeat
--    condvar "wait";
--    for thread in pairs(threads) do
--      if coroutine.status(thread) == "dead" then threads[thread] = nil end
--    end
--  until next(threads) == nil;
--  return responses;
--end
do end -- no function here, see nse_main.lua

--- Returns the base coroutine of the running script.
--
-- A script may be resuming multiple coroutines to facilitate its own
-- collaborative multithreading design. Because there is a "root" or "base"
-- coroutine that lets us determine whether the script is still active
-- (that is, the script did not end, possibly due to an error), we provide
-- this <code>stdnse.base</code> function that will retrieve the base
-- coroutine of the script. This base coroutine is the coroutine that runs
-- the action function.
--
-- The base coroutine is useful for many reasons but here are some common
-- uses:
-- * We want to attribute the ownership of an object (perhaps a network socket) to a script.
-- * We want to identify if the script is still alive.
--@name base
--@class function
--@return coroutine Returns the base coroutine of the running script.
do end -- no function here, see nse_main.lua
