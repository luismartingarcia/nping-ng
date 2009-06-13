
#include "nse_main.h"

#include "nse_fs.h"
#include "nse_nsock.h"
#include "nse_nmaplib.h"
#include "nse_bit.h"
#include "nse_binlib.h"
#include "nse_pcrelib.h"
#include "nse_openssl.h"
#include "nse_debug.h"

#include "nmap.h"
#include "nmap_error.h"
#include "portlist.h"
#include "nsock.h"
#include "NmapOps.h"
#include "timing.h"
#include "Target.h"
#include "nmap_tty.h"

#define NSE_MAIN "NSE_MAIN" /* the main function */
#define NSE_TRACEBACK "NSE_TRACEBACK"

/* string keys used in interface with nse_main.lua */
#define NSE_WAITING_TO_RUNNING "NSE_WAITING_TO_RUNNING"
#define NSE_DESTRUCTOR "NSE_DESTRUCTOR"

#define MAX_FILENAME_LEN 4096

extern NmapOps o;

int current_hosts = LUA_NOREF;

static int timedOut (lua_State *L)
{
  Target *target = get_target(L, 1);
  lua_pushboolean(L, target->timedOut(NULL));
  return 1;
}

static int startTimeOutClock (lua_State *L)
{
  Target *target = get_target(L, 1);
  if (!target->timeOutClockRunning())
    target->startTimeOutClock(NULL);
  return 0;
}

static int stopTimeOutClock (lua_State *L)
{
  Target *target = get_target(L, 1);
  if (target->timeOutClockRunning())
    target->stopTimeOutClock(NULL);
  return 0;
}

static int next_port (lua_State *L)
{
  lua_settop(L, 2);
  lua_pushvalue(L, lua_upvalueindex(1));
  lua_pushvalue(L, 2);
  if (lua_next(L, -2) == 0)
    return 0;
  else {
    lua_pop(L, 1); /* pop boolean value */
    return 1;
  }
}

static int ports (lua_State *L)
{
  static const int states[] = {
    PORT_OPEN,
    PORT_OPENFILTERED,
    PORT_UNFILTERED,
    PORT_HIGHEST_STATE /* last one marks end */
  };
  Target *target = get_target(L, 1);
  PortList *plist = &(target->ports);
  Port *current = NULL;
  lua_newtable(L);
  for (int i = 0; states[i] != PORT_HIGHEST_STATE; i++)
    while ((current = plist->nextPort(current, TCPANDUDPANDSCTP,
            states[i])) != NULL)
    {
      lua_newtable(L);
      set_portinfo(L, current);
      lua_pushboolean(L, 1);
      lua_rawset(L, -3);
    }
  lua_pushcclosure(L, next_port, 1);
  lua_pushnil(L);
  lua_pushnil(L);
  return 3;
}

static int host_set_output (lua_State *L)
{
  ScriptResult sr;
  Target *target = get_target(L, 1);
  sr.set_id(luaL_checkstring(L, 2));
  sr.set_output(luaL_checkstring(L, 3));
  target->scriptResults.push_back(sr);
  return 0;
}

static int port_set_output (lua_State *L)
{
  ScriptResult sr;
  Target *target = get_target(L, 1);
  Port *port = get_port(L, target, 2);
  sr.set_id(luaL_checkstring(L, 3));
  sr.set_output(luaL_checkstring(L, 4));
  port->scriptResults.push_back(sr);
  /* increment host port script results*/
  target->ports.numscriptresults++;
  return 0;
}

static int fetchfile_absolute (lua_State *L)
{
  char path[MAX_FILENAME_LEN];
  switch (nse_fetchfile_absolute(path, sizeof(path), luaL_checkstring(L, 1)))
  {
    case 0: // no such path
      lua_pushnil(L);
      lua_pushfstring(L, "no path to file/directory: %s", lua_tostring(L, 1));
      break;
    case 1: // file returned
      lua_pushliteral(L, "file");
      lua_pushstring(L, path);
      break;
    case 2: // directory returned
      lua_pushliteral(L, "directory");
      lua_pushstring(L, path);
      break;
    default:
      return luaL_error(L, "nse_fetchfile_absolute returned bad code");
  }
  return 2;
}

static int dump_dir (lua_State *L)
{
  luaL_checkstring(L, 1);
  lua_pushcclosure(L, nse_scandir, 0);
  lua_pushvalue(L, 1);
  lua_pushinteger(L, NSE_FILES);
  lua_call(L, 2, 1);
  return 1;
}

static int nsock_loop (lua_State *L)
{
  if (l_nsock_loop(luaL_checkint(L, 1)) == NSOCK_LOOP_ERROR)
    luaL_error(L, "an error occurred in nsock_loop");
  return 0;
}

static int key_was_pressed (lua_State *L)
{
  lua_pushboolean(L, keyWasPressed());
  return 1;
}

static int ref (lua_State *L)
{
  lua_settop(L, 1);
  lua_pushinteger(L, (lua_Integer) luaL_ref(L, LUA_REGISTRYINDEX));
  return 1;
}

static int unref (lua_State *L)
{
  luaL_unref(L, LUA_REGISTRYINDEX, luaL_checkint(L, 1));
  return 0;
}

static int updatedb (lua_State *L)
{
  lua_pushboolean(L, script_updatedb());
  return 1;
}

static int scp (lua_State *L)
{
  static const char * const ops[] = {"printStats", "printStatsIfNecessary",
    "mayBePrinted", "endTask", NULL};
  ScanProgressMeter *progress =
    (ScanProgressMeter *) lua_touserdata(L, lua_upvalueindex(1));
  switch (luaL_checkoption(L, 1, NULL, ops))
  {
    case 0: /* printStats */
      progress->printStats((double) luaL_checknumber(L, 2), NULL);
      break;
    case 1:
      progress->printStatsIfNecessary((double) luaL_checknumber(L, 2), NULL);
      break;
    case 2: /*mayBePrinted */
      lua_pushboolean(L, progress->mayBePrinted(NULL));
      return 1;
    case 3: /* endTask */
      progress->endTask(NULL, NULL);
      delete progress;
      break;
  }
  return 0;
}

static int scan_progress_meter (lua_State *L)
{
  lua_pushlightuserdata(L, new ScanProgressMeter(luaL_checkstring(L, 1)));
  lua_pushcclosure(L, scp, 1);
  return 1;
}

static void open_cnse (lua_State *L)
{
  static const luaL_Reg nse[] = {
    {"fetchfile_absolute", fetchfile_absolute},
    {"dump_dir", dump_dir},
    {"nsock_loop", nsock_loop},
    {"key_was_pressed", key_was_pressed},
    {"ref", ref},
    {"unref", unref},
    {"updatedb", updatedb},
    {"scan_progress_meter", scan_progress_meter},
    {"timedOut", timedOut},
    {"startTimeOutClock", startTimeOutClock},
    {"stopTimeOutClock", stopTimeOutClock},
    {"ports", ports},
    {"host_set_output", host_set_output},
    {"port_set_output", port_set_output},
    {NULL, NULL}
  };

  lua_newtable(L);
  luaL_register(L, NULL, nse);
  /* Add some other fields */
  lua_pushboolean(L, o.script == 1); /* default scripts if none enumerated? */
  lua_setfield(L, -2, "default");
  lua_pushboolean(L, o.scriptversion == 1);
  lua_setfield(L, -2, "scriptversion");
  lua_pushliteral(L, SCRIPT_ENGINE_LUA_DIR SCRIPT_ENGINE_DATABASE);
  lua_setfield(L, -2, "script_dbpath");
  lua_pushstring(L, o.scriptargs);
  lua_setfield(L, -2, "scriptargs");
}

void ScriptResult::set_output (const char *out)
{
  output = std::string(out);
}

std::string ScriptResult::get_output (void)
{
  return output;
}

void ScriptResult::set_id (const char *ident)
{
  id = std::string(ident);
}

std::string ScriptResult::get_id (void)
{
  return id;
}

/* int panic (lua_State *L)
 *
 * Panic function set via lua_atpanic().
 */
static int panic (lua_State *L)
{
  const char *err = lua_tostring(L, 1);
  fatal("Unprotected error in Lua:\n%s\n", err);
  return 0;
}

static void set_nmap_libraries (lua_State *L)
{
  static const luaL_Reg libs[] = {
    {NSE_PCRELIBNAME, luaopen_pcrelib}, // pcre library
    {"nmap", luaopen_nmap}, // nmap bindings
    {NSE_BINLIBNAME, luaopen_binlib},
    {BITLIBNAME, luaopen_bit}, // bit library
#ifdef HAVE_OPENSSL
    {OPENSSLLIBNAME, luaopen_openssl}, // openssl bindings
#endif
    {"stdnse.c", luaopen_stdnse_c},
    {NULL, NULL}
  };

  /* Put our libraries in the package.preload */
  lua_getglobal(L, "require"); /* the require function */
  lua_getglobal(L, LUA_LOADLIBNAME);
  lua_getfield(L, -1, "preload");
  for (int i = 0; libs[i].name != NULL; i++)
  {
    lua_pushstring(L, libs[i].name);
    lua_pushcclosure(L, libs[i].func, 0);
    lua_settable(L, -3); /* set package.preload */

    lua_pushvalue(L, -3); /* the require function */
    lua_pushstring(L, libs[i].name);
    lua_call(L, 1, 0); /* explicitly require it */
  }
  lua_pop(L, 3); /* require, package, package.preload */
}

int script_updatedb (void)
{
  static const char load_db[] = 
    "local nse = ...\n"
    "local _G, assert, ipairs, loadfile, setfenv, setmetatable, rawget, type ="
    "      _G, assert, ipairs, loadfile, setfenv, setmetatable, rawget, type\n"
    "local lower, match, create, resume, open = \n"
    "  string.lower, string.match, coroutine.create, coroutine.resume,"
    "  io.open\n"
    /* set the package.path */
    "local t, path = assert(nse.fetchfile_absolute('nselib/'))\n"
    "assert(t == 'directory', 'could not locate nselib directory!')\n"
    "package.path = package.path..';'..path..'?.lua'\n"
    /* fetch the scripts directory */
    "local t, path = nse.fetchfile_absolute('scripts/')\n"
    "assert(t == 'directory', 'could not locate scripts directory')\n"
    "local db = assert(open(path..'script.db', 'w'),\n"
    "  'could not open database for writing')\n"
    /* dump the scripts/categories */
    "local scripts = nse.dump_dir(path)\n"
    "table.sort(scripts)\n"
    "for i, script in ipairs(scripts) do\n"
    "  local env = setmetatable({}, {__index = _G})\n"
    "  local thread = create(setfenv(assert(loadfile(script)), env))\n"
    "  assert(resume(thread))\n"
    "  local categories = rawget(env, 'categories')\n"
    "  assert(type(categories) == 'table', script.."
    "    ' categories field is not a table')\n"
    "  local basename = assert(match(script, '[/\\\\]?([^/\\\\]-%.nse)$'))\n"
    "  table.sort(categories)\n"
    "  db:write('Entry { filename = \"', basename, '\", categories = {')\n"
    "  for j, category in ipairs(categories) do\n"
    "    db:write(' \"', lower(category), '\",')\n"
    "  end\n"
    "  db:write(' } }\\n')\n"
    "end\n"
    "db:close()\n";
  int status = 1;
  lua_State *L;

  log_write(LOG_STDOUT, "%s: Updating rule database.\n", SCRIPT_ENGINE);

  L = luaL_newstate();
  if (L == NULL)
    fatal("%s: error opening lua for database update\n", SCRIPT_ENGINE);
  lua_atpanic(L, panic); /* we let Lua panic if memory error */
  luaL_openlibs(L);
  set_nmap_libraries(L);
  
  lua_settop(L, 0); // safety, is 0 anyway
  lua_getglobal(L, "debug");
  lua_getfield(L, -1, "traceback");
  lua_replace(L, -2);

  if (luaL_loadstring(L, load_db) != 0)
    fatal("%s: loading load_db failed %s", SCRIPT_ENGINE, lua_tostring(L, -1));
  open_cnse(L);
  if (lua_pcall(L, 1, 0, 1) != 0)
  {
    error("%s: error while updating Script Database:\n%s\n",
        SCRIPT_ENGINE, lua_tostring(L, -1));
    status = 0;
  }
  else
    log_write(LOG_STDOUT, "NSE script database updated successfully.\n");
  lua_close(L);
  return status;
}

static int init_main (lua_State *L)
{
  char path[MAX_FILENAME_LEN];
  std::vector<std::string> *rules = (std::vector<std::string> *)
      lua_touserdata(L, 1);

  /* Load some basic libraries */
  luaL_openlibs(L);
  set_nmap_libraries(L);

  /* Load current_hosts */
  luaL_unref(L, LUA_REGISTRYINDEX, current_hosts);
  lua_newtable(L);
  current_hosts = luaL_ref(L, LUA_REGISTRYINDEX);

  /* Load debug.traceback for collecting any error tracebacks */
  lua_settop(L, 0); /* clear the stack */
  lua_getglobal(L, "debug");
  lua_getfield(L, -1, "traceback");
  lua_replace(L, 1); // debug.traceback stack position 1
  lua_pushvalue(L, 1);
  lua_setfield(L, LUA_REGISTRYINDEX, NSE_TRACEBACK); /* save copy */

  /* Load main Lua code, stack position 2 */
  if (nmap_fetchfile(path, MAX_FILENAME_LEN, "nse_main.lua") != 1)
    luaL_error(L, "could not locate nse_main.lua");
  if (luaL_loadfile(L, path) != 0)
    luaL_error(L, "could not load nse_main.lua: %s", lua_tostring(L, -1));

  /* The first argument to the NSE Main Lua code is the private nse
   * library table which exposes certain necessary C functions to
   * the Lua engine.
   */
  open_cnse(L); // stack index 3

  /* The second argument is the script rules, including the
   * files/directories/categories passed as the userdata to this function.
   */
  lua_createtable(L, rules->size(), 0); // stack index 4
  for (std::vector<std::string>::iterator si = rules->begin();
       si != rules->end(); si++)
  {
    lua_pushstring(L, si->c_str());
    lua_rawseti(L, 4, lua_objlen(L, 4) + 1);
  }

  /* Get Lua main function */
  if (lua_pcall(L, 2, 1, 1) != 0) lua_error(L); /* we wanted a traceback */

  lua_setfield(L, LUA_REGISTRYINDEX, NSE_MAIN);
  return 0;
}

static int run_main (lua_State *L)
{
  std::vector<Target *> *targets = (std::vector<Target*> *)
      lua_touserdata(L, 1);

  lua_settop(L, 0);
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_TRACEBACK); /* index 1 */

  lua_getfield(L, LUA_REGISTRYINDEX, NSE_MAIN); /* index 2 */
  assert(lua_isfunction(L, -1));

  /* The first and only argument to main is the list of targets.
   * This has all the target names, 1-N, in a list.
   */
  lua_createtable(L, targets->size(), 0); // stack index 3
  for (std::vector<Target *>::iterator ti = targets->begin();
       ti != targets->end(); ti++)
  {
    lua_newtable(L);
    set_hostinfo(L, (Target *) *ti);
    lua_rawseti(L, 3, lua_objlen(L, 3) + 1);
    lua_rawgeti(L, LUA_REGISTRYINDEX, current_hosts);
    lua_pushlightuserdata(L, (void *) *ti);
    lua_setfield(L, -2, (*ti)->targetipstr());
    lua_pop(L, 1); /* current_hosts */
  }

  if (lua_pcall(L, 1, 0, 1) != 0) lua_error(L); /* we wanted a traceback */

  return 0;
}

void nse_restore (lua_State *L, int number)
{
  luaL_checkstack(L, 5, "nse_restore: stack overflow");
  lua_pushthread(L);
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_WAITING_TO_RUNNING);
  lua_insert(L, -(number+2)); /* move WAITING_TO_RUNNING down below the args */
  lua_insert(L, -(number+1)); /* move thread above WAITING_TO_RUNNING */
  /* Call WAITING_TO_RUNNING (defined in nse_main.lua) on the thread and any
     other arguments. */
  if (lua_pcall(L, number+1, 0, 0) != 0)
    fatal("nse_restore: WAITING_TO_RUNNING error!\n%s", lua_tostring(L, -1));
}

/* This function adds (what = 'a') or removes (what 'r') a destructor
 * from the Thread owning the running Lua thread (L). We call the nse_main.lua
 * function _R.NSE_DESTRUCTOR in order to add (or remove) the destructor to
 * the Thread's close handler table.
 *
 * what == 'r', destructor key on stack
 * what == 'a', destructor key and destructor on stack
 */
void nse_destructor (lua_State *L, char what)
{
  assert(what == 'a' || what == 'r');
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_DESTRUCTOR);
  lua_pushstring(L, what == 'a' ? "add" : "remove");
  lua_pushthread(L);
  if (what == 'a')
  {
    lua_pushvalue(L, -5); /* destructor key */
    lua_pushvalue(L, -5); /* destructor */
  }
  else
  {
    lua_pushvalue(L, -4); /* destructor key */
    lua_pushnil(L); /* no destructor, we are removing */
  }
  if (lua_pcall(L, 4, 0, 0) != 0)
    fatal("nse_destructor: NSE_DESTRUCTOR error!\n%s", lua_tostring(L, -1));
  lua_pop(L, what == 'a' ? 2 : 1);
}

static lua_State *L_NSE = NULL;

void open_nse (void)
{
  if (L_NSE == NULL)
  {
    if ((L_NSE = luaL_newstate()) == NULL)
      fatal("%s: failed to open a Lua state!", SCRIPT_ENGINE);
    lua_atpanic(L_NSE, panic);

    if (lua_cpcall(L_NSE, init_main, (void *) &o.chosenScripts) != 0)
      fatal("%s: failed to initialize the script engine:\n%s\n", SCRIPT_ENGINE, 
          lua_tostring(L_NSE, -1));
  }
}

void script_scan (std::vector<Target *> &targets)
{
  o.current_scantype = SCRIPT_SCAN;

  assert(L_NSE != NULL);
  lua_settop(L_NSE, 0); /* clear the stack */

  if (lua_cpcall(L_NSE, run_main, (void *) &targets) != 0)
  {
    error("%s: Script Engine Scan Aborted.\nAn error was thrown by the "
          "engine: %s", SCRIPT_ENGINE, lua_tostring(L_NSE, -1));
  }
}

void close_nse (void)
{
  if (L_NSE != NULL)
  {
    lua_close(L_NSE);
    L_NSE = NULL;
  }
}
