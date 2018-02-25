-- latest development release of Wireshark supports plugin version information
if set_plugin_info then
    local my_info = {
        version   = "1.0",
        author    = "Hadriel Kaplan",
        email     = "hadriel@128technology.com",
        copyright = "Copyright (c) 2015, 128 Technology, Inc.",
        license   = "MIT license",
        details   = "This is a plugin for Wireshark, to dissect Google protobuf messages.",
        help      = [[
    HOW TO RUN THIS SCRIPT:

    Wireshark and Tshark support multiple ways of loading Lua scripts: through
    a dofile() call in init.lua, through the file being in either the global
    or personal plugins directories, or via the command line. The latter two
    methods are the best: either copy this script into your "Personal Plugins"
    directory, or load it from the command line.

    This script also needs to know where to find your '.proto' files. There are
    two ways of accomplishing that:
        1. Add it to the "ProtoFileNames" table inside this script, or...
        2. Add it as a command-line argument(s). This only works if this protobuf.lua
           script is also loaded through the command line. For example:
          wireshark -X lua_script:protobuf.lua -X lua_script1:foo.proto -X lua_script1:bar.proto
    ]]
    }
    set_plugin_info(my_info)
end


-- capture command line arguments
local args = { ... }

local __DIR__ = os.getenv("HOME") .. "/.wireshark/plugins/protobuf_dissector"
local __DIR_SEPARATOR__ = package.config:sub(1,1) -- first character

-- enable loading of our modules
_G['protbuf_dissector'] = {
    ["__DIR__"] = __DIR__,
    ["__DIR_SEPARATOR__"] = __DIR_SEPARATOR__,
}


-- help wireshark find our modules
package.prepend_path("modules")


-- load our settings
local Settings = require "settings"
Settings:processCmdLine(args)
local dprint  = Settings.dprint
local dprint2 = Settings.dprint2

-- load the rest of our modules
local GenericProto  = require "generic.proto"

local Compiler = require "compiler"


dprint("Protobuf modules loaded")


-- initialize the compiler
Compiler:init()

local proto_files = Settings:getProtoFileNames()


----------------------------------------
-- load the proto file contents
dprint2(#proto_files,"proto files being compiled")


----------------------------------------
-- compile the proto files
local decoder_table = Compiler:compile(proto_files)


----------------------------------------
-- create and register protocol handlers
local Dispatch = require "protocol.dispatch"

local CoAPHandler = require "protocol.coap"
local coap_handler = CoAPHandler.new("CoAP Payload", "???", 5683)
Dispatch.dispatcher:register(coap_handler)

local STOMPHandler = require "protocol.stomp"
local stomp_handler = STOMPHandler.new("STOMP Payload", "???", 61613)
Dispatch.dispatcher:register(stomp_handler)

local WebsocketHandler = require "protocol.websocket"
local websocket_handler = WebsocketHandler.new("Websocket Payload", "???", 80)
Dispatch.dispatcher:register(websocket_handler)

local USPHandler = require "protocol.usp"
local usp_handler = USPHandler.new("USP Payload")
Dispatch.dispatcher:register(usp_handler)

-- disable loading of our modules
_G['protbuf_dissector'] = nil
