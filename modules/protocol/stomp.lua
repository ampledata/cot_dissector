----------------------------------------
--
-- Copyright (c) 2018, Honu Ltd.
--
-- author: William Lupton <william@honu.co.uk>
--
-- This code is licensed under the MIT license.
--
-- Version: 1.0
--
------------------------------------------

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


local Settings = require "settings"
local dprint   = Settings.dprint
local dprint2  = Settings.dprint2
local dassert  = Settings.dassert
local derror   = Settings.derror
local dsummary = Settings.dsummary

local Dispatch = require "protocol.dispatch"
local Payload  = require "protocol.payload"

local Handler  = Dispatch.Handler

-------------------------------------------------------------------------------
-- STOMP definitions.
--

local STOMPHandler = {}


local STOMPHandler_mt = { __index = STOMPHandler }
setmetatable( STOMPHandler, { __index = Dispatch.Handler } )


function STOMPHandler.new(payload_name, port_type, port)
    local new_class = Handler.new(Payload.new(payload_name), port_type, port)
    setmetatable( new_class, STOMPHandler_mt )
    return new_class
end


local stomp_dissector = Dissector.get("stomp")
local payload_field = Field.new("stomp.body")

-- this is only called if the port_type and port match those supplied in the
-- constructor
function STOMPHandler:dissect_app_packet(tvbuf, pktinfo, root)
    -- dissect the STOMP header
    stomp_dissector:call(tvbuf, pktinfo, root)
    local payload_field_info = payload_field()

    -- if there's no STOMP payload (or it's empty), we're done
    if not payload_field_info or payload_field_info.len == 0 then
        return

    -- otherwise, the payload is always within the packet, so convert the
    -- range to a buffer directly
    else
        return payload_field_info.range:tvb()
    end
end


-- this isn't needed (and needn't really be defined) because the STOMP payload
-- is handled by dissect_app_packet()
function STOMPHandler:check_sublayer_payload(tvbuf, pktinfo, root)
end


return STOMPHandler
