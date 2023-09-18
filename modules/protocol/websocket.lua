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
-- Websocket definitions.
--

local WebsocketHandler = {}


local WebsocketHandler_mt = { __index = WebsocketHandler }
setmetatable( WebsocketHandler, { __index = Dispatch.Handler } )


function WebsocketHandler.new(payload_name, port_type, port)
    local new_class = Handler.new(Payload.new(payload_name), port_type, port)
    setmetatable( new_class, WebsocketHandler_mt )
    return new_class
end


local websocket_dissector = Dissector.get("websocket")
local payload_field = Field.new("websocket.payload")

-- this is only called if the port_type and port match those supplied in the
-- constructor
function WebsocketHandler:dissect_app_packet(tvbuf, pktinfo, root)
    -- dissect the Websocket header
    websocket_dissector:call(tvbuf, pktinfo, root)
    local payload_field_info = payload_field()

    -- if there's no Websocket payload (or it's empty), we're done
    if not payload_field_info or payload_field_info.len == 0 then
        return

    -- otherwise, the payload is always within the packet, so convert the
    -- range to a buffer directly
    else
        return payload_field_info.range:tvb()
    end
end


-- this isn't needed (and needn't really be defined) because the Websocket
-- payload is handled by dissect_app_packet()
function WebsocketHandler:check_sublayer_payload(tvbuf, pktinfo, root)
end


return WebsocketHandler
