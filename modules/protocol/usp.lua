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
-- USP definitions.
--

-- XXX should really be a USPRecordHandler?
local USPHandler = {}
local USPHandler_mt = { __index = USPHandler }
setmetatable( USPHandler, { __index = Dispatch.Handler } )


local function new_payload(payload_name)
    local payload_sar_states = {BEGIN = 1, INPROCESS = 2, COMPLETE = 3}

    local function map_payload_sar_state_to_more(evalue)
        if evalue == nil then
            return false
        else
            return evalue ~= payload_sar_states.COMPLETE
        end
    end

    -- XXX these names need to be unique within the USP record (if they
    --     weren't, we'd need to add decoder field name path logic)
    return Payload.new(payload_name,
        {
            session = { "session_id" },
            block = { "sequence_id" },
            more = { "payload_sar_state", map_payload_sar_state_to_more },
            payload = { "payload" },
        }
    )
end


function USPHandler.new(payload_name, port_type, port)
    local new_class = Handler.new(new_payload(payload_name), port_type, port)
    setmetatable( new_class, USPHandler_mt )
    return new_class
end


-- this isn't needed (and needn't really be defined) because USP never carries
-- an application payload!
function USPHandler:dissect_app_packet(tvbuf, pktinfo, root)
end

local usp_msg_dissector = Dissector.get("usp.msg")

-- for USP, "sub-layer" means USP Msg
function USPHandler:check_sublayer_payload(tvbuf, pktinfo, root)
    if not self.payload:more() then
        local payload_hex_string = self.payload:get_payload_hex_string()
        if payload_hex_string ~= nil then
            -- this needs to be a _new_ buffer so the offset will be zero when
            -- we process it (so we know not to look for an application header)
            -- XXX but this is a hack; it's better only to create a new buffer
            --     when absolutely necessary
            local new_tvbuf =
                ByteArray.new(payload_hex_string):tvb(self.payload.name)
            usp_msg_dissector:call(new_tvbuf, pktinfo, root)
        end
    end
end


return USPHandler
