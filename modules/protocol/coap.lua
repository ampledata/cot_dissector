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
-- CoAP definitions.
--

local CoAPHandler = {}


local CoAPHandler_mt = { __index = CoAPHandler }
setmetatable( CoAPHandler, { __index = Dispatch.Handler } )


local function new_payload(payload_name)
    return Payload.new(payload_name,
        {
            session = { "coap.token" },
            block = { "coap.opt.block_number" },
            more = { "coap.opt.block_mflag" },
            payload = { "coap.payload" },
        }
    )
end

function CoAPHandler.new(payload_name, port_type, port)
    local new_class = Handler.new(new_payload(payload_name), port_type, port)
    setmetatable( new_class, CoAPHandler_mt )
    return new_class
end


-- XXX should define constants for these names
local coap_dissector = Dissector.get("coap")
local name_field = Field.new("coap.opt.name")
local session_field = Field.new("coap.token")
local block_field = Field.new("coap.opt.block_number")
local more_field = Field.new("coap.opt.block_mflag")
local payload_field = Field.new("coap.payload")

-- gets header field values from the current packet
local function get_header_field_values()
    -- get the session
    local session_field_info = session_field()
    local session = tostring(session_field_info.value)

    -- determine "Block1" and "Block2" option existence and order (we want
    -- "Block1")
    local name_field_info = { name_field() }
    local block1_index
    local block2_index
    for i, info in ipairs(name_field_info) do
        local last6 = info.value:sub(-6, -1)
        if last6 == "Block1" then
            block1_index = i
        elseif last6 == "Block2" then
            block2_index = i
        end
    end

    -- determine the block number and more flag
    local block = 1
    local more = false
    if block1_index then
        local block_and_more_index
        if block2_index and block2_index < block1_index then
            block_and_more_index = 2
        else
            block_and_more_index = 1
        end
        local block_field_info = { block_field() }
        local more_field_info = { more_field() }
        block = block_field_info[block_and_more_index].value + 1
        more = more_field_info[block_and_more_index].value == 1
    end

    return session, block, more, payload_field()
end

-- this is only called if the port_type and port match those supplied in the
-- constructor
function CoAPHandler:dissect_app_packet(tvbuf, pktinfo, root)
    -- dissect the CoAP header
    coap_dissector:call(tvbuf, pktinfo, root)

    -- get the necessary info from the CoAP header fields
    local session, block, more, payload_field_info = get_header_field_values()

    -- if there's no CoAP payload (or it's empty), we're done
    if not payload_field_info or payload_field_info.len == 0 then
        return
    end

    -- if (block,more) = (1,false), the payload is within the packet, so
    -- convert the range to a buffer directly
    if block == 1 and not more then
        dprint("payload directly in packet")
        return payload_field_info.range:tvb()
    end

    -- otherwise, set the field values and, if there is now a complete payload,
    -- create and return a new buffer
    self.payload:set_field_values(
        pktinfo.number, {session=session, block=block, more=more,
                         payload=payload_field_info.range}, true)
    if not more then
        local payload_hex_string = self.payload:get_payload_hex_string()
        return ByteArray.new(payload_hex_string):tvb(self.payload.name)
    end

    -- otherwise, there isn't yet a complete payload, so return nothing
end


-- this isn't needed (and needn't really be defined) because the CoAP payload
-- is handled by dissect_app_packet()
function CoAPHandler:check_sublayer_payload(tvbuf, pktinfo, root)
end


return CoAPHandler
