  do
	local elliptics_proto = Proto("elliptics", "Elliptics");
	
	local elliptics_command = function(label, fields)
		return {
			["label"] = label,
			["parse"] = function(buffer, off, tree)
							return 1
						end
		}
	end
	
	local commands = {
		[1] = elliptics_command(
			"DNET_CMD_LOOKUP", {}
		),
		[2] = elliptics_command(
			"DNET_CMD_REVERSE_LOOKUP", {}
		),
		[3] = elliptics_command(
			"DNET_CMD_JOIN", {}
		),
		[4] = elliptics_command(
			"DNET_CMD_WRITE", {}
		),
		[5] = elliptics_command(
			"DNET_CMD_READ", {}
		),
		[6] = elliptics_command(
			"DNET_CMD_LIST", {}
		),
		[7] = elliptics_command(
			"DNET_CMD_EXEC", {}
		),
		[8] = elliptics_command(
			"DNET_CMD_ROUTE_LIST", {}
		),
		[9] = elliptics_command(
			"DNET_CMD_STAT", {}
		),
		[10] = elliptics_command(
			"DNET_CMD_NOTIFY", {}
		),
		[11] = elliptics_command(
			"DNET_CMD_DEL", {}
		),
		[12] = elliptics_command(
			"DNET_CMD_STATUS", {}
		),
		[13] = elliptics_command(
			"DNET_CMD_READ_RANGE", {}
		),
		[14] = elliptics_command(
			"DNET_CMD_DEL_RANGE", {}
		),
		[15] = elliptics_command(
			"DNET_CMD_AUTH", {}
		),
		[16] = elliptics_command(
			"DNET_CMD_BULK_READ", {}
		),
		[17] = elliptics_command(
			"DNET_CMD_DEFRAG", {}
		),
		[18] = elliptics_command(
			"DNET_CMD_ITERATOR", {}
		)
	}
	
	local unknown_command = elliptics_command(
		"DNET_CMD_UNKNOWN", {}
	)
	
	function elliptics_proto.dissector(buffer, pinfo, tree)
		pinfo.cols.protocol = "ELLIPTICS"
		
		local header_size = 104
		local buf_len = buffer:len()
		local offset = 0
		
		while offset + header_size <= buf_len do
			local data_size = buffer(96, 4):le_uint()
			local packet_size = header_size + data_size
			
			if buf_len - offset < packet_size then
				break
			end
			
			local item = tree:add(elliptics_proto, buffer(offset, packet_size), "Elliptics CMD Header")
			
			local dnet_id = item:add(elliptics_proto, buffer(offset + 0, 72), "dnet_id")
			dnet_id:add(buffer(offset + 0, 64), "id: " .. tostring(buffer(offset + 0, 64)))
			dnet_id:add(buffer(offset + 64, 4), "group_id: " .. buffer(offset + 64, 4):le_uint())
			dnet_id:add(buffer(offset + 68, 4), "type: " .. buffer(offset + 68, 4):le_uint())
			
			local cmd_id = buffer(offset + 76, 4):le_uint()
			local cmd = commands[cmd_id]
			local cmd_label
			if cmd == nil then
				cmd = unknown_command
			end
			
			item:add(buffer(offset + 72, 4), "status: " .. buffer(offset + 72, 4):le_uint())
			item:add(buffer(offset + 76, 4), "cmd: " .. cmd.label .. " (" .. cmd_id .. ")")
			item:add(buffer(offset + 80, 8), "flags: " .. tostring(buffer(offset + 80, 8)))
			item:add(buffer(offset + 88, 8), "trans: " .. tostring(buffer(offset + 88, 8)))
			item:add(buffer(offset + 96, 8), "size: " .. buffer(offset + 96, 4):le_uint())
			if data_size > 0 then
				item:add(buffer(offset + 104, data_size), "data: " .. tostring(buffer(offset + 104, data_size)))
			end
			
			offset = offset + packet_size
		end
		
		if offset ~= buf_len then
			pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
			pinfo.desegment_offset = offset
			return DESEGMENT_ONE_MORE_SEGMENT
			end
		
		return buf_len
	end

	local tcp_table = DissectorTable.get("tcp.port")
	tcp_table:add(1025, elliptics_proto)
  end

