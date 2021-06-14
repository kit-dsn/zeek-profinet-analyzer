module ProfinetIO;

export {

	## Alert after this many (unanswered) idents
	const attack_ident_threshold: count = 5 &redef;

}

type AttackState: enum { Happy, DCP_Rename_Req, DCP_Rename_Resp, DCP_Ident_Old};

type EndpointState: record {
	name: string &default="Unknown";
	attack_state: AttackState &default=Happy;
	attack_xid: count &default=0;
	orig_name: string &optional;
};

global endpoint_states: table[string] of EndpointState &default=EndpointState();
global endpoint_idents: table[string] of count &default=0;
global renamed_endpoints: table[string] of string;


event ProfinetIO::dcp_request(hdr: DCPHeader, blocks: vector of DCPBlock)
	{
	if ( hdr$service_id != 0x06 ) # Hello
		return;

	local ph = get_current_packet_header();
	local ep = ph$l2$src;
	local eps = endpoint_states[ep];

	for ( i in blocks )
		{
		local block = blocks[i];

		if ( block$opt == 0x02 &&   # Device options
			 block$subopt == 0x02 ) # NameOfStation suboption
			{
			eps$name = block$data[2:];
			endpoint_states[ep] = eps;
			return;
			}
		}
	}

event ProfinetIO::dcp_request(hdr: DCPHeader, blocks: vector of DCPBlock)
	{
	if ( hdr$service_id != 0x04 ) # Set value
		return;

	local ph = get_current_packet_header();
	local ep = ph$l2$dst;
	local eps = endpoint_states[ep];

	for ( i in blocks )
		{
		local block = blocks[i];

		if ( block$opt == 0x02 &&   # Device options
			 block$subopt == 0x02 ) # NameOfStation suboption
			{
			eps$attack_state = DCP_Rename_Req;
			eps$attack_xid = hdr$xid;
			eps$orig_name = eps$name;
			eps$name = block$data[2:];
			endpoint_states[ep] = eps;

			print fmt("Trying to rename %s to %s", eps$orig_name, eps$name);
			return;
			}
		}
	}

event ProfinetIO::dcp_response(hdr: DCPHeader, blocks: vector of DCPBlock)
	{
	local ph = get_current_packet_header();
	local ep = ph$l2$src;
	local eps = endpoint_states[ep];

	if ( eps$attack_state != DCP_Rename_Req )
		return;

	if ( (hdr$service_id != 0x04) || !hdr$success ) # Set value success
		return;

	for ( i in blocks )
		{
		local block = blocks[i];

		if ( block$opt == 0x05    && # Device options
			 block$subopt == 0x04 && # NameOfStation suboption
			 hdr$xid == eps$attack_xid )
			{
			eps$attack_state = DCP_Rename_Resp;
			endpoint_states[ep] = eps;
			endpoint_idents[eps$name] = 0;
			renamed_endpoints[eps$orig_name] = eps$name;

			print fmt("Renaming successful");
			return;
			}
		}
	}

event ProfinetIO::dcp_request(hdr: DCPHeader, blocks: vector of DCPBlock)
	{
	if ( hdr$service_id != 0x05 ) # Identify
		return;

	for ( i in blocks )
		{
		local block = blocks[i];

		if ( block$opt == 0x02 &&   # Device options
			 block$subopt == 0x02 ) # NameOfStation suboption
			{
			#attack_state = DCP_Ident_Old;
			local ep_name = block$data;
			endpoint_idents[ep_name] += 1;

			if ( endpoint_idents[ep_name] % attack_ident_threshold == 0 )
				{ 
				print fmt("Ident threshold (%d) crossed for %s --> %d",
					attack_ident_threshold, ep_name, endpoint_idents[ep_name]);
				}

			if ( ep_name in renamed_endpoints )
				{
				print fmt("(!) Ident for previously renamed endpoint %s (%s)",
					ep_name, renamed_endpoints[ep_name]);
				delete renamed_endpoints[ep_name];
				}
			return;
			}
		}
	}
