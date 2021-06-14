module PacketAnalyzer::SPICY_PROFINETIO;

module ProfinetIO;

export {

	type DCPHeader: record {
		## Service Identifier
		service_id:	count;
		## True if service_types indicates request
		request:	bool;
		## True if service_types indicates response
		response:	bool;
		## True if service_types indicates success
		success:	bool;
		## Xid
		xid:	count;
		## Response delay
		response_delay:	count;
	};

	type DCPBlock: record {
		## Option
		opt:	count;
		## Suboption
		subopt:	count;
		## Raw data
		len:	count;
		data:	string;
	};

	type RTCHeader: record {
		## RTC data
		data:	string;
		## Cycle counter
		cycle_counter:	count;
		## Data status
		data_status:	count;
		## Transfer status
		transfer_status:	count;
	};

}

event zeek_init()
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x8892, "spicy::ProfinetIO") )
		print "cannot register ProfinetIO analyzer";
	}
