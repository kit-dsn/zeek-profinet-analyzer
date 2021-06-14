module ProfinetIO;

export {
	redef enum Log::ID += { LOG_DCP, LOG_RTC };

	# Define the record type that will contain the DCP data to log.
	type DCPInfo: record {
		ts: time &log;
		frame_id:       count &log;
		service_id:     count &log;
		request:	    bool &log;
		response:	    bool &log;
		success:	    bool &log;
		xid:            count &log;
		response_delay: count &log;
	};

	# Define the record type that will contain the RTC data to log.
	type RTCInfo: record {
		ts: time &log;
		frame_id:        count &log;
		cycle_counter:   count &log;
		data_status:     count &log;
		transfer_status: count &log;
	};
}

event zeek_init() &priority=5
	{
	Log::create_stream(ProfinetIO::LOG_DCP, [$columns=DCPInfo, $path="profinet_dcp"]);
	Log::create_stream(ProfinetIO::LOG_RTC, [$columns=RTCInfo, $path="profinet_rtc"]);
	}

event ProfinetIO::dcp_message(frame_id: count, hdr: DCPHeader, blocks: vector of DCPBlock)
	{
	local rec: ProfinetIO::DCPInfo = [
		$ts = network_time(),
		$frame_id = frame_id,
		$service_id = hdr$service_id,
		$request = hdr$request,
		$response = hdr$response,
		$success = hdr$success,
		$xid = hdr$service_id,
		$response_delay = hdr$xid];

	Log::write(ProfinetIO::LOG_DCP, rec);
	}

event ProfinetIO::rtc_message(frame_id: count, hdr: RTCHeader)
	{
	local rec: ProfinetIO::RTCInfo = [
		$ts = network_time(),
		$frame_id = frame_id,
		$cycle_counter = hdr$cycle_counter,
		$data_status = hdr$data_status,
		$transfer_status = hdr$transfer_status];

	Log::write(ProfinetIO::LOG_RTC, rec);
	}
