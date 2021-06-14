# ProfinetIO Analyzer

The ProfinetIO analyzer makes use of the Spicy parser generator. For instructions on how to install the Spicy toolchain see https://docs.zeek.org/projects/spicy/en/latest/installation.html.

## Install the Analyzer

Using Spicy, the analyzer can be compiled just-in-time. To precompile the ProfinetIO analyzer for Zeek, do the following:
	
	# cd spicy-analyzer
	# spicyz ProfinetIO.spicy Zeek_ProfinetIO.spicy ProfinetIO.evt -o ProfinetIO.hlto

## Run the Analyzer

Use the following command to run Zeek with the ProfinetIO analyzer on a PCAP:

	# zeek spicy-analyzer/ProfinetIO.hlto spicy-analyzer/ProfinetIO.zeek scripts -r <PCAP_FILE>

The supplied scripts will detect renaming attacks and generate logs for DCP (`profinet_dcp.log`) as well as RTC (`profinet_rtc.log`).

## Data

So far, we are unable to share the attack traffic used for our validation. General Profinet example PCAPs be found for example at: https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps/profinet
