#pragma once

struct TrafficCounters { unsigned int UDPCount, TCPCount; };
typedef std::map<std::string, TrafficCounters> StatisticsMap;

class Adapter
{
public:

	void IncreaseCounter(char* remote_address, int protocol, int ErrorCode);
	int StartSniffingStatistics();
	StatisticsMap& GetAdapterStatistics();
	void PrintStatistics ( StatisticsMap& StatMap );
	std::string AdapterName;
	std::ostream *StatisticsOutStream;

};
