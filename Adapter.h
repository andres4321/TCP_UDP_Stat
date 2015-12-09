#pragma once
#include "AdapterBase.h"

struct TrafficCounters { unsigned int UDPCount, TCPCount; };
typedef std::map<std::string, TrafficCounters> StatisticsMap;

class Adapter: public AdapterBase
{
private:


	StatisticsMap StatMap1, StatMap2;

	std::thread StatisticsThread;

	int RunningMap, StatisticsThreadExitValue;

	std::time_t LastStatisticsTakenTime;

	std::string AdapterName;
	std::ostream *StatisticsOutStream;

	std::mutex StatMapMutex;

	std::vector<unsigned int> LocalAddresses;


	void SetAdapterName( char* pc_AdapterName);
	void IncreaseCounter(char* remote_address, int protocol, int ErrorCode);
	void CallSniffer();
	void AddLocalAddress(unsigned int LocalAddress);
	unsigned int DetectRemoteAddress(unsigned int daddr, unsigned int saddr);

public:
	int StartSniffingStatistics();
	StatisticsMap& GetAdapterStatistics();
	void PrintStatistics(StatisticsMap& StatMap_JustTaken);
};
