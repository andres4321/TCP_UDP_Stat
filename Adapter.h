#pragma once
#include "AdapterBase.h"

struct TrafficCounters { unsigned int UDPCount, TCPCount; };
typedef std::map<std::string, TrafficCounters> StatisticsMap;

class Adapter: public AdapterBase
{
#ifdef GOOGLE_TEST
public:
	virtual void Test_Adapter_Sleep(int duration) { std::this_thread::sleep_for(std::chrono::milliseconds(duration)); };
#else
private:
#endif


	StatisticsMap StatMap1, StatMap2;
	StatisticsMap* RunningStatMap = &StatMap1;

	std::future<int> StatisticsThreadExitValue;

	std::time_t LastStatisticsTakenTime;

	std::string AdapterName;

	std::mutex StatMapMutex;

	std::vector<unsigned int> LocalAddresses;


	void SetAdapterName( char* pc_AdapterName);
	void IncreaseCounter(char* remote_address, int protocol, int ErrorCode);
	void AddLocalAddress(unsigned int LocalAddress);
	unsigned int DetectRemoteAddress(unsigned int daddr, unsigned int saddr);
public:
	void StartSniffingStatistics();
	StatisticsMap& GetAdapterStatistics();
	void PrintStatistics(std::ostream* StatisticsSink, StatisticsMap& StatMap_JustTaken);
	~Adapter();
};
