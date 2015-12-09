#include <string>
#include <iostream>
#include <map>
#include <thread>
#include <iomanip>
#include <ctime>
#include <csignal>
#include <mutex>
#include <vector>
#include <iterator>
#include <algorithm>

#include "AdapterBase.h"
#include "Adapter.h"

void Adapter::SetAdapterName(char* pc_AdapterName)
{
	AdapterName = pc_AdapterName;
}

void Adapter::AddLocalAddress(unsigned int LocalAddress)
{
	LocalAddresses.push_back(LocalAddress);
}

unsigned int Adapter::DetectRemoteAddress(unsigned int daddr, unsigned int saddr)
{
	auto result = std::find(std::begin(LocalAddresses), std::end(LocalAddresses), daddr );

	if (result != std::end(LocalAddresses) )
		return saddr;
	else return daddr;
}

void Adapter::CallSniffer()
	{
		StatisticsThreadExitValue = AdapterStatistics( (char *) AdapterName.c_str() );
	}

void Adapter::IncreaseCounter(char* remote_address, int protocol, int ErrorCode)
	{
		std::lock_guard<std::mutex> lock(StatMapMutex);

		if (RunningMap == STATISTICS_MAP_1)
		{
			(protocol == TCP) ? StatMap1[std::string(remote_address)].TCPCount++ : StatMap1[std::string(remote_address)].UDPCount++;
		}
		else
		{
			(protocol == TCP) ? StatMap2[std::string(remote_address)].TCPCount++ : StatMap2[std::string(remote_address)].UDPCount++;
		}

	}

int Adapter::StartSniffingStatistics()
	{

		RunningMap = STATISTICS_MAP_1;

		StatisticsThread = std::thread( &Adapter::CallSniffer, this );

		return 0;
	}

StatisticsMap& Adapter::GetAdapterStatistics()
	{
		std::lock_guard<std::mutex> lock(StatMapMutex);

		LastStatisticsTakenTime = std::time(nullptr);

		if (RunningMap == STATISTICS_MAP_1)
		{
			RunningMap = STATISTICS_MAP_2; return StatMap1;
		}
		else
		{
			RunningMap = STATISTICS_MAP_1; return StatMap2;
		}
	}

struct TCP_Compare
{
	bool operator()(const unsigned int ui1, const unsigned int ui2) const
	{
		return !(ui1 < ui2);
	}
};


void Adapter::PrintStatistics(StatisticsMap& StatMap_JustTaken)
	{
		if (!StatisticsThread.joinable())
		{
			std::cout << "Sniffing statistics thread has exit with code " << StatisticsThreadExitValue << std::endl;
			clean_up_pcap1();
			exit(StatisticsThreadExitValue);
		}

		std::tm tm = *std::localtime(&LastStatisticsTakenTime);

		std::cout << "\n\n\nTime: " << std::put_time(&tm, "%F %T") << "\n";
		std::cout << "IP address                Number of TCP packets     Number of UDP packets\n";
		std::cout << "-------------------------------------------------------------------------\n";


		unsigned int TCP_Total = 0, UDP_Total = 0;

		struct s { std::string Address; unsigned int UDP_Count; } s_temp;
		std::multimap < unsigned int, s, TCP_Compare > Statistics_TCP_Sorted;

		for (auto &pair : StatMap_JustTaken)
		{
			s_temp.Address = pair.first;
			UDP_Total += s_temp.UDP_Count = pair.second.UDPCount;
			Statistics_TCP_Sorted.emplace(pair.second.TCPCount, s_temp);
			TCP_Total += pair.second.TCPCount;
		}
		for (auto &pair : Statistics_TCP_Sorted)
		{
			printf("%-21s     %-26d%d\n", (char*)pair.second.Address.c_str(), pair.first, pair.second.UDP_Count);
		}

		std::cout << "-------------------------------------------------------------------------\n";
		printf("%-21s     %-26d%d\n", (char *) "Total", TCP_Total, UDP_Total);

		StatMap_JustTaken.clear();
	}
