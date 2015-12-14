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
#include <future>

#include "AdapterBase.h"
#include "Adapter.h"

#define TestSniffingThreadAlive \
	auto status = StatisticsThreadExitValue.wait_for(std::chrono::milliseconds(0)); \
	if (status == std::future_status::ready) \
	{ \
		std::string _ErrorMessage = std::string("Sniffing statistics thread has exited with code ") + std::to_string(StatisticsThreadExitValue.get()); \
		throw std::exception(_ErrorMessage.c_str()); \
	} 



Adapter::~Adapter()
{
	if ( g_alldevs ) clean_up_pcap1();
}

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

void Adapter::IncreaseCounter(char* remote_address, int protocol, int ErrorCode)
	{
		std::lock_guard<std::mutex> lock(StatMapMutex);

		(protocol == TCP) ? (*RunningStatMap)[std::string(remote_address)].TCPCount++ : (*RunningStatMap)[std::string(remote_address)].UDPCount++;

	}

void Adapter::StartSniffingStatistics()
	{

		RunningStatMap = &StatMap1;

		StatisticsThreadExitValue = std::async(std::launch::async, [this]{ return this->AdapterStatistics((char *)AdapterName.c_str()); });

		TestSniffingThreadAlive;
	}

StatisticsMap& Adapter::GetAdapterStatistics()
	{
		TestSniffingThreadAlive;

		std::lock_guard<std::mutex> lock(StatMapMutex);

		LastStatisticsTakenTime = std::time(nullptr);

		if ( &StatMap1 == RunningStatMap )
		{
			StatMap2.clear();  RunningStatMap = &StatMap2; return StatMap1;
		}
		else
		{
			StatMap1.clear(); RunningStatMap = &StatMap1; return StatMap2;
		}
}

struct TCP_Compare
{
	bool operator()(const unsigned int ui1, const unsigned int ui2) const
	{
		return !(ui1 <= ui2);
	}
};


void Adapter::PrintStatistics(std::ostream* StatisticsSink, StatisticsMap& StatMap_JustTaken)
	{

		std::tm tm = *std::localtime(&LastStatisticsTakenTime);

		(*StatisticsSink) << "\n\n\nTime: " << std::put_time(&tm, "%F %T") << "\n";
		(*StatisticsSink) << "IP address                Number of TCP packets     Number of UDP packets\n";
		(*StatisticsSink) << "-------------------------------------------------------------------------\n";


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
			(*StatisticsSink) << std::setfill(' ') << std::setw(26) << std::left << pair.second.Address.c_str() << std::setw(26) << pair.first << std::setw(0) << pair.second.UDP_Count << std::endl;
		}

		(*StatisticsSink) << "-------------------------------------------------------------------------\n";
		(*StatisticsSink) << std::setfill(' ') << std::setw(26) << std::left << "Total" << std::setw(26) << TCP_Total << std::setw(0) << UDP_Total << std::endl;

	}
