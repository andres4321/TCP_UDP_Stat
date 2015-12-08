#include <string>
#include <iostream>
#include <map>
#include <thread>
#include <iomanip>
#include <ctime>
#include <csignal>
#include "pcap1.h"

#include "Adapter.h"


class Sniffer
{
public:

	static void CallSniffer(char* AdapterName, char* FilterString, unsigned int* StatisticsCounter, unsigned int ui_netmask, int* ErrCode)
	{
		AdapterStatistics(AdapterName, FilterString, StatisticsCounter, ui_netmask, ErrCode);
	}

};

class Adapter {

private:


	StatisticsMap StatMap1, StatMap2;

	std::thread StatisticsThread;

	int RunningMap;

	Sniffer MySniffer;

	std::time_t LastStatisticsTakenTime;

public:
	std::string AdapterName;
	std::ostream *StatisticsOutStream;

	void IncreaseCounter(char* remote_address, int protocol, int ErrorCode)
	{
		if (RunningMap == STATISTICS_MAP_1)
		{
			(protocol == TCP) ? StatMap1[std::string(remote_address)].TCPCount++ : StatMap1[std::string(remote_address)].UDPCount++;
		}
		else
		{
			(protocol == TCP) ? StatMap2[std::string(remote_address)].TCPCount++ : StatMap1[std::string(remote_address)].UDPCount++;
		}

	}

	int StartSniffingStatistics()
	{

		StatisticsThread = std::thread(&Sniffer::CallSniffer, &MySniffer, (char*)AdapterName.c_str(), pair.second.FilterString, &(pair.second.TCPCount),
			pair.second.ui_netmask, &(pair.second.TCP_ErrCode));

		return 0;
	}

	StatisticsMap& GetAdapterStatistics()
	{
		return StatMap1;
	}

	void PrintStatistics(StatisticsMap& StatMap)
	{

		std::tm tm = *std::localtime(&t);

		std::cout << "\n\n\nTime: " << std::put_time(&tm, "%F %T") << "\n";
		std::cout << "IP address                Number of TCP packets     Number of UDP packets\n";
		std::cout << "-------------------------------------------------------------------------\n";


		for (auto &pair : MyAdapter.Addresses)
		{
			if (PreviousStatistics[pair.first].TCPCount <= CurrentStatistics[pair.first].TCPCount)
			{
				TCP_Total += ThisSliceStatistics[pair.first].TCPCount = CurrentStatistics[pair.first].TCPCount - PreviousStatistics[pair.first].TCPCount;
			}
			else
			{
				TCP_Total += ThisSliceStatistics[pair.first].TCPCount = CurrentStatistics[pair.first].TCPCount + 1 + ~PreviousStatistics[pair.first].TCPCount;
			}
			if (PreviousStatistics[pair.first].UDPCount <= CurrentStatistics[pair.first].UDPCount)
			{
				UDP_Total += ThisSliceStatistics[pair.first].UDPCount = CurrentStatistics[pair.first].UDPCount - PreviousStatistics[pair.first].UDPCount;
			}
			else
			{
				UDP_Total += ThisSliceStatistics[pair.first].UDPCount = CurrentStatistics[pair.first].UDPCount + 1 + ~PreviousStatistics[pair.first].UDPCount;
			}
		}

		struct s { std::string Address; unsigned int UDP_Count; } s_temp;
		std::multimap < unsigned int, s> Statistics_TCP_Sorted;

		for (auto &pair : ThisSliceStatistics)
		{
			s_temp.Address = pair.first;
			s_temp.UDP_Count = pair.second.UDPCount;
			Statistics_TCP_Sorted.emplace(pair.second.TCPCount, s_temp);
		}
		for (auto &pair : Statistics_TCP_Sorted)
		{
			printf("%-21s     %-26d%d\n", (char*)pair.second.Address.c_str(), pair.first, pair.second.UDP_Count);
		}

		std::cout << "-------------------------------------------------------------------------\n";
		printf("%-21s     %-26d%d\n", (char *) "Total", TCP_Total, UDP_Total);
	}

}; //end class