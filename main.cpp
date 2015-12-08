#include <string>
#include <iostream>
#include <map>
#include <thread>
#include <iomanip>
#include <ctime>
#include <csignal>
#include "pcap1.h"

#include "Adapter.h"

using namespace std::literals;

#define STATISTICS_MAP_1 1
#define STATISTICS_MAP_2 2
#define TCP 1
#define UDP 2


void sig_handler(int signal)
{
	if (signal == SIGINT)
	{
		clean_up_pcap1();
		exit(0);
	}
}

int main()
{
	char* pc_AdapterName;
	Adapter MyAdapter;
	int res;

	std::signal(SIGINT, sig_handler );
	std::signal(SIGABRT, sig_handler);
	std::signal(SIGTERM, sig_handler);

	if (get_adapter_name(&pc_AdapterName) == 0)
	{
		MyAdapter.AdapterName = pc_AdapterName;
	}
	if ( )
	{
		std::cout << "Error getting adapter name for statistics.\n";
		clean_up_pcap1();
		exit(1);
	}

	
//	clean_up_pcap1();


	if (MyAdapter.StartSniffingStatistics() != 0)
	{
		std::cout << "Failed starting sniffing statistics.\n";
		exit(2);
	}

	MyAdapter.StatisticsOutStream = &(std::cout);

	for (;;)
	{
		MyAdapter.LastStatisticsTakenTime = std::time(nullptr);
		MyAdapter.PrintStatistics(MyAdapter.GetAdapterStatistics());
		std::this_thread::sleep_for(5s);
	}

	return 0;
}
