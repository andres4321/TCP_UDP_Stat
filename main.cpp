#include <string>
#include <iostream>
#include <map>
#include <thread>
#include <iomanip>
#include <ctime>
#include <csignal>
#include <chrono>
#include <mutex>
#include <vector>

#include "AdapterBase.h"
#include "Adapter.h"

Adapter *p_MyAdapter;

void sig_handler(int signal)
{
	if (signal == SIGINT)
	{
//		p_MyAdapter->clean_up_pcap1();
		exit(0);
	}
}

int main()
{
	char* pc_AdapterName;
	Adapter MyAdapter;
	int res;

	p_MyAdapter = &MyAdapter;
	std::signal(SIGINT, sig_handler );
	std::signal(SIGABRT, sig_handler);
	std::signal(SIGTERM, sig_handler);

	if ( MyAdapter.choose_ether_adapter_via_console() != 0)
	{
		std::cout << "Error getting adapter properties for statistics.\n";
		MyAdapter.clean_up_pcap1();
		exit(1);
	}

	MyAdapter.clean_up_pcap1();

	if (MyAdapter.StartSniffingStatistics() != 0)
	{
		std::cout << "Failed starting sniffing statistics.\n";
		exit(2);
	}


	for (;;)
	{
		std::this_thread::sleep_for(std::chrono::seconds(5));
		MyAdapter.PrintStatistics(MyAdapter.GetAdapterStatistics());
	}

	return 0;
}
