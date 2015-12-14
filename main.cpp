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
#include <future>

#include "AdapterBase.h"
#include "Adapter.h"


int main()
{
	Adapter MyAdapter;


	if ( MyAdapter.choose_ether_adapter_via_console() != 0)
	{
		std::cout << "Error getting adapter properties for statistics.\n";
		exit(1);
	}


	try
	{
		MyAdapter.StartSniffingStatistics();

		for (;;)
		{
			std::this_thread::sleep_for(std::chrono::seconds(5));
			MyAdapter.PrintStatistics(&std::cout, MyAdapter.GetAdapterStatistics());
		}
	}
	catch (std::exception e)
	{
		std::cout << std::endl << e.what() << std::endl;
	}

	return 2;
}
