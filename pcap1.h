#pragma once
int get_adapter_name(char** cAdapterName);
void clean_up_pcap1();

int get_first_non_local_IP_address( char* pc_AdapterName, unsigned int* ui_Address, char* pc_Address, unsigned int* ui_netmask);
int get_next_non_local_IP_address( unsigned int* ui_Address, char* pc_Address, unsigned int* ui_netmask);

void AdapterStatistics(char* AdapterName, char* StatisticsFilter, unsigned int* StatisticsCounter, unsigned int ui_netmask, int* ErrCode );

#define CLEAR_ERROR_STATE 0
#define ERRORS 1
#define FAILED 2

#define STATISTICS_MAP_1 1
#define STATISTICS_MAP_2 2
#define TCP 1
#define UDP 2