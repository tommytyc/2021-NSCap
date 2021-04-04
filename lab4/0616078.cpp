#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>
using namespace std;

int main(int argc, char* argv[])
{
    int option = 0;
    vector<pcap_if_t> devices;
    pcap_if_t* devices_ptr = NULL;
    char errbuff[1024];
    if(pcap_findalldevs(&devices_ptr, errbuff) != -1)
    {
        for(pcap_if_t* d = devices_ptr; d; d = d->next)
        {
            cout << option << " Name: " << d->name << endl;
            devices.push_back(*d);
            ++option;
        }
    }
    cout << "Insert a number to select interface" << endl;
    cin >> option;
    cout << "Start listening at $" << devices[option].name << endl;


    pcap_freealldevs(devices_ptr);
    return 0;
}