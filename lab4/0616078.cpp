#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <vector>
#include <string>
#include <cstring>
#define MAC_LEN 14
using namespace std;

bool brgr0 = 0;

typedef struct PKT_INFO{
    string out_src_mac_addr;
    string in_src_mac_addr;
    string out_dst_mac_addr;
    string in_dst_mac_addr;
    char src_ip_addr[INET_ADDRSTRLEN];
    char dst_ip_addr[INET_ADDRSTRLEN];
    u_char ip_next;
    u_int16_t in_eth_next;
    u_int16_t out_eth_next;
    u_int16_t gre_proto;
} pkt_info;

struct GRE_HDR{
    u_int16_t gre_garbage;
    u_int16_t gre_proto;
};

bool dump_content(const u_char* content, pkt_info *info)
{
    pkt_info tmp_info;
    struct ether_header* out_eth_hdr  = (struct ether_header*)content;
    char mac[MAC_LEN];
    tmp_info.out_src_mac_addr = string(ether_ntoa((const struct ether_addr *)&out_eth_hdr->ether_shost));
    tmp_info.out_dst_mac_addr = string(ether_ntoa((const struct ether_addr *)&out_eth_hdr->ether_dhost));
    tmp_info.out_eth_next = ntohs(out_eth_hdr->ether_type);
    if(tmp_info.out_eth_next == ETHERTYPE_IP)
    {
        struct ip* ip_hdr = (struct ip*)(content + MAC_LEN);
        inet_ntop(AF_INET, &ip_hdr->ip_src, tmp_info.src_ip_addr, sizeof(tmp_info.src_ip_addr));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, tmp_info.dst_ip_addr, sizeof(tmp_info.dst_ip_addr));
        tmp_info.ip_next = ip_hdr->ip_p;
        unsigned int ip_total_len = ip_hdr->ip_hl << 2;
        if(tmp_info.ip_next == IPPROTO_GRE)
        {
            struct ether_header* in_eth_hdr  = (struct ether_header*)(content + MAC_LEN + ip_total_len + 4);
            tmp_info.in_src_mac_addr = string(ether_ntoa((const struct ether_addr *)&in_eth_hdr->ether_shost));
            tmp_info.in_dst_mac_addr = string(ether_ntoa((const struct ether_addr *)&in_eth_hdr->ether_dhost));
            tmp_info.in_eth_next = ntohs(in_eth_hdr->ether_type);
            struct GRE_HDR* gre = (struct GRE_HDR*)(content + MAC_LEN + ip_total_len);
            tmp_info.gre_proto = ntohs(gre->gre_proto);
            *info = tmp_info;
            return 1;
        }
        else
            return 0;
    }
    else
        return 0;

}

void get_packet(int* id, pcap_pkthdr* hdr, const u_char * content, string* new_rule, bool* new_rule_flag)
{
    pkt_info info;
    int flag = dump_content(content, &info);
    if(flag)
    {
        cout << "Packet Num [" << *id << "]\n";
        for(int i = 0; i < hdr->caplen; i++)
        {
            cout << hex << setfill('0') << setw(2) <<static_cast<unsigned>(content[i]) << " ";
            if((i+1) % 10 == 0)
                cout << endl;
        }
        cout << dec << setfill(' ') << setw(0);
        cout << "\n" << endl;
        cout << "Outer Ethernet:" << endl;
        cout << "Src MAC " << info.out_src_mac_addr << endl;
        cout << "Dst MAC " << info.out_dst_mac_addr << endl;
        cout << "Ethernet Type: " << hex << info.out_eth_next << endl;
        cout << dec;
        cout << "Src IP " << info.src_ip_addr << endl;
        cout << "Dst IP " << info.dst_ip_addr << endl;
        cout << "Next Layer Protocol: GRE\n" << endl;
        cout << "GRE Protocol: " << hex << info.gre_proto << endl;
        cout << dec;
        cout << "Inner Ethernet:" << endl;
        cout << "Src MAC " << info.in_src_mac_addr << endl;
        cout << "Dst MAC " << info.in_dst_mac_addr << endl;
        cout << "Ether Type: " << hex << info.in_eth_next << endl;
        cout << dec;
        cout << "Tunnel Finish!\n" << endl;
        if(!brgr0)
        {
            system("ip link add br0 type bridge");
            system("brctl addif br0 BRGr-eth0");
            brgr0 = 1;
        }
        string tmp = "ip link add " + to_string(*id) + " type gretap remote ";
        tmp += (string(info.src_ip_addr) + " local 140.113.0.1");
        system(tmp.c_str());
        system(string("ip link set " + to_string(*id) + " up").c_str());
        system(string("brctl addif br0 " + to_string(*id)).c_str());
        system("ip link set br0 up");
        
        *new_rule = (*new_rule) + " and not host " + string(info.src_ip_addr);
        *new_rule_flag = 1;
        *id = *id + 1;
    }
    new_rule_flag = 0;
}

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
    cout << "Insert a number to select interface\n";
    cin >> option;
    cout << "Start listening at $" << devices[option].name << endl;

    pcap_t *handle = NULL;
    bpf_u_int32 net, mask;
    string bpf_rule = "";
    handle = pcap_open_live(devices[option].name, 65536, 1, 1, errbuff);
    if(!handle){
        cerr << pcap_geterr(handle) << endl;
        pcap_close(handle);
        exit(1);
    }

    pcap_lookupnet(devices[option].name, &net, &mask, errbuff);

    cout << "Insert BPF filter expression:\n";
    cin.ignore();
    getline(cin, bpf_rule);
    bpf_rule += " and not src 140.113.0.1";
    string new_rule = "";
    bool new_rule_flag = 0;
    int id = 0;
    while(1)
    {
        struct bpf_program code;
        new_rule = bpf_rule;
        if(0 == pcap_compile(handle, &code, bpf_rule.c_str(), 1, mask))
        {
            if(0 == pcap_setfilter(handle, &code))
            {
                pcap_freecode(&code);
                while(1)
                {
                    pcap_pkthdr* hdr = NULL;
                    const u_char* content = NULL;
                    int ret = pcap_next_ex(handle, &hdr, &content);
                    if(ret == 1)
                    {
                        get_packet(&id, hdr, content, &new_rule, &new_rule_flag);
                        if(new_rule_flag)
                        {
                            bpf_rule = new_rule;
                            break;
                        }
                    }
                }
            }
        }
    }
    
    pcap_close(handle);
    pcap_freealldevs(devices_ptr);
    return 0;
}