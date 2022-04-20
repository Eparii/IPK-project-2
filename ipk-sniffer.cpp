#include <iostream>
#include <bitset>
#include <cstring>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstdio>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ctime>

#define WRONG_ARGUMENTS_ERROR 10
#define WRONG_ARGUMENT_NUMBER_ERROR 11
#define OPENING_INTERFACE_ERROR 12
#define NO_ETHERNET_HEADER_ERROR 13
#define NETMASK_ERROR 14
#define FILTER_COMPILING_ERROR 15
#define FILTER_APPLYING_ERROR 16
#define PCAP_LOOP_ERROR 17

#define ETHERNET_SIZE 14
#define IPV6_HEADER_SIZE 40

bool interface_arg;
std::string interface_name;
int port;
int packet_num;
bool tcp_arg;
bool udp_arg;
bool arp_arg;
bool icmp_arg;

// funkce slouzici k vypisu chybovych hlasek a ukonceni programu
void print_error(int errorcode)
{
    if(errorcode == WRONG_ARGUMENTS_ERROR)
    {
        std::cerr << "Wrong number of arguments" << std::endl;
    }
    else if (errorcode == WRONG_ARGUMENT_NUMBER_ERROR)
    {
        std::cerr << "Wrong number after -p or -n argument" << std::endl;
    }
    else if (errorcode == OPENING_INTERFACE_ERROR)
    {
        std::cerr << "Error in opening entered interface" << interface_name << std::endl;
    }
    else if (errorcode == NO_ETHERNET_HEADER_ERROR)
    {
        std::cerr << "Entered interface_name " << interface_name << " doesn't provide Ethernet headers" << std::endl;
    }
    else if (errorcode == NETMASK_ERROR)
    {
        std::cerr << "Problem with getting mask for interface_name " << interface_name << std::endl;
    }
    else if (errorcode == FILTER_COMPILING_ERROR)
    {
        std::cerr << "Problem with filter compiling" << std::endl;
    }
    else if (errorcode == FILTER_APPLYING_ERROR)
    {
        std::cerr << "Problem with filter applying" << std::endl;
    }
    else if (errorcode == PCAP_LOOP_ERROR)
    {
        std::cerr << "Problem in pcap_loop()" << std::endl;
    }
    exit(2);
}

/* funkce slouzici k parsovani argumentu a naslednemu ulozeni, zda
 * byly zadany, a pripadne i ulozeni jejich parametru
 *
 * Vse je ukladano do predem definovanych globalnich promennych */
void parse_arguments(int argc, char* argv[])
{
    for (int i = 1; i < argc; i++)
    {
        char* ptr; // slouzi pro ukladani znaku, ktere nasleduji po cisle
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface_name") == 0)
        {
            if (interface_arg)
                print_error(WRONG_ARGUMENTS_ERROR);
            interface_arg = true;
            if (i + 1 < argc) // pokud se nejedna o posledni argument
            {
                if (argv[i + 1][0] != '-') // pokud je dalsi argument parametr rozhrani
                {
                    interface_name = argv[i + 1];
                    i++;
                }
            }
        }
        else if (strcmp(argv[i], "-p") == 0)
        {
            if (port)
                print_error(WRONG_ARGUMENTS_ERROR);
            if (i + 1 == argc)
                print_error(WRONG_ARGUMENTS_ERROR);
            port = (int)strtol(argv[i + 1], &ptr, 10);
            if (*ptr != '\0')
            {
                print_error(WRONG_ARGUMENT_NUMBER_ERROR);
            }
            i++; // preskoci se nasledujici argument, ve kterem se nachazi cislo portu
        }
        if (strcmp(argv[i], "-n") == 0)
        {
            if (packet_num)
                print_error(WRONG_ARGUMENTS_ERROR);
            if (i + 1 == argc)
                print_error(WRONG_ARGUMENTS_ERROR);
            packet_num = (int)strtol(argv[i + 1], &ptr, 10);
            if (*ptr != '\0')
            {
                print_error(WRONG_ARGUMENT_NUMBER_ERROR);
            }
            i++; // preskoci se nasledujici argument, ve kterem se nachazi pocet packetu
        }
        else if(strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0)
        {
            if (tcp_arg)
                print_error(WRONG_ARGUMENTS_ERROR);
            tcp_arg = true;
        }
        else if(strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0)
        {
            if (udp_arg)
                print_error(WRONG_ARGUMENTS_ERROR);
            udp_arg = true;
        }
        else if(strcmp(argv[i], "--arp") == 0)
        {
            if (arp_arg)
                print_error(WRONG_ARGUMENTS_ERROR);
            arp_arg = true;
        }
        else if(strcmp(argv[i], "--icmp") == 0)
        {
            if (icmp_arg)
                print_error(WRONG_ARGUMENTS_ERROR);
            icmp_arg = true;
        }
    }
}

// funkce slouzici pro vytvoreni filtru
std::string create_filter()
{
    std::string filter;
    return filter;
}

// funkce slouzici k vytisknuti vsech rozhrani
void get_all_interfaces()
{
    char errorbuffer[PCAP_ERRBUF_SIZE+1];
    pcap_if_t *device;
    pcap_findalldevs(&device, errorbuffer);
    while (device->next != nullptr)
    {
        std::cout << device->name << std::endl;
        device = device->next;
    }
    exit(0);
}

void print_timestamp(timeval time)
{
    auto tm = localtime(&time.tv_sec);
    tm->tm_year+=1900; // obdrzene roky byly pocet let od 1.1.1900
    tm->tm_mon+=1; // mesice se pocitaly od 0
    char time_string[1024];
    int zone = (int)tm->tm_gmtoff/3600; // prevedeni zony ze sekund na hodiny
    char sign;
    zone > 0 ? sign = '+' : sign = '-';
    sprintf(time_string, "%d-%02d-%02dT%02d:%02d:%02d.%d%c%02d:00",
            tm->tm_year, tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min,
            tm->tm_sec, (int)time.tv_usec, sign, zone);
    std::cout << time_string << std::endl;
}

void print_mac_addresses(struct ether_header *eth_header)
{
    printf("src MAC: ");
    for (int i = 0; i < 5; i++)
    {
        printf("%02x:", eth_header->ether_shost[i]);
    }
    printf("%02x\n", eth_header->ether_shost[5]);

    printf("dst MAC: ");
    for (int i = 0; i < 5; i++)
    {
        printf("%02x:", eth_header->ether_dhost[i]);
    }
    printf("%02x\n", eth_header->ether_dhost[5]);
}

void print_ips_arp(struct ether_arp* arp_packet)
{
    printf("src IP: ");
    for (int i = 0; i < 3; i++)
    {
        printf("%d.", arp_packet->arp_spa[i]);
    }
    printf("%d\n", arp_packet->arp_spa[3]);

    printf("dst IP: ");
    for (int i = 0; i < 3; i++)
    {
        printf("%d.", arp_packet->arp_tpa[i]);
    }
    printf("%d\n", arp_packet->arp_tpa[3]);
}

void print_ips_ipv4(struct ip* ipv4_packet)
{
    auto src_ip = inet_ntoa(ipv4_packet->ip_dst);
    auto dst_ip = inet_ntoa(ipv4_packet->ip_dst);
    printf("src IP: %s\n", src_ip);
    printf("dst IP: %s\n", dst_ip);
}

void print_ips_ipv6(struct ip6_hdr* ipv6_packet)
{
    char src_address[256]{};
    char dst_address[256]{};

    inet_ntop(AF_INET6, &(ipv6_packet->ip6_src), src_address, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_packet->ip6_dst), dst_address, INET6_ADDRSTRLEN);

    std::cout << "src IP: " << src_address << std::endl;
    std::cout << "dst IP: " << dst_address << std::endl;

}


/* funkce, ve ktere se deje veskere zpracovani packetu.
 * Jedna se o callback pro pcap_loop() */
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    print_timestamp(header->ts);
    auto *eth_header = (struct ether_header *) packet;
    print_mac_addresses(eth_header);
    struct ip* ipv4_packet;
    int ipv4_header_size;
    struct ip6_hdr* ipv6_packet;
    struct icmphdr* icmp_packet;
    struct tcphdr* tcp_packet;
    struct udphdr* udp_packet;
    struct ether_arp* arp_packet;


    std::cout << "frame length: " << header->caplen << " bytes" << std::endl;
    switch (ntohs(eth_header->ether_type))
    {
        case ETHERTYPE_IP:
            ipv4_packet = (struct ip*)(packet + ETHERNET_SIZE); // preskoci ethernet header
            print_ips_ipv4(ipv4_packet);
            ipv4_header_size = ipv4_packet->ip_hl * 4; // vypocet delky ip hlavicky
            switch (ipv4_packet->ip_p) // ip_p obsahuje informace o protokolu
            {
                case IPPROTO_TCP:
                    printf("tcp\n");
                    break;
                case IPPROTO_UDP:
                    printf("udp\n");
                    break;
                case IPPROTO_ICMP:
                    printf("icmp4\n");
                    break;
            }
            break;
        case ETHERTYPE_IPV6:
            ipv6_packet = (struct ip6_hdr*)(packet + ETHERNET_SIZE); // preskoci ethernet header
            print_ips_ipv6(ipv6_packet);
            switch (ipv6_packet->ip6_ctlun.ip6_un1.ip6_un1_nxt) // next header, obsahuje informace o protokolu
                case IPPROTO_TCP:
                    printf("tcp\n");
                    break;
                case IPPROTO_UDP:
                    printf("udp\n");
                    break;
                case IPPROTO_ICMPV6:
                    printf("icmp6\n");
                    break;
        case ETHERTYPE_ARP:
            arp_packet = (struct ether_arp*)(packet + ETHERNET_SIZE); // preskoci ethernet header
            print_ips_arp(arp_packet);
            break;
        default:
            std::cout << "UNSUPPORTED PROTOCOL" << std::endl;
            break;
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[])
{
    parse_arguments(argc, argv);
    if ((interface_arg && interface_name.empty()) || !interface_arg)
    {
        get_all_interfaces();
    }

    char errorbuffer[PCAP_ERRBUF_SIZE];
    pcap_t *interface;
    struct pcap_pkthdr header{};
    bpf_u_int32 mask; // maska site zadaneho rozhrani
    bpf_u_int32 net; // ip adresa zadaneho rozhrani
    struct bpf_program filter_pointer{}; // vraci pcap_compile, nachazi se zde zkompilovany filtr
    const u_char *packet; // aktualni packet

    /////////////////////////////////////////////////////////////////////////////////////////
    //////                                                                             //////
    //////          Nasledujici kod je velmi inspirovan navodem pro pcap               //////
    //////     ze stranky tcp dump, konkretne https://www.tcpdump.org/pcap.html        //////
    //////                                                                             //////
    /////////////////////////////////////////////////////////////////////////////////////////

    // zjisti IP adresu a masku pro zvoleny interface
    if (pcap_lookupnet(interface_name.c_str(), &net, &mask, errorbuffer) == -1)
        print_error(NETMASK_ERROR);

    // otevre zadane rozhrani pro sniffing
    interface = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errorbuffer);
    if (interface == nullptr)
        print_error(OPENING_INTERFACE_ERROR);

    // overi, zda se jedna o ethernet, nic jine tento program nepodporuje
    if (pcap_datalink(interface) != DLT_EN10MB)
        print_error(NO_ETHERNET_HEADER_ERROR);

    // vytvori a zkompiluje filtr
    std::string filter = create_filter();
    if (pcap_compile(interface, &filter_pointer, filter.c_str(), 0, net) == -1)
        print_error(FILTER_COMPILING_ERROR);

    // aplikuje zkompilovany filtr
    if (pcap_setfilter(interface, &filter_pointer) == -1)
        print_error(FILTER_APPLYING_ERROR);

    if (pcap_loop(interface, packet_num, callback, nullptr) == -1)
        print_error(PCAP_LOOP_ERROR);

    // ukonci sniffing session
    pcap_close(interface);

}