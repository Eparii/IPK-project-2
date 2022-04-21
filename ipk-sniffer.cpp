/*
 * Autor: Tetauer Pavel
 * Login: xtetau00
 * Rok: 2021/22
*/



#include <iostream>
#include <bitset>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ctime>
#include <csignal>

#define WRONG_ARGUMENTS_ERROR 10
#define WRONG_ARGUMENT_NUMBER_ERROR 11
#define OPENING_INTERFACE_ERROR 12
#define NO_ETHERNET_HEADER_ERROR 13
#define NETMASK_ERROR 14
#define FILTER_COMPILING_ERROR 15
#define FILTER_APPLYING_ERROR 16
#define PCAP_LOOP_ERROR 17

#define ETHERNET_SIZE 14
#define IPV6_HEADER_LEN 40

bool interface_arg;
std::string interface_name;
int port;
int packet_num;
bool tcp_arg;
bool udp_arg;
bool arp_arg;
bool icmp_arg;
pcap_t *interface; // globalni kvuli pristupnosti ze signal handling funkce


// funkce slouzici k vypisu chybovych hlasek a ukonceni programu
void print_error(int errorcode)
{
    if(errorcode == WRONG_ARGUMENTS_ERROR)
    {
        std::cerr << "Neznámý argument, špatný počet nebo kombinace argumentů" << std::endl;
    }
    else if (errorcode == WRONG_ARGUMENT_NUMBER_ERROR)
    {
        std::cerr << "Špatné číslo po argumentu -p nebo -n" << std::endl;
        std::cerr << "Číslo portu musí být v intervalu <0, 65535>" << std::endl;
    }
    else if (errorcode == OPENING_INTERFACE_ERROR)
    {
        std::cerr << "Chyba při otevírání rozhraní " << interface_name << std::endl;
    }
    else if (errorcode == NO_ETHERNET_HEADER_ERROR)
    {
        std::cerr << "Zvolené rozhraní " << interface_name << " neposkytuje Ethernet protokol" << std::endl;
    }
    else if (errorcode == NETMASK_ERROR)
    {
        std::cerr << "Chyba při získánání masky pro " << interface_name << std::endl;
    }
    else if (errorcode == FILTER_COMPILING_ERROR)
    {
        std::cerr << "Chyba při kompilaci filtru" << std::endl;
    }
    else if (errorcode == FILTER_APPLYING_ERROR)
    {
        std::cerr << "Chyba při aplikaci filtru" << std::endl;
    }
    else if (errorcode == PCAP_LOOP_ERROR)
    {
        std::cerr << "Chyba při pcap_loop()" << std::endl;
    }
    std::cerr << "Použijte argument --help pro nápovědu" << std::endl;
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
        if (strcmp(argv[i], "--help") == 0)
        {
            if (argc != 2)
            {
                print_error(WRONG_ARGUMENTS_ERROR);
            }
            else
            {
                std::cerr << "Použití: sudo ./ipk-sniffer [-i rozhraní | --interface rozhraní]"
                             "{-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n\n"
                             "rozhraní = právě jedno rozhraní, na kterém se bude poslouchat\n"
                             "port = filtrování paketů na daném rozhraní podle portu\n"
                             "tcp = bude zobrazovat pouze TCP pakety\n"
                             "udp = bude zobrazovat pouze TCP pakety\n"
                             "icmp = bude zobrazovat pouze ICMPv4 a ICMPv6 pakety\n"
                             "arp = bude zobrazovat pouze ARP rámce\n"
                             "num = počet zobrazených packetů\n";
                exit(0);
            }
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface_name") == 0)
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
            if (*ptr != '\0' || port < 0 || port > 65535)
            {
                print_error(WRONG_ARGUMENT_NUMBER_ERROR);
            }
            i++; // preskoci se nasledujici argument, ve kterem se nachazi cislo portu
        }
        else if (strcmp(argv[i], "-n") == 0)
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
        else
        {
            print_error(WRONG_ARGUMENTS_ERROR);
        }
    }
    // defaultne se uvazuje zachyceni jednoho packetu
    if (!packet_num)
        packet_num = 1;
}

// funkce slouzici pro vytvoreni filtru
std::string create_filter()
{
    std::string filter;
    // osetruje jak samotny tcp, tak i kombinaci s udp
    if (tcp_arg)
    {
        filter = udp_arg ? "(tcp or udp" : "(tcp";
        filter = port ? filter + " and port " + std::to_string(port) + ")" : filter + ")";
    }
    // osetruje pouze samotne udp, kombinace s tcp je resena v predchozim ifu
    else if (udp_arg)
    {
        filter = "(udp";
        filter = port ? filter + " and port " + std::to_string(port) + ")" : filter + ")";
    }
    if (arp_arg)
    {
        filter = !tcp_arg and !udp_arg ?  "arp" : filter + " or arp";
    }
    if (icmp_arg)
    {
        filter = !tcp_arg and !udp_arg and !arp_arg ? "icmp or icmp6" : filter + " or icmp or icmp6";
    }
    // neni zadany zadny argument specifikujici protokol
    if (!tcp_arg and !udp_arg and !arp_arg and !icmp_arg)
    {
        filter = port ? "(tcp or udp and port " + std::to_string(port) + ") or arp or icmp or icmp6"
                : "tcp or udp or arp or icmp or icmp6";
    }
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

// funkce slouzici pro vypsani casu zachyceni packetu
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

// funkce slouzici pro vypsani mac adres
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

// funkce slouzici pro vypsani IP adres z ARP packetu
void print_ips_arp(struct ether_arp* arp_header)
{
    printf("src IP: ");
    for (int i = 0; i < 3; i++)
    {
        printf("%d.", arp_header->arp_spa[i]);
    }
    printf("%d\n", arp_header->arp_spa[3]);

    printf("dst IP: ");
    for (int i = 0; i < 3; i++)
    {
        printf("%d.", arp_header->arp_tpa[i]);
    }
    printf("%d\n", arp_header->arp_tpa[3]);
}

// funkce slouzici pro vypsani IP adres z ipv4 packetu
void print_ips_ipv4(struct ip* ipv4_header)
{
    std::string src_ip = inet_ntoa(ipv4_header->ip_src);
    std::string dst_ip = inet_ntoa(ipv4_header->ip_dst);
    printf("src IP: %s\n", src_ip.c_str());
    printf("dst IP: %s\n", dst_ip.c_str());
}

// funkce slouzici pro vypsani IP adres z ipv6 packetu
void print_ips_ipv6(struct ip6_hdr* ipv6_header)
{
    char src_address[128]{};
    char dst_address[128]{};

    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), src_address, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dst_address, INET6_ADDRSTRLEN);

    std::cout << "src IP: " << src_address << std::endl;
    std::cout << "dst IP: " << dst_address << std::endl;

}

// funkce slouzici pro vypis dat ve stanovenem formatu
void print_data(const u_char *packet, bpf_u_int32 size)
{
    uint counter = 0;
    uint i = 0;
    uint j = 0;
    std::cout << "0x0000:  ";
    while (i < size)
    {
        printf("%02x ", packet[i]); // nejprve tiskne v hexadecimalnim formatu
        if ((i + 1) % 16 == 0 || i + 1 == size) // po precteni 16 bajtu vypisuje v ascii formatu
        {
            if ((i + 1) % 16 != 0) // padding pro posledni radek
            {
                uint x = i;
                while ((x + 1) % 16 != 0)
                {
                    printf("   ");
                    x++;
                }
            }
            printf(" "); // mezera mezi ascii a hex formaty
            while (j <= i)
            {
                // pokud je znak tisknutelny, vypise ho, jinak misto nej napise tecku
                printf("%c", isprint(packet[j]) ? packet[j] : '.');
                j++;

            }
            // novy radek
            std::cout << std::endl;
            if (i + 1 < size)
            {
                counter += 16;
                printf("0x%04x:  ", counter);
            }
        }
        i++;
    }
}

// funkce slouzici na vytisknuti udp portu
void print_ports_udp(udphdr* udp_header)
{
    printf("src port: %d\n", ntohs(udp_header->uh_sport));
    printf("dst port: %d\n", ntohs(udp_header->uh_dport));
}

void print_ports_tcp(tcphdr* tcp_header)
{
    printf("src port: %d\n", ntohs(tcp_header->th_sport));
    printf("src port: %d\n", ntohs(tcp_header->th_dport));
}


/* funkce, ve ktere se deje veskere zpracovani packetu.
 * Jedna se o callback pro pcap_loop() */
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    print_timestamp(header->ts);
    auto *eth_header = (struct ether_header *) packet;
    print_mac_addresses(eth_header);
    struct ip* ipv4_header;
    int ipv4_header_size;
    struct ip6_hdr* ipv6_header;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    struct ether_arp* arp_header;


    std::cout << "frame length: " << header->caplen << " bytes" << std::endl;
    switch (ntohs(eth_header->ether_type))
    {
        case ETHERTYPE_IP:
            ipv4_header = (struct ip*)(packet + ETHERNET_SIZE); // preskoci ethernet header
            print_ips_ipv4(ipv4_header);
            ipv4_header_size = ipv4_header->ip_hl * 4; // vypocet delky ip hlavicky
            switch (ipv4_header->ip_p) // ip_p obsahuje informace o protokolu
            {
                case IPPROTO_TCP:
                    // pointerova aritmetika pro ziskani TCP hlavicky, preskoci ethernet header
                    // a zaroven preskoci i IPv4 header pomoci vypocitane delky
                    tcp_header = (struct tcphdr*)(packet + ETHERNET_SIZE + ipv4_header_size);
                    print_ports_tcp(tcp_header);
                    print_data(packet, header->caplen);
                    break;
                case IPPROTO_UDP:
                    // pointerova aritmetika pro ziskani UDP hlavicky, preskoci ethernet header
                    // a zaroven preskoci i IPv4 header pomoci vypocitane delky
                    udp_header = (struct udphdr*)(packet + ETHERNET_SIZE + ipv4_header_size);
                    print_ports_udp(udp_header);
                    print_data(packet, header->caplen);
                    break;
                case IPPROTO_ICMP:
                    print_data(packet, header->caplen);
                    break;
            }
            break;
        case ETHERTYPE_IPV6:
            ipv6_header = (struct ip6_hdr*)(packet + ETHERNET_SIZE); // preskoci ethernet header
            print_ips_ipv6(ipv6_header);
            switch (ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt) // next header, obsahuje informace o protokolu
            {
                case IPPROTO_TCP:
                    tcp_header = (struct tcphdr*)(packet + ETHERNET_SIZE + IPV6_HEADER_LEN);
                    print_ports_tcp(tcp_header);
                    print_data(packet, header->caplen);
                    break;
                case IPPROTO_UDP:
                    udp_header = (struct udphdr*)(packet + ETHERNET_SIZE + IPV6_HEADER_LEN);
                    print_ports_udp(udp_header);
                    print_data(packet, header->caplen);
                    break;
                case IPPROTO_ICMPV6:
                    print_data(packet, header->caplen);
                    break;
            }
            break;
        case ETHERTYPE_ARP:
            arp_header = (struct ether_arp*)(packet + ETHERNET_SIZE); // preskoci ethernet header
            print_ips_arp(arp_header);
            print_data(packet, header->caplen);
            break;
        default:
            std::cout << "Nepodporovaný protokol" << std::endl;
            break;
    }
    std::cout << std::endl;
}

void my_handler(int param)
{
    pcap_close(interface);
    exit(130);
}

int main(int argc, char* argv[])
{
    parse_arguments(argc, argv);
    // pokud neni zadan argument -i, nebo je zadan bez nazvu rozhrani,
    // vypise vsechny dostupne rozhrani a ukonci program
    if ((interface_arg && interface_name.empty()) || !interface_arg)
    {
        get_all_interfaces();
    }
    bpf_u_int32 mask; // maska site zadaneho rozhrani
    bpf_u_int32 net; // ip adresa zadaneho rozhrani
    struct bpf_program filter_pointer{}; // vraci pcap_compile, nachazi se zde zkompilovany filtr

    /////////////////////////////////////////////////////////////////////////////////////////
    //////                                                                             //////
    //////          Nasledujici kod je velmi inspirovan navodem pro pcap               //////
    //////     ze stranky tcp dump, konkretne https://www.tcpdump.org/pcap.html        //////
    //////                                                                             //////
    /////////////////////////////////////////////////////////////////////////////////////////

    // zjisti IP adresu a masku pro zvoleny interface
    if (pcap_lookupnet(interface_name.c_str(), &net, &mask, nullptr) == -1)
        print_error(NETMASK_ERROR);

    // otevre zadane rozhrani pro sniffing
    interface = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, nullptr);
    if (interface == nullptr)
        print_error(OPENING_INTERFACE_ERROR);

    // sigint handling
    // kod prevzat z https://www.cplusplus.com/reference/csignal/signal/
    void (*prev_handler)(int);
    prev_handler = signal (SIGINT, my_handler);

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

    // smycka, ve ktere se vola callback funkce pro kazdy packet
    if (pcap_loop(interface, packet_num, callback, nullptr) == -1)
        print_error(PCAP_LOOP_ERROR);

    // ukonci sniffing session
    pcap_close(interface);
}