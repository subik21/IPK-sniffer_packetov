#include <getopt.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <time.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

int number_print = 0, tflag = 0, uflag = 0;

void my_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    time_t rawtime;
    struct tm* timeinfo;
    //struktury pre parsovanie paketov
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;

    int size_eth = sizeof(struct ether_header);
    int size_ip = sizeof(struct ip);
    int size_tcp = sizeof(struct tcphdr);
    int size_payl;

    const u_char *payload;

    eth_header = (struct ether_header *)(packet);
    //ak nieje typ eternetu IP zahodi paket
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP){
        return;
    }
    //rozdelenie paketov do struktur
    ip_header = (struct ip*)(packet+ size_eth);
    tcp_header = (struct tcphdr*)(packet + size_eth + size_ip);
    payload = (u_char *)(packet + size_eth+ size_ip+ size_tcp);
    //ak paket nieje tcp alebo udp zahodi ho
    if (!(ip_header->ip_p == IPPROTO_UDP || ip_header->ip_p == IPPROTO_TCP)){
        return;
    }
    //filter pre tcp alebo udp pakety
    if (!(tflag && uflag)) {
        if (tflag) {
            if (ip_header->ip_p == IPPROTO_UDP)
                return;
        }
        if (uflag) {
            if (ip_header->ip_p == IPPROTO_TCP)
                return;
        }
    }
    //ziskanie a vypis spravneho casu
    time (&rawtime);
    timeinfo = localtime(&rawtime);

    printf("%d: %d: %d.%ld ",timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec,header->ts.tv_usec);
    //vypis ip adries a ich portov
    printf("%s: %hu> ",inet_ntoa(ip_header->ip_src),tcp_header->th_sport);
    printf("%s: %hu\n\n",inet_ntoa(ip_header->ip_dst),tcp_header->th_dport);

    size_payl = header->caplen - (size_eth + size_ip + size_tcp);

    /*printf("0x%04x: ",number_print);

    if (size_payl > 0) {
        const u_char *temp_pointer = payload;
        int byte_cnt = 0;
        while (byte_cnt < size_payl){
            printf("%02x ", *temp_pointer);
            temp_pointer++;
            byte_cnt++;
        }
    }

    if (size_payl > 0) {
        const u_char *temp_pointer = payload;
        int byte_cnt = 0;
        while (byte_cnt < size_payl){
            if (isprint(*temp_pointer)){
                printf("%c", *temp_pointer);
            } else{
                printf(".");
            }
            temp_pointer++;
            byte_cnt++;
        }
        printf("\n");
    }*/
    //vypis celeho paketu po 16 znakov
    char hexa[49];
    char dec[17];

    int byte_cnt = 1;
    int num_hexa = 0;
    const u_char *temp_pointer = packet;
    while (byte_cnt <= header->caplen){
        sprintf(&hexa[num_hexa*3],"%02x ", *temp_pointer);//znak v hexadecimalnej sustave
        if (isprint(*temp_pointer)){
            sprintf(&dec[num_hexa],"%c", *temp_pointer);//ak je znak vypisatelny ulozi si ho do premnnej
        } else{
            sprintf(&dec[num_hexa],".");//ak nieje znak vypisatelny ulozi si do premennej bodku
        }
        if ((byte_cnt%16) == 0){ //vypis 16 znakov najprv v hexadecimalnej sustave a za nimi 16 znakov
            printf("0x%04x: ",number_print);
            number_print = number_print+16;
            printf("%s %s\n",hexa,dec);
            memset(hexa,'\0',sizeof(hexa));
            memset(dec,'\0',sizeof(dec));
            num_hexa = -1;
        }
        temp_pointer++;
        byte_cnt++;
        num_hexa++;
    }
    byte_cnt--;
    if ((byte_cnt%16) != 0){ //vypis menej ako 16 znakov
        printf("0x%04x: ",number_print);
        number_print = number_print+(byte_cnt%16);
        printf("%s %s\n",hexa,dec);
    }
    printf("\n");

    //number_print = number_print + size_payl;
}

int main(int argc, char **argv) {
    int c,port = 0, iflag = 0, number = 1, option_index = 0, pflag = 0;
    char* ethernet = NULL;
    char * error;
    std::string port_string;

    //dlhe argumenty
    static struct option long_options[] = {
            {"tcp", no_argument, &tflag, 1},
            {"udp", no_argument, &uflag, 1},
    };
    //argument parser
    while (( c = getopt_long(argc,argv,"i:p:tun:",long_options,&option_index)) != -1){
        switch(c){
            case 0:
                if (long_options[option_index].flag != 0) {
                    break;
                }
                else {
                    fprintf(stderr, "Nespravny prepinac.\n");
                    return 1;
                }
            case 'p':
                pflag = 1;
                port_string = optarg;
                port = int(strtol(optarg,&error,10));
                if (strcmp(error,"") != 0) {
                    printf("%s", error);
                    fprintf(stderr, "Nespravne zadane cislo pri prepinaci -n\n");
                    return 1;
                }
                break;
            case 't':
                tflag = 1;
                break;
            case 'u':
                uflag = 1;
                break;
            case 'n':
                number = int(strtol(optarg, &error, 10));
                if (strcmp(error,"") != 0) {
                    printf("%s", error);
                    fprintf(stderr, "Nespravne zadane cislo pri prepinaci -n\n");
                    return 1;
                }
                break;
            case 'i':
                ethernet = optarg;
                iflag = 1;
                break;
            default:
                fprintf(stderr,"Nespravny argument.\n");
                return 1;
        }
    }
    if (optind < argc){
        fprintf(stderr,"Nespravny argument.\n");
        return 1;
    }

    pcap_t *handle;
    char *dev = ethernet;
    bpf_u_int32 net, mask;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    std::string filter_exp = "port "+port_string;
    // Ak skript nebol spusteny s prepinacom -i vypise zoznam aktivnych rozhrani
    if (!iflag){
        pcap_if_t *list;
        pcap_if_t *alldev;

        pcap_findalldevs(&list,errbuf);
        if (list == NULL){
            fprintf(stderr, "Nenasli sa ziadne zariadenia.\n");
            pcap_freealldevs(list);
            return 1;
        }

        for (alldev = list; alldev != NULL; alldev = alldev->next){
            printf("%s\n",alldev->name);
        }
        pcap_findalldevs(&list,errbuf);
        return 0;
    }
    //ziskanie masky a ip adrresy rozhrania
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr,"Nepodarilo sa ziskat masku.\n");
        net = 0;
        mask = 0;
    }
    //otvorenie komunikacie pre chytanie paketov
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr,"Nepodarilo sa otvorit zariadenie %s.\n",dev);
        return 1;
    }
    //Ak je zadany port na ktorom sa ma odpocuvat vytvori filter pre port
    if (pflag) {
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
            fprintf(stderr, "Nepodarilo sa vytvorit filter.\n");
            pcap_close(handle);
            return 1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Napodarilo sa pouzit filter.\n");
            pcap_close(handle);
            return 1;
        }
    }
    //prehladavanie paketmi
    pcap_loop(handle, number, my_handler, NULL);

    pcap_close(handle);
    return 0;
}