#include <string>
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <winsock2.h>
#include <vector>
#include <fstream>
#include <algorithm>

#include "Headers.h"

using namespace std;

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996) 
#pragma warning(disable : 4995)

/* класс, содержащий адреса источника, отправител€ и нумерацию пар этих адресов + порты и протокол */
class ips {
public:
    ips(string s, string d, u_short sp, u_short dp, string pr, int n) : source(s), destination(d), sport(sp), dport(dp), protocol(pr), number(n) {}
    string source;
    string destination;
    u_short sport;
    u_short dport;
    string protocol;
    int number;
};

int main(int argc, char* argv[])
{
    int count = 0;  /* счЄтчик ip */
    vector<ips> allips;  /* вектор с ip адресами */
    char errbuff[PCAP_ERRBUF_SIZE];  /* массив дл€ ошибок (=256 согласно документации) */
    const struct sniff_ip* ip;  /* объ€вление */
    struct pcap_pkthdr* header;  /* заголовок */
    const u_char* data;  /* массив символов (typedef unsigned char = u_char) */

    /* получение от пользовател€ папки, в которой нужно сохранить файлы */
    string p;
    cout << "Enter the name of folder in which files should be saved: ";
    cin >> p;

    /* получение от пользовател€ имени файла pcap, который будет считан. ѕример: string file = "C:\\Users\\’оз€йка\\Desktop\\44.pcap"; */
    string name;
    cout << "Enter pcap file name: ";
    cin >> name;

    /* получение от пользовател€ имени csv-файла, который будет создан */
    string csv_name;
    cout << "Enter csv file name: ";
    cin >> csv_name;

    /* объ€влени€ дл€ tcp */
    u_int size_ip;
    const struct sniff_tcp* tcp;

    /* объ€влени€ дл€ udp */
    const struct udp_header* udp;

    /* открытие и сохранение файла в переменной */
    pcap_t* pcap = pcap_open_offline(name.c_str(), errbuff);

    /* начинаем чтение пакетов */
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        /* вывод предупреждени€, если размеры захвата и пакета различаютс€ */
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);

        /* получаем ip отправител€ и получател€ в переменные а и b... */

        ip = (struct sniff_ip*)(data + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;

        u_char proto = ip->ip_p;  /* протокол. 17 - udp, 6 - tcp */
        //int protocol = int(proto);
        string protocol;
        if (proto == IPPROTO_UDP) protocol = "udp";
        else if (proto == IPPROTO_ICMP) protocol = "icmp";
        else protocol = "tcp";

        u_short des_port = 0; /* получение портов */
        u_short sor_port = 0;

        if (protocol == "udp") /* udp */
        {
            udp = (struct udp_header*)(data + SIZE_ETHERNET + size_ip);
            des_port = ntohs(udp->dport);
            sor_port = ntohs(udp->sport);
        }

        if (protocol == "tcp") /* tcp */
        {
            tcp = (struct sniff_tcp*)(data + SIZE_ETHERNET + size_ip);
            des_port = ntohs(tcp->th_dport);
            sor_port = ntohs(tcp->th_sport);
        }

        //cout << "sp " << sor_port << "   ds " << des_port << "\n";

        char* a = inet_ntoa(ip->ip_src);  /* источник */
        string str_a; str_a.append(a);

        char* b = inet_ntoa(ip->ip_dst);  /* отправитель */
        string str_b; str_b.append(b);

        int check = 0; /* дл€ проверки - вдруг уже есть такой ip в векторе */

        for (int i = 0; i < count; i++)
            if ((allips[i].source == str_a && allips[i].destination == str_b && allips[i].dport == des_port && allips[i].sport == sor_port) /* || (allips[i].destination == str_a && allips[i].dport == sor_port && allips[i].source == str_b && allips[i].sport == des_port)*/) check = 1;

        if (check == 0) /* только уникальные ip попадут в вектор allips */
        {
            ips z(str_a, str_b, sor_port, des_port, protocol, count);
            allips.push_back(z);
            count = count + 1;
        }
    }

    pcap_close(pcap);

    /* вывод массива */
    for (int i = 0; i < count; i++) cout << "Number: " << allips[i].number << "   Destination: " << allips[i].destination << "     Source: " << allips[i].source << "   Sport " << allips[i].sport << "   Dport " << allips[i].dport << "   Protocol " << allips[i].protocol << "\n";

    /* открытие csv-файла */
    std::ofstream myfile;
    csv_name = p + "\\\\" + csv_name + ".csv";
    const char* csv_csv = csv_name.c_str();
    myfile.open(csv_csv);

    /* запись в csv-файл */
    myfile << "Number,Destination,Source,Source_port,Destination_port,Protocol,\n";
    for (int i = 0; i < count; i++) myfile << allips[i].number << "," << allips[i].destination << "," << allips[i].source << "," << allips[i].sport << "," << allips[i].dport << "," << allips[i].protocol << "," << "\n";
    myfile.close();

    struct pcap_pkthdr* new_header;
    const u_char* new_data;

    /* теперь сортировка пакетов по ip */
    for (int i = 0; i < count; i++)
    {
        string des = allips[i].destination; /* получаем уникального отправител€... */
        string sor = allips[i].source; /* и получател€ */
        u_short spp = allips[i].sport;
        u_short dpp = allips[i].dport;
        string prot = allips[i].protocol;
        int num = allips[i].number;

        char intStr[100];
        itoa(num, intStr, 10);
        string nu = string(intStr);

        /* формирование пути сохранени€ */
        string pth = p + "\\\\" + nu + "__" + prot + "__" + sor + "__" + des + ".pcap";
        const char* path = pth.c_str();

        pcap_t* write_pcap = pcap_open_dead(DLT_EN10MB, 65535); /* переменна€ дл€ новых файлов с пакетами */
        pcap_dumper_t* new_file = pcap_dump_open(write_pcap, path); /* открываем ее */

        /* снова читаем оригинальный pcap файл */
        pcap_t* new_pcap = pcap_open_offline(name.c_str(), errbuff);

        while (int returnValue = pcap_next_ex(new_pcap, &new_header, &new_data) >= 0)
        {
            /* получаем ip отправител€ и получател€ в переменные str_а и str_b */
            ip = (struct sniff_ip*)(new_data + SIZE_ETHERNET);
            size_ip = IP_HL(ip) * 4;

            char* a = inet_ntoa(ip->ip_src); string str_a; str_a.append(a); //cout << "sor = " << str_a;
            char* b = inet_ntoa(ip->ip_dst); string str_b; str_b.append(b); //cout << "   des = " << str_b << "\n";

            u_char proto = ip->ip_p;  /* протокол. 17 - udp, 6 - tcp */
            //int protocol = int(proto);
            string protocol;
            if (proto == IPPROTO_UDP) protocol = "udp";
            else if (proto == IPPROTO_ICMP) protocol = "icmp";
            else protocol = "tcp";

            u_short des_port = 0; /* получение портов */
            u_short sor_port = 0;

            tcp_seq err_seq = 0;
            tcp_seq err_ack = 0;
            u_char err_flags;
            u_short err_win = 0;
            u_short err_sum = 0;

            if (protocol == "udp") /* udp */
            {
                udp = (struct udp_header*)(new_data + SIZE_ETHERNET + size_ip);
                des_port = ntohs(udp->dport);
                sor_port = ntohs(udp->sport);
            }

            else if (protocol == "tcp") /* tcp */
            {
                tcp = (struct sniff_tcp*)(new_data + SIZE_ETHERNET + size_ip);
                des_port = ntohs(tcp->th_dport);
                sor_port = ntohs(tcp->th_sport);

                err_seq = tcp->th_seq;
                err_ack = tcp->th_ack;
                err_flags = tcp->th_flags;
                err_win = tcp->th_win;
                err_sum = tcp->th_sum;
            }

            if (str_a == sor && str_b == des && sor_port == spp && des_port == dpp) /* поиск совпадений по ip */
            {
                pcap_dump_ftell(new_file);  /* поиск текущей позиции в файле */
                pcap_dump((u_char*)new_file, new_header, new_data);  /* запись */
                pcap_dump_flush(new_file);  /* сброс из буфера в файл сохранени€ */
            }
        }
        pcap_dump_close(new_file);
        pcap_close(new_pcap);
        pcap_close(write_pcap);
    }
}

