#pragma once

//попытка 2-3 - разбиение на много-много сессий
        //string path = p + "\\\\session_";
        /*std::stringstream ss;
        ss << packetCount;
        path += ss.str();
        ss.clear();
        path = path + ".pcap";
        const char* files = path.c_str();
        cout << files << "\n";*/

        /* запись в файлы
                struct bpf_program pgm;
                const char* studp = "proto \ udp";
                //tcp - fin, tcp - syn, tcp - rst, tcp - push, tcp - push, tcp - ack, tcp - urg
                //tcp [tcpflags] & (tcp-syn | tcp-fin)! = 0,
                const char* sttcp = "tcp [tcpflags] & (tcp-syn | tcp-fin | tcp-rst | tcp-push | tcp-ack | tcp-urg)! = 0 & udp == 0";
                if ((pcap_compile(pcap, &pgm, studp, 1, PCAP_NETMASK_UNKNOWN) == -1))*/

                // !проверки! 1 части кода
                        /*printf("src address: %s ", inet_ntoa(ip->ip_src));
                        printf("dest address: %s\n", inet_ntoa(ip->ip_dst));
                        cout << "OR CHECK IS IT CORRECT\n";
                        cout << "source adr " << str_a;
                        cout << "destination adr " << str_b;
                        printf("dest address: %s\n", b);*/


                        //pcap_t* handle;   /* Дескриптор сессии */
                        //char* dev; char errbuf[PCAP_ERRBUF_SIZE]; dev = pcap_lookupdev(errbuf); handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
                        //struct pcap_pkthdr new_header; /* Заголовок который нам дает PCAP */
        //const u_char* new_packet; /* переменная для пакета */
                        //new_packet = pcap_next(handle, &new_header);
                        //new_packet = pcap_loop(handle, 1, got_packet, 0);

        /*
        if ((str_a == sor && str_b == des && sor_port == spp && des_port == dpp) && (protocol == "tcp"))
                    {
                    int f = find_re(err_seq, err_ack);
                    if (f == 1)
                    {
                        cout << "PROTOCOL " << i << "\n";
                        cout << f << "\n";
                        cout << des_port << " + " << sor_port << " + " << err_seq << " + " << err_ack << "\n";
                        pcap_dump_ftell(err_file);
                        pcap_dump((u_char*)err_file, new_header, new_data);
                        pcap_dump_flush(err_file);
                    }
                    else if (f == 0) {
                        err e(err_seq, err_ack);
                        allerr.push_back(e);
                        pcap_dump_ftell(new_file);
                        pcap_dump((u_char*)new_file, new_header, new_data);
                        pcap_dump_flush(new_file);
                    }
                    }
                    */

/*
vector<err> allerr; // вектор со всеми комбинациями номеров 

int find_re(tcp_seq s, tcp_seq a, u_char f, u_short w, u_short su) //функция для поиска повторов 
{
int check = 0;
tcp_seq ss;
tcp_seq aa;
u_char ff;
u_short ww;
u_short susu;

int n = allerr.size();
for (int i = 0; i <= n - 1; i++)
{
    ss = allerr[i].seq;
    aa = allerr[i].ack;
    ff = allerr[i].flags;
    ww = allerr[i].win;
    susu = allerr[i].sum;
    if ((ss == s) && (aa == a) && (f == ff) && (w == ww) && (su == susu)) check = 1;
}

return check;
};
*/
/*string err_pth = "err_packets.pcap";
const char* err_path = err_pth.c_str();
pcap_t* err_pcap = pcap_open_dead(DLT_EN10MB, 65535);
pcap_dumper_t* err_file = pcap_dump_open(err_pcap, err_path);*/


                    /*if (protocol == "tcp")
                                {
                                    int f = find_re(err_seq, err_ack, err_flags, err_win, err_sum);
                                    if (f == 1)
                                    {
                                        cout << "PROTOCOL " << nu << "\n";
                                    }
                                    else if (f == 0) {
                                        err e(err_seq, err_ack, err_flags, err_win, err_sum);
                                        allerr.push_back(e);
                                    }
                                }*/
                                /* закрытие записанного файла и переменных */
        //pcap_dump_close(err_file); /* закрытие файла с ошибочными пакетами */

/* класс с характеристиками tcp 
class err {
public:
    err(tcp_seq s, tcp_seq a, u_char f, u_short w, u_short su) : seq(s), ack(a), flags(f), win(w), sum(su) {}
    tcp_seq seq;  // номер последовательности 
    tcp_seq ack;  // номер подтверждения 
    u_char flags;
    u_short win;  // окно 
    u_short sum;  // контрольная сумма 
};
*/