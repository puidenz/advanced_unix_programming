#include<iostream>
#include<string>
#include<sstream>
#include<fstream>
#include<vector>

#include<cstring>
#include<cstdlib>
#include<cerrno>

#include<arpa/inet.h>
#include<netinet/in.h>

#define IPV4 32
#define IPV6 128
#define TCP_FILE "/proc/net/tcp"
#define TCP6_FILE "/proc/net/tcp6"
#define UDP_FILE "/proc/net/udp"
#define UDP6_FILE "/proc/net/udp6"

using namespace std;

class netstat_entry{
    public:
        string type;
        string local_address;
        string remote_address;

        int pid;
        string program;

        netstat_entry(){
            type = "NULL";
            local_address = "NULL";
            remote_address = "NULL";
            pid = -1;
            program = "NULL";
        }
};

struct my_in6_addr{
    long long ipv6_addr;
};

void output_if_err(bool err, string err_msg){
    if (err)
        cerr << err_msg << ": " << strerror(errno) << endl;
}
void read_netstat_entry(vector<netstat_entry> &netstat_table, ifstream &netstat_file, string type);
void print_netstat_entry(const vector<netstat_entry> &netstat_table);
vector<char> hexstr_to_byte(string hex_string);
string address_ntop (string network_style_address, unsigned short int ip_type);

int main(){
    ifstream tcp_file, udp_file;
    string tmp;
    vector<netstat_entry> tcp_table, udp_table;

    cout << "List of TCP connections:" << endl;
    tcp_file.open(TCP_FILE, ios::in);
    read_netstat_entry(tcp_table, tcp_file, "tcp");
    output_if_err(!tcp_file.is_open(), "TCP file open error");
    tcp_file.close();

    tcp_file.open(TCP6_FILE, ios::in);
    output_if_err(!tcp_file.is_open(), "TCP6 file open error");
    read_netstat_entry(tcp_table, tcp_file, "tcp6");
    print_netstat_entry(tcp_table);
    tcp_file.close();

    cout << endl << "List of TCP connections:" << endl;
    udp_file.open(UDP_FILE, ios::in);
    output_if_err(!udp_file.is_open(), "UDP file open error");
    read_netstat_entry(udp_table, udp_file, "udp");
    udp_file.close();
    udp_file.open(UDP6_FILE, ios::in);
    output_if_err(!udp_file.is_open(), "UDP6 file open error");
    read_netstat_entry(udp_table, udp_file, "udp6");
    print_netstat_entry(udp_table);
    udp_file.close();
}

void read_netstat_entry(vector<netstat_entry> &netstat_table, ifstream &netstat_file, string type){
    string entry;
    getline(netstat_file, entry); //remove header
    while(getline(netstat_file, entry)){
        netstat_entry tmp_entry;
        istringstream ss_entry(entry);
        string tmp;    
        //address: "ip:port"
        string local_address;
        string remote_address;

        tmp_entry.type = type;        

        for(int column=0; ss_entry >> tmp; column++){
            switch(column){
                //local address column
                case 1:
                    if(type == "tcp" || type == "udp")
                        tmp_entry.local_address = address_ntop(tmp, IPV4);
                    else if(type == "tcp6" || type == "udp6")
                        tmp_entry.local_address = address_ntop(tmp, IPV6);
                    else
                        output_if_err(true, "Invaild type");
                    break;
                //remote address column
                case 2:
                    if(type == "tcp" || type == "udp")
                        tmp_entry.remote_address = address_ntop(tmp, IPV4);
                    else if(type == "tcp6" || type == "udp6")
                        tmp_entry.remote_address = address_ntop(tmp, IPV6);
                    else
                        output_if_err(true, "Invaild type");
                    break;
            }
        }
        netstat_table.push_back(tmp_entry);
    }
}

// net formate -> printable format
string address_ntop (string network_style_address, unsigned short int ip_type){
    int split_position = network_style_address.find(":");
    string network_style_ip = network_style_address.substr(0, split_position);
    string network_style_port = network_style_address.substr(split_position+1, network_style_address.size()-split_position-1);

    string printable_ip;
    if(ip_type == IPV4){
        struct in_addr ip_bytes;
        ip_bytes.s_addr = strtol(network_style_ip.c_str(), NULL, 16);
        char printable_ipv4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_bytes, printable_ipv4, INET_ADDRSTRLEN);
        printable_ip = string(printable_ipv4);
    }
    else if(ip_type == IPV6){
        // struct in6_addr ip_bytes;
        
        // ip_bytes.ipv6_addr = strtol(network_style_ip.c_str(), NULL, 16);
        char printable_ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, hexstr_to_byte(network_style_ip).data(), printable_ipv6, INET6_ADDRSTRLEN);
        printable_ip = string(printable_ipv6);
    }
    

    int printable_port = strtol(network_style_port.c_str(), NULL, 16);
    if(printable_port == 0)
        return string(printable_ip) + ":*";
    else
        return string(printable_ip) + ":" + to_string(printable_port);
}

vector<char> hexstr_to_byte(string hex_string){
    vector<char> bytes;
    bytes.reserve(16);

    output_if_err( (hex_string.size()%2!=0), "Address size is odd, invalid address!");

    for(uint i=0; i<hex_string.size(); i+=2){
        string byte_str = hex_string.substr(i, 2);
        char byte =(char) strtol(byte_str.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

void print_netstat_entry(const vector<netstat_entry> &netstat_table){
    string header = "Proto\tLocal Address\tForeign Address\tPID/Program name and arguments";
    cout << header << endl;
    for(auto entry : netstat_table){
        cout << entry.type << "\t" << entry.local_address << "\t" << entry.remote_address << "\t" \
        << entry.pid << "/" << entry.program << endl;
    }
}