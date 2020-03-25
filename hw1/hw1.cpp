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


#define TCP_FILE "/proc/net/tcp"
#define UDP_FILE "/proc/net/udp"

using namespace std;

class netstat_entry{
    public:
        string type = "NULL";
        string loacal_address = "NULL";
        string remote_address = "NULL";

        int pid = -1;
        string program = "NULL";
};

void output_if_err(bool err, string err_msg){
    if (err)
        cerr << err_msg << ": " << strerror(errno) << endl;
}
void read_netstat_entry(vector<netstat_entry> &netstat_table, ifstream &netstat_file, string type);
void print_netstat_entry(const vector<netstat_entry> &netstat_table);
void hexstr_to_byte(string hex_string, vector<char> &network_bytes);
string address_ntop (string address);

int main(){
    ifstream tcp_file, udp_file;
    string tmp;
    vector<netstat_entry> tcp_table, udp_table;

    tcp_file.open(TCP_FILE, ios::in);
    udp_file.open(UDP_FILE, ios::in);
    output_if_err(!(tcp_file.is_open() && udp_file.is_open() ), "File open error");

    cout << "List of TCP connections:" << endl;
    read_netstat_entry(tcp_table, tcp_file, "tcp");
    print_netstat_entry(tcp_table);

    cout << endl << "List of TCP connections:" << endl;
    read_netstat_entry(udp_table, udp_file, "udp");
    print_netstat_entry(udp_table);
    // tcp_file >> tmp;
    // cout << tmp << endl;
}

void read_netstat_entry(vector<netstat_entry> &netstat_table, ifstream &netstat_file, string type){
    string entry;

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
                    tmp_entry.loacal_address = address_ntop(tmp);
                    break;
                //remote address column
                case 2:
                    tmp_entry.remote_address = address_ntop(tmp);
                    break;
            }
        }
        netstat_table.push_back(tmp_entry);
    }
}

// net formate -> printable format
string address_ntop (string network_style_address){
    int split_position = network_style_address.find(":");
    string network_style_ip = network_style_address.substr(0, split_position);
    string network_style_port = network_style_address.substr(split_position+1, network_style_address.size()-split_position-1);

    struct in_addr ip_bytes;
    ip_bytes.s_addr = strtol(network_style_ip.c_str(), NULL, 16);

    char printable_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_bytes, printable_ip, INET_ADDRSTRLEN);

    int printable_port = strtol(network_style_port.c_str(), NULL, 16);
    if(printable_port == 0)
        return string(printable_ip) + ":*";
    else
        return string(printable_ip) + ":" + to_string(printable_port);
}

void hexstr_to_byte(string hex_string, vector<char> &network_bytes){
    network_bytes.reserve(64);
    output_if_err( (hex_string.size()%2!=0), "Address size is odd, invalid address!");

    for(uint i=0; i<hex_string.size(); i+=2){
        string byte_str = hex_string.substr(i, 2);
        char byte =(char) strtol(byte_str.c_str(), NULL, 16);
        network_bytes.push_back(byte);
    }
}

void print_netstat_entry(const vector<netstat_entry> &netstat_table){
    string header = "Proto\tLocal Address\tForeign Address\tPID/Program name and arguments";
    cout << header << endl;
    for(auto entry : netstat_table){
        cout << entry.type << "\t" << entry.loacal_address << "\t" << entry.remote_address << "\t" \
        << entry.pid << "/" << entry.program << endl;
    }
}