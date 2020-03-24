#include<iostream>
#include<string>
#include<sstream>
#include<fstream>
#include<vector>

#include<cstring>
#include<cerrno>

#define TCP_FILE "/proc/net/tcp"
#define UDP_FILE "/proc/net/udp"

using namespace std;

class netstat_entry{
    public:
        string type;
        string loacal_ip;
        string loacal_port;

        string remote_ip;
        string remote_port;

        int pid;
        string program;
};

void output_if_err(bool err, string err_msg){
    if (err)
        cerr << err_msg << ": " << strerror(errno) << endl;
}

void read_netstat_entry(vector<netstat_entry> &netstat_table, ifstream &netstat_file);

int main(){
    ifstream tcp_file, udp_file;
    string tmp;

    tcp_file.open(TCP_FILE, ios::in);
    udp_file.open(UDP_FILE, ios::in);
    output_if_err(!(tcp_file.is_open() && udp_file.is_open() ), "File open error");

    

    tcp_file >> tmp;
    cout << tmp << endl;
}

void read_netstat_entry(vector<netstat_entry> &netstat_table, ifstream &netstat_file){
    string entry;
    netstat_entry tmp_entry;

    while(getline(netstat_file, entry)){
        istringstream ss_entry(entry);
        string tmp;    
        //address: "ip:port"
        string local_address;
        string remote_address;
        
        for(int i=0; ss_entry >> tmp; i++){
            switch(i){
                case 1:
                    local_address = tmp;
                    break;
                case 2:
                    remote_address = tmp;
                    break;
            }

        }
    }
}

// ip:port (in net format) -> netstat_entry.ip, netstat_entry.port
void formate_address (netstat_entry &entry, string address){
    int split_position = address.find(":");
    entry.loacal_ip = address.substr(0, split_position);
    entry.loacal_port = address.substr(split_position+1, address.size()-split_position-1);
}