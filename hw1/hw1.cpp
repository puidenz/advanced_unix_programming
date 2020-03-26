#include<iostream>
#include<string>
#include<sstream>
#include<fstream>
#include<vector>
#include<unordered_map>
#include<iomanip>

#include<cstring>
#include<cstdlib>
#include<cerrno>

#include<arpa/inet.h>
#include<netinet/in.h>
#include<sys/types.h>
#include<dirent.h>
#include<unistd.h>

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

        string pid;
        unsigned int inode;
        string program;

        netstat_entry(){
            type = "NULL";
            local_address = "NULL";
            remote_address = "NULL";
            inode = 0;
            pid = "-1";
            program = "NULL";
        }
};

void output_if_err(bool err, string err_msg){
    if (err)
        cerr << err_msg << ": " << strerror(errno) << endl;
}
void read_netstat_entry(vector<netstat_entry> &netstat_table, ifstream &netstat_file, string type);
void print_netstat_table(const vector<netstat_entry> &netstat_table);
void parse_processes(vector<netstat_entry> &netstat_table, string path);

vector<char> hexstr_to_byte(string hex_string);
string address_ntop (string network_style_address, unsigned short int ip_type);

int filter_inode(string link_content);
bool is_digit(string str);
bool is_socket_link(string str);

unordered_map<unsigned int, int> inode_table;

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
    tcp_file.close();
    
    parse_processes(tcp_table, "/proc");
    print_netstat_table(tcp_table);
    inode_table.clear();


    cout << endl << "List of UCP connections:" << endl;
    udp_file.open(UDP_FILE, ios::in);
    output_if_err(!udp_file.is_open(), "UDP file open error");
    read_netstat_entry(udp_table, udp_file, "udp");
    udp_file.close();

    udp_file.open(UDP6_FILE, ios::in);
    output_if_err(!udp_file.is_open(), "UDP6 file open error");
    read_netstat_entry(udp_table, udp_file, "udp6");
    udp_file.close();

    parse_processes(udp_table, "/proc");
    print_netstat_table(udp_table);
    
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
                case 9:
                    tmp_entry.inode = strtol(tmp.c_str(), NULL, 10);
                    break;
            }
        }
        inode_table[tmp_entry.inode] = netstat_table.size();    //netstat_table.size() = index of incoming element
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
        struct in6_addr ip_bytes;
        
        for(unsigned int pos=0; pos<network_style_ip.size(); pos+=8)
            ip_bytes.__in6_u.__u6_addr32[pos/8] = strtol(network_style_ip.substr(pos, 8).c_str(), NULL, 16);
        
        char printable_ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip_bytes, printable_ipv6, INET6_ADDRSTRLEN);
        // inet_ntop(AF_INET6, hexstr_to_byte(network_style_ip).data(), printable_ipv6, INET6_ADDRSTRLEN);
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

void print_netstat_table(const vector<netstat_entry> &netstat_table){
    cout.setf(ios::left);
    //print header
    cout << setw(7) << "Proto" << setw(35) << "Local Address" \
    << setw(35) << "Foreign Address" << "PID/Program name and arguments" << endl;
    
    //print content
    for(auto entry : netstat_table){
        cout << setw(7) << entry.type << setw(35) << entry.local_address << setw(35) << entry.remote_address \
        << entry.pid << "/" << entry.program << endl;
    }
}

void parse_processes(vector<netstat_entry> &netstat_table, string path){
    DIR *procs_dir = opendir(path.c_str());
    while(struct dirent *proc = readdir(procs_dir)){
        if( is_digit(string(proc->d_name)) ){
            string fd_path = path + "/" + string(proc->d_name) + "/fd";
            DIR* fd_dir = opendir(fd_path.c_str());
            if(fd_dir == NULL){
                output_if_err(fd_dir == NULL, "Open dir error - " + fd_path);
                continue;
            }

            char buf[1024];
            while(struct dirent *fd = readdir(fd_dir)){
                memset(buf, 0, 1024);
                string link_path = fd_path + "/" + string(fd->d_name);
                
                if(readlink(link_path.c_str(), buf, 1024) < 0){
                    // output_if_err(true, "Read link fail");
                    continue;
                }

                string link_content = buf;
                if(!is_socket_link(link_content))
                    continue;

                int inode = filter_inode(link_content);
                unordered_map<unsigned int, int>::iterator it = inode_table.find(inode); 
                if(it == inode_table.end())
                    continue;
                netstat_table[it->second].pid = string(proc->d_name);
                
                string cmd_path = "/proc/" + string(proc->d_name) + "/cmdline";
                ifstream cmd_file;
                cmd_file.open(cmd_path.c_str());
                string command;
                getline(cmd_file, command);
                netstat_table[it->second].program = command.substr(command.find_last_of("/")+1);
            }
        }
    }
}

bool is_digit(string str){
    return strtol(str.c_str(), NULL, 10);
}

bool is_socket_link(string str){
    return str.find("socket:[") != string::npos || str.find("[0000]:") != string::npos;
}

int filter_inode(string link_content){
    size_t pos_first;
    if((pos_first = link_content.find("socket:[")) != string::npos){
        string inode_str = link_content.substr(sizeof("socket:[")-1, link_content.find("]"));
        return strtol(inode_str.c_str(), NULL, 10);
    }else if((pos_first = link_content.find("[0000]:")) != string::npos){
        string inode_str = link_content.substr(sizeof("[0000]:")-1, link_content.find("]", sizeof("[0000]:")-1));
        return strtol(inode_str.c_str(), NULL, 10);
    }else{
        output_if_err(true, "Wired link content");
    }
    return 0;
}