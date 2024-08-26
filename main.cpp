
#include <string>
#include <regex>
#include <iostream>
#include <utility>
#include <list>

#include "main.h"

using namespace std;

std::list<igdAddr> parseAddrArgs(const int count, const char** argv){
    std::list<igdAddr> ret;
    for(int i = 1; i < count; ++i){
        igdAddr addr(argv[i]);
        if(addr) ret.push_back(addr);
    }
    return ret;
}
int parsePortArg(int argc, char** argv){
    if(argc < 2) return 0;
    auto portPos = strstr(argv[1], "-p=");
    if(!portPos) return 0;
    int port = atoi(portPos+3);
    if(!port) return -1;
    return port;
    cout << "end parse port" << endl;
}

constexpr auto helpMsg = 
                        "natExplorer [params] [urls]\r\n"
                        "params:\r\n"
                        "   -p=<port> - change TCP port (9000 default)\r\n"
                        "urls: list of gateway ctrl urls\r\n"
                        "example: natExplorer -p=1500 http://192.168.0.4:1900/ctl/IPCon http://192.168.7.1:2828/ctl/IPCon\r\n";

int port = 0;

int main(int argc, char** argv){
    if(argc > 1 && strstr(argv[1], "-h")){
        cout << helpMsg << endl;
        return 0;
    }
    port = parsePortArg(argc, argv);
    if(port < 0){
        cout << "invalid port value" << endl;
        cout << helpMsg << endl;
        return -1;
    }else if(!port) port = 9000;
    printf("Using port = %d\r\n", port);
    const auto& addrs = parseAddrArgs(argc, (const char**)argv);
    if(addrs.empty()){
        cout << "no gtw addrs specified - run natExplorer -h" << endl;
        return -1;
        // target = {"http://192.168.0.4:1900/ctl/IPCon"};
    }
    else
    {
        for(auto & addr : addrs){
            // cout << addr.getCtrlUrl() << endl;
            getNat(addr);
        // cout << getMapEntryMsg(addr, 1) << endl;
        }
    }
    return 0;
}