#include <string>
#include <regex>
#include <utility>
#include <cstring>
#include <cstdio>
#include <chrono>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

using namespace std;
struct NATRule{
        NATRule() = default;
        //!changeable params
        struct CommonConf{
            uint16_t dstPort = 0;
            bool manual = false;
            bool enable = false;
        }comCfg;
        
        //!unchangeable params
        struct SystemConf{
            uint16_t srcPort = 0;
            std::string portType = "";
        }sysCfg;
        //!Check json is valid for NATRule::CommonConf
        inline bool isValid() const{
            return comCfg.dstPort && sysCfg.srcPort &&
                (sysCfg.portType == "TCP" || sysCfg.portType == "UDP");
        }
        inline std::string toString() const{
            std::stringstream str;
            str << " srcPort:" << sysCfg.srcPort << " "<< "dstPort:" << comCfg.dstPort;
            return str.str();
        }
        inline uint16_t outPort() const {
            return comCfg.manual ? comCfg.dstPort : sysCfg.srcPort;
        }
    };

std::pair<std::string, NATRule> parseResponse(const std::string &xmlResp)
{
    pair<std::string, NATRule> ret;
    constexpr const char *entry = "GetGenericPortMappingEntryResponse";
    const size_t startEntry = xmlResp.find(entry);
    const size_t endEntry = xmlResp.find(entry, startEntry+10);
    if(startEntry == std::string::npos || endEntry == std::string::npos) return ret;
    const string &mapBlock = xmlResp.substr(startEntry, endEntry-startEntry);
    regex rx;
    {
        smatch matcher;
        rx.assign(R"(NewInternalClient>(.+)</NewInternalClient)");
        if(regex_search(mapBlock, matcher, rx)){
            if(!matcher.empty())
                ret.first = matcher[1];
        }
    }
    {
        smatch matcher;
        rx.assign(R"(NewPortMappingDescription>(.+)</NewPortMappingDescription)");
        if(regex_search(mapBlock, matcher, rx)){
            if(!matcher.empty()){
                ret.first +=": ";
                ret.first += matcher[1];
            }
        }
    }
    {
        smatch matcher;
        rx.assign(R"(NewExternalPort>(.+)</NewExternalPort)");
        if(regex_search(mapBlock, matcher, rx)){
            if(!matcher.empty()){
                try{
                    ret.second.comCfg.manual = true;
                    ret.second.comCfg.dstPort = stoul(matcher[1]);
                } catch(const std::exception &ex){std::cout << "stoul() failed " << ex.what() << endl;}
            }
                
        }
    }
    {
        smatch matcher;
        rx.assign(R"(NewProtocol>(.+)</NewProtocol)");
        if(regex_search(mapBlock, matcher, rx)){
            if(!matcher.empty())
                ret.second.sysCfg.portType = matcher[1];
        }
    }
    {
        smatch matcher;
        rx.assign(R"(NewInternalPort>(.+)</NewInternalPort)");
        if(regex_search(mapBlock, matcher, rx)){
            if(!matcher.empty()){
                try{
                    ret.second.sysCfg.srcPort = stoul(matcher[1]);
                } catch(const std::exception &ex){std::cout  << "stoul() failed " << ex.what() << endl;}
            }
        }
    }
    
    return ret;
}

constexpr const char *GET_PORTMAP_BODY =  "<?xml version=\"1.0\" ?> "
    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"> "
        "<s:Body> "
            "<u:GetGenericPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"> "
                "<NewPortMappingIndex>%d</NewPortMappingIndex> "
                "</u:GetGenericPortMappingEntry> "
            "</s:Body> "
        "</s:Envelope> ";

struct igdAddr{
    std::string ip, port, ipCtrlURI;
    igdAddr(const std::string &fullUrl){
        if(fullUrl.find("http") == std::string::npos){
            // cout << "not http" << endl;
            return;
        };
        regex rx;
        {
            smatch matcher;
            rx.assign(R"(http://(\d+\.\d+\.\d+\.\d+):(\d+)(.+))");
            if(regex_search(fullUrl, matcher, rx)){
                if(!matcher.empty()){
                    if(matcher.size() >= 2)
                        ip = matcher[1];
                    if(matcher.size() >= 3)
                        port = matcher[2];
                    if(matcher.size() >= 4)
                        ipCtrlURI = matcher[3];
                }
            }
        }
    }
    igdAddr(){}
    std::string getCtrlUrl() const{
        return std::string{"http://"} + ip + ":" + port + ipCtrlURI; 
    }
    operator bool() const{
        return !(ip.empty() || port.empty() || ipCtrlURI.empty());
    }
};

std::string getMapHead(const igdAddr &addr, const char* method = "GET"){
    constexpr auto GET_GENERIC_MAP_HEAD = 
    "SOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry\"\r\n"
    "Content-Type: text/xml; charset=\"utf-8\"\r\n"
    "Connection: keep-alive\r\n";
    std::stringstream ss;
    if(!addr || !strlen(method)) return ss.str();
    ss << method << " " << addr.ipCtrlURI << " HTTP/1.1\r\n"
        << "HOST: " << addr.ip << ":" << addr.port  << "\r\n"
        << GET_GENERIC_MAP_HEAD;
    return ss.str();
}
std::string getMapEntryMsg(const igdAddr &addr, const int num){
    std::stringstream ss;
    if(!addr) return ss.str();
    ss << getMapHead(addr, "POST");
    char body[1024];
    memset(body, 0, 1024);
    sprintf(body, GET_PORTMAP_BODY, num);
    ss << "Content-Length: " <<  std::to_string(strlen(body)) << "\r\n\r\n"
        << body;
    return ss.str();
}

struct autoSock{
    autoSock(const int sockFd) : fd(sockFd){}
    ~autoSock(){
        if(close(fd)) perror("close fd: ");
        // printf("close sock %d\r\n", fd);
    }
    int fd = 0;
};

extern int port;

int getNat(const igdAddr& gtw){
    printf("Gtw: %s NAT list:\r\n", gtw.ip.c_str());
    sockaddr_in inAddr{};
    inAddr.sin_family = AF_INET;
    inAddr.sin_port = htons(port);
    inAddr.sin_addr.s_addr = INADDR_ANY;
    sockaddr_in remoteAddr{AF_INET, htons(stoi(gtw.port)), inet_addr(gtw.ip.c_str())};
    
    auto ret = int(0);
    for(auto n = 1; n < 100; ++n){
        auto sock = socket(AF_INET, SOCK_STREAM, 0);
        if(!sock)
        {
            const int enable = 1;
            ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &enable, sizeof(enable));
            if(ret) perror("setsockopt: ");
        }
        autoSock closer(sock);
        {
            auto start = chrono::system_clock::now();
            chrono::milliseconds period(500);
            while(bind(sock, (sockaddr *)&inAddr, sizeof(inAddr)) && chrono::system_clock::now() - start > period){
                usleep(200);
            }
        }
        ret = connect(sock, (sockaddr *)&remoteAddr, sizeof(remoteAddr));
        if(ret){
            perror("connect: ");
            continue;
        }
        const auto &msg = getMapEntryMsg(gtw, n);
        send(sock, msg.c_str(), msg.size(),0);
        pollfd poller{.fd = sock, .events = POLLIN};
        ret = poll(&poller, 1, 5000);
        if(ret > 0){
            if(poller.revents && POLLIN){
                char buff[1024];
                read(poller.fd, buff, 1024);
                poller.revents = 0;
                // printf(buff);
                auto bodyPos = strstr(buff, "\r\n\r\n");
                if(bodyPos){
                    bodyPos+=4;
                    std::string bod(bodyPos);
                    // std::cout << "BODY " << bod << endl;
                    auto pair = parseResponse(bod);
                    if(!pair.first.empty())std::cout << "IP: " << pair.first << " rule: " << pair.second.toString() << endl;
                    else return 0;
                }
            }
            else{
                printf("Something error\r\n");
            }
        }
        else if(ret == 0){
            printf("timeout\r\n");
        }
        else{
            perror("poll error: ");
        }
    }
    return 0;
}