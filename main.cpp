#include <iostream>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <iostream>
#include <string.h>
#include <iomanip>
#include <sstream>
#include <net/if.h>
#include <sys/ioctl.h>

std::string niceMac(const u_char mac[ETHER_ADDR_LEN])
{
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(mac[0]);
    for(uint8_t i = 1; i < ETHER_ADDR_LEN; i++)
    {
        ss << ":" << static_cast<unsigned int>(mac[i]);
    }
    return ss.str();
}

std::string niceIp(uint32_t ip)
{
    uint8_t *ip_ = reinterpret_cast<uint8_t *>(&ip);
    std::stringstream ss;
    ss << static_cast<unsigned int>(ip_[0]);
    for(uint8_t i = 1; i < 4; i++)
    {
        ss << "." << static_cast<unsigned int>(ip_[i]);
    }
    return ss.str();
}

int createSocket()
{
    auto sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd == -1)
    {
        std::cout << "something went wrong when creating socket: " << strerror(errno) << std::endl;
    }
    return sd;
}

int interfaceNameToIndex(int sd, const std::string& interfaceName)
{
    ifreq ifr = {};
    memcpy(&ifr.ifr_name, interfaceName.c_str(), interfaceName.length());
    ioctl(sd, SIOCGIFINDEX, &ifr); // now we have interface index from name
    return ifr.ifr_ifindex;
}


bool setPromiscuousMode(int sd, const std::string& interfaceName)
{
    packet_mreq mreq;
    mreq.mr_ifindex = interfaceNameToIndex(sd, interfaceName);
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_alen = ETHER_ADDR_LEN;
    if (setsockopt(sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                   (void*)&mreq,(socklen_t)sizeof(mreq)) < 0)
    {
        std::cout << "something went wrong: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}


int main() {

    if(auto sd = createSocket())
    {
        if(setPromiscuousMode(sd, "enp0s3"))
        {
            while(1)
            {
                uint8_t buf[IP_MAXPACKET] = {0};
                ether_header *eh = reinterpret_cast<ether_header*>(buf);
                iphdr *ip = reinterpret_cast<iphdr*>(buf+sizeof(ether_header));

                auto rcvbytes = recv(sd, buf, IP_MAXPACKET, 0);
                std::string msg = "GOT packet src mac: " + niceMac(eh->ether_shost);
                if(eh->ether_type == htons(ETH_P_IP))
                {
                    msg += ", ip src addr: " + niceIp(ip->saddr);
                }
                std::cout << msg << std::endl;
            }
        }
    }
}