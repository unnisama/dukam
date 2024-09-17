#include "proxy.h"

ProxyManager::ProxyManager(std::string f)
{
    std::ifstream file(f);
    if(!file.good()){
        return;
    }

    std::regex rgx("(socks4|https|socks5|http):\\/\\/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\:\\d{2,5}");
    std::string line;

    while(std::getline(file, line)){
        if(std::regex_match(line, rgx)){
            proxies.push_back(line);
        }
    }
}

ProxyManager::ProxyManager()
{
}

void ProxyManager::RemoveProxy(std::string& proxy)
{
    int cidx = 0;
    for(std::string p : proxies){
        if(p == proxy){
            break;
        }
        idx += 1;
    }
    if(idx > cidx){
        idx -= 1;
    }

    proxies.erase(proxies.begin()+cidx);
}

void ProxyManager::RemoveProxy(int pxid)
{
    if(idx > pxid){
        idx -= 1;
    }

    proxies.erase(proxies.begin()+pxid);
}

int ProxyManager::GetProxyType(std::string prox){
    std::string proxy(prox.data());
    proxy.resize(proxy.find_first_of("://"));

    if(proxy == "http"){
        return CURLPROXY_HTTP;
    }else if (proxy == "https")
    {
        return CURLPROXY_HTTPS;
    }else if (proxy == "socks4")
    {
        return CURLPROXY_SOCKS4;
    }else if (proxy == "socks5")
    {
        return CURLPROXY_SOCKS5;
    }else{
        return -1;
    }
}

std::string ProxyManager::GetIP(std::string &proxy)
{
    int cidx = proxy.find_first_of("://");
    std::string ip(&(proxy.data()[cidx+3]));
    ip.resize(ip.find_last_of(":"));

    return ip;
}

int ProxyManager::GetPort(std::string &proxy)
{
    int cidx = proxy.find_last_of(":");
    std::string sport(&(proxy.data()[cidx+1]));
    return std::atoi(sport.data());
}

std::string ProxyManager::GetProxy()
{
    if(proxies.size() == 0){
        return "";
    }
    idx += 1;
    idx = idx % proxies.size();

    return proxies[idx];
}