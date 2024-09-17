#ifndef PROXY_H
#define PROXY_H
#include <vector>
#include <fstream>
#include <curl/curl.h>
#include <iostream>
#include <regex>

class ProxyManager{
public:
    ProxyManager(std::string f);
    ProxyManager();
    std::string GetProxy();
    void RemoveProxy(std::string& proxy);
    void RemoveProxy(int pxid);
    int GetProxyType(std::string proxy);
    std::string GetIP(std::string& proxy);
    int GetPort(std::string& proxy);
    inline int GetIdx() { return idx; };
    inline std::string GetProxyAt(int idx) { return proxies[idx]; };
private:
    int idx = -1;
    std::vector<std::string> proxies;
};


#endif