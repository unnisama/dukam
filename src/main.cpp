#include <curl/curl.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <iostream>
#include <iomanip>
#include <queue>
#include <sstream>
#include <algorithm>
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <set>
#include <openssl/evp.h>
#include <chrono>
#include "proxy.h"
#include "city.h"
#include "turbobase64/turbob64.h"

using rocksdb::DB;
using rocksdb::Options;
using rocksdb::ReadOptions;
using rocksdb::WriteOptions;
using rocksdb::Status;

struct Response
{
    size_t size;
    char *data;
    char *url;
    int pidx;
    bool ishead;
};

int max_in_go = 4;
int handles_not_done = 0;
DB* db = NULL;
Options options;
int total_urls_added = 0;

std::deque<std::pair<std::string, bool>> urls_tobe_rqtd;
int running_handles = 0;

ProxyManager proxym;

std::vector<rocksdb::ColumnFamilyDescriptor> column_families;
std::vector<rocksdb::ColumnFamilyHandle*> cfhandles;

enum class CRAWL_TYPE{
    SAME_HOST = 1,
    EXTERNAL = 2
};

std::string EncodeURL(std::string url){
    CURLU *urlp = curl_url();
    curl_url_set(urlp, CURLUPART_URL, url.data(), CURLU_DEFAULT_SCHEME);

    char * encoded_url = NULL;
    curl_url_get(urlp, CURLUPART_URL, &encoded_url, CURLU_URLENCODE);

    std::string out;

    if(encoded_url != NULL){
        out = encoded_url;
        curl_free(encoded_url);
    }
    curl_url_cleanup(urlp);

    return out;
}

std::string GetHost(std::string url){
    
    url = url.substr(url.find("://")+3);
    size_t idx = url.find("/");
    if(idx != std::string::npos){
        url.resize(idx);
    }
    
    return url;
}


std::string GenerateSHA256(std::string& data){

    uint128 chash = CityHash128(data.data(), data.size());

    std::ostringstream oss;

    oss << std::hex << Uint128Low64(chash) << Uint128High64(chash);
    
    return oss.str();
}

std::string Base64Encode(std::string in){
    int encodedLen = tb64enclen(in.size());
    std::string encodedData(encodedLen, '\0');

    tb64enc((unsigned char *)in.data(), in.size(), (unsigned char *)encodedData.data());

    return encodedData;

}

std::string Base64Decode(std::string in){
    int decodedLen = tb64declen((unsigned char *)in.data(), in.size());

    std::string decodedData(decodedLen, '\0');

    tb64dec((unsigned char *)in.data(), in.size(), (unsigned char *)decodedData.data());

    return decodedData;

}

bool CheckErr(Status& s){
    if (!s.ok()) {
        std::cerr << "Unable to open database: " << s.ToString() << std::endl;
        return false;
    }
    return true;
}

static size_t write_cb(char *data, size_t n, size_t l, Response *res)
{
    size_t tobecom = n*l;
    size_t prev_size = res->size;
    res->size += tobecom;

    res->data = (char *)realloc(res->data, res->size);
    
    char *pend = &(res->data[prev_size]);
    memcpy(pend, data, tobecom);

    return n*l;
}


void remove_handle_cleanup(CURLM *cm, CURL* eh){
    char *url = NULL;
                
    curl_easy_getinfo(eh, CURLINFO_EFFECTIVE_URL, &url);

    printf("[-] %s\n", url);

    curl_multi_remove_handle(cm, eh);
    curl_easy_cleanup(eh);
    handles_not_done -= 1;
}
void add_handle(CURLM *cm, std::string url, bool ishead=false){
    
    
    Response *res = (Response *)malloc(sizeof(Response));

    res->size = 0;
    res->data = NULL;
    res->ishead = ishead;
    res->url = (char *)malloc(url.size()+1);
    memcpy(res->url, url.data(), url.size());
    res->url[url.size()] = '\0';


    CURL* eh = curl_easy_init();

    curl_easy_setopt(eh, CURLOPT_URL, url.data());
    curl_easy_setopt(eh, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(eh, CURLOPT_PRIVATE, res);
    if(ishead){
        curl_easy_setopt(eh, CURLOPT_NOBODY, 1L);
    }else{
        curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(eh, CURLOPT_WRITEDATA, res);
    }

    std::string px = proxym.GetProxy();
    res->pidx = -1;

    if(px.size() != 0){
        curl_easy_setopt(eh, CURLOPT_PROXY, px.data());
        res->pidx = proxym.GetIdx();
    }
    
    
    handles_not_done += 1;
    curl_multi_add_handle(cm, eh);
}

void add_url(std::string url, bool ishead){

    std::string temp = EncodeURL(url);
    if(temp.size() == 0){
        printf("%s\n", url.data());
        return;
    }
    url = temp;

    std::string dir;
    std::string wurl = &(url.data()[url.find("://")+3]);
    std::stringstream ssurl(wurl);
    std::string outurl;
    std::vector<std::string> dirs;

    while(std::getline(ssurl, dir, '/')){
        dirs.push_back(dir);
    }

   dir = "";

    for(int i = 0; i < url.find("://"); i++){
        dir += url.at(i);
    }
    dir += "://"+dirs[0];
    for(int i = 1; i < dirs.size(); i++){

        if(dirs[i] == ".."){
            int idx = outurl.find_last_of("/");
            if(idx != std::string::npos){
                outurl.resize(idx);
            }
        }else if(dirs[i] == "."){

        }
        else{
            outurl += "/"+dirs[i];
        }
    }

    outurl = dir + outurl;

    auto hashidx = outurl.find_last_of("#");
    if(hashidx != std::string::npos){
        outurl.resize(hashidx);
    }

    if(std::find(urls_tobe_rqtd.begin(), urls_tobe_rqtd.end(), std::pair(outurl, ishead)) != urls_tobe_rqtd.end()){
        return;
    }

    std::string v;
    Status s = db->Get(ReadOptions(), cfhandles[1], outurl, &v);
    
    if(s.IsNotFound()){
        std::cout << "[+] " << outurl << std::endl;
        urls_tobe_rqtd.push_back(std::pair(outurl, ishead));
        total_urls_added += 1;
    }
    
}

int Iter(){
    if(db == nullptr){
        return -1;
    }

    std::vector<rocksdb::Iterator*> its;
    Status s = db->NewIterators(ReadOptions(), cfhandles, &its);
    assert(CheckErr(s));

    
    for (its[0]->SeekToFirst(); its[0]->Valid(); its[0]->Next())
    {
        auto value = its[0]->value().ToString();
        auto key = its[0]->key().ToString();
        std::cout << "Key: " << key << " ValueSize: " << value.size() << std::endl;
    }

    free(its[0]);

    for (its[1]->SeekToFirst(); its[1]->Valid(); its[1]->Next())
    {
        auto value = its[1]->value().ToString();
        auto key = its[1]->key().ToString();
        std::cout << "Key: " << key << " Value: " << value << std::endl;
    }

    free(its[1]);


    return 0;
}


void processdata(std::string& resp, std::string ctype, std::string url, std::string ourl, int ct){

    std::string hashsha256 = GenerateSHA256(resp);

    auto wrtopt = rocksdb::WriteOptions();

    url = EncodeURL(url);
    std::string host = GetHost(url);

    float uxtime = std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch()).count();
    
 
    db->Put(wrtopt, hashsha256, Base64Encode(resp));
    db->Put(wrtopt, cfhandles[1], url, hashsha256);
    db->Put(wrtopt, cfhandles[3], ctype, hashsha256);
    std::stringstream ss;
    ss << uxtime;
    db->Put(wrtopt, cfhandles[4], ss.str(), hashsha256);
    db->Put(wrtopt, cfhandles[5], ourl, hashsha256);
    

    if(ctype.find("text/html") != 0){
        return;
    }


    htmlDocPtr doc = htmlReadMemory(resp.data(), resp.size(), NULL, NULL, HTML_PARSE_RECOVER | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);
    if (!doc) {
        fprintf(stderr, "Failed to parse HTML content.\n");
        return;
    }
    
    url.resize(url.find_last_of("/"));


    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
    if (!xpathCtx) {
        fprintf(stderr, "Failed to create XPath context.\n");
        xmlFreeDoc(doc);
        return;
    }


    xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression((xmlChar *)"//a", xpathCtx);
    if (!xpathObj) {
        fprintf(stderr, "Failed to evaluate XPath expression.\n");
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return;
    }
    std::set<std::string> urls;

    xmlNodeSetPtr nodes = xpathObj->nodesetval;
    if (nodes) {
        for (int i = 0; i < nodes->nodeNr; ++i) {
            xmlNode *node = nodes->nodeTab[i];
            if (node->type == XML_ELEMENT_NODE && xmlStrEqual(node->name, (xmlChar *)"a"))
            {
                xmlAttr *attr = node->properties;
                while (attr)
                {
                    if (xmlStrEqual(attr->name, (xmlChar *)"href"))
                    {
                        xmlChar *value = xmlNodeGetContent(attr->children);
                        if (value)
                        {
                            std::string svalue((char *)value);
                            if (svalue.size() != 0)
                            {
                                int idx = svalue.find_last_of("\n");
                                if(idx == svalue.size() - 1){
                                    svalue.resize(idx);
                                }
                                idx = svalue.find_last_of(" ");
                                if(idx == svalue.size() - 1){
                                    svalue.resize(idx);
                                }
                                std::string protocol;
                                std::getline(std::stringstream(url), protocol, ':');

                                std::string svalue((char *)value);
                                if (svalue.find("#") == 0)
                                {
                                    xmlFree(value);
                                    attr = attr->next;
                                    continue;
                                }

                                if (svalue.find("//") == 0)
                                {
                                    svalue = "https:" + svalue;
                                }
                                else if (svalue.find("/") == 0)
                                {
                                    svalue = protocol + "://" + host + svalue;
                                }
                                else if (svalue.find("https://") != 0 && svalue.find("http://") != 0)
                                {
                                    svalue = url + "/" + svalue;
                                }

                                std::string svaluehost = GetHost(svalue);

                                if (svaluehost == host)
                                {
                                    if ((ct & (int)CRAWL_TYPE::SAME_HOST) != 0)
                                    {
                                        urls.insert(svalue);
                                    }
                                }
                                else
                                {
                                    if ((ct & (int)CRAWL_TYPE::EXTERNAL) != 0)
                                    {
                                        urls.insert(svalue);
                                    }
                                }

                                if(svalue.size() > 0){
                                    db->Put(WriteOptions(), cfhandles[2], ourl, svalue);
                                }
                            }

                            xmlFree(value);
                        }
                    }
                    attr = attr->next;
                }
            }
        }
    }


    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    
    for(auto url_ : urls){
        add_url(url_.data(), true);
    }
}

void CleanHandles()
{
    Status s;
    for (int i = 1; i < cfhandles.size(); i++)
    {
        s = db->DestroyColumnFamilyHandle(cfhandles[i]);
        assert(CheckErr(s));
    }
}


int main(int argc, char **argv){

    if(argc < 2){
        printf("Please provide url(s)\n");
        return -1;
    }


    column_families.emplace_back(rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions());
    column_families.emplace_back("URL", rocksdb::ColumnFamilyOptions());
    column_families.emplace_back("Parent", rocksdb::ColumnFamilyOptions());
    column_families.emplace_back("Content-Type", rocksdb::ColumnFamilyOptions());
    column_families.emplace_back("Time", rocksdb::ColumnFamilyOptions());
    column_families.emplace_back("OriginalURL", rocksdb::ColumnFamilyOptions());
    
    xmlInitParser();

    
    options.IncreaseParallelism(1);
    options.OptimizeForSmallDb();

    options.create_if_missing = true;
    options.WAL_size_limit_MB = 3;

    Status s = DB::Open(options, "./data", column_families, &cfhandles, &db);

    if(s.IsInvalidArgument()){
        std::string emsg = s.ToString();
        if(emsg.find("Column family not found") != std::string::npos){
            s = DB::Open(options, "./data", &db);
            assert(CheckErr(s));

            cfhandles.push_back(db->DefaultColumnFamily());

            for(int i = 1; i < column_families.size(); i++){
                auto cfdesc = column_families[i];
                rocksdb::ColumnFamilyHandle *cfhandle;
                s = db->CreateColumnFamily(cfdesc.options, cfdesc.name, &cfhandle);
                assert(CheckErr(s));

                cfhandles.push_back(cfhandle);
            }
            
        }
    }
    
    assert(CheckErr(s));
    int mode = (int)CRAWL_TYPE::SAME_HOST | (int)CRAWL_TYPE::EXTERNAL;

    for (int i = 1; i < argc; i++){
        std::regex urlreg(R"((http|https)://([a-zA-Z0-9._-]+)(:[0-9]+)?(/[a-zA-Z0-9\?\=\+._-]*)*)");
        std::string carg(argv[i]);
        if(carg == "-e"){
            mode |= (int)CRAWL_TYPE::EXTERNAL;
            continue;
        }
        if(carg == "-s"){
            mode |= (int)CRAWL_TYPE::SAME_HOST;
            continue;
        }
        if(std::regex_match(carg, urlreg)){
            printf("[" "\e[1;32m" "Passed" "\e[0;37m" "] %s\n", carg.data());
            add_url(carg, false);
        }else{
            printf("[" "\e[1;31m" "Failed" "\e[0;37m" "] %s\n", carg.data());
        }
    }

    curl_global_init(CURL_GLOBAL_ALL);
    CURLM* cm = curl_multi_init();
    if(!cm){
        CleanHandles();
        delete db;
        fprintf(stderr, "Couldn't initialize curl multi handle\n");
        xmlCleanupParser();
        return -1;
    }
    curl_multi_setopt(cm, CURLMOPT_MAXCONNECTS, (long)max_in_go);
    
    do {
        if (handles_not_done < max_in_go)
        {
            int count = max_in_go - handles_not_done;
            count = std::min(count, (int)urls_tobe_rqtd.size());
            for (int i = 0; i < count; i++)
            {
                auto url = urls_tobe_rqtd.front();
                urls_tobe_rqtd.pop_front();
                add_handle(cm, url.first.data(), url.second);
            }
        }
        CURLMcode cmcode = curl_multi_perform(cm, &running_handles);

        if (cmcode != CURLM_OK){
            curl_multi_cleanup(cm);
            CleanHandles();
            delete db;
            fprintf(stderr, "url_multi_perform failed!\n %s\n", curl_multi_strerror(cmcode));
            xmlCleanupParser();
            return -1;
        }

        int msg_in_q = -1;
        CURLMsg* cmmsg = NULL;
        do {
            cmmsg = curl_multi_info_read(cm, &msg_in_q);
            
            if(cmmsg != NULL){
                
                CURL *eh = cmmsg->easy_handle;

                
                char *url = NULL;
                
                curl_easy_getinfo(eh, CURLINFO_EFFECTIVE_URL, &url);
                

                if (cmmsg->msg == CURLMSG_DONE)
                {
                    Response *res = NULL;
                    curl_easy_getinfo(eh, CURLINFO_PRIVATE, &res);

                    if (res->pidx != -1)
                    {
                        std::string cproxy = proxym.GetProxyAt(res->pidx);
                        int ptype = proxym.GetProxyType(cproxy);
                        if (ptype > 3)
                        {
                            long pecode = NULL;
                            CURLcode err = curl_easy_getinfo(eh, CURLINFO_PROXY_ERROR, &pecode);

                            if (!err && pecode)
                            {
                                proxym.RemoveProxy(res->pidx);
                                add_url(url, false);
                            }
                            
                        }
                    }

                    if (cmmsg->data.result == CURLE_OK)
                    {
                        

                        char *ctype = NULL;
                        curl_easy_getinfo(eh, CURLINFO_CONTENT_TYPE, &ctype);

                        if (res->ishead)
                        {
                            if (ctype != NULL)
                            {
                                if (std::string(ctype).find("text/html") == 0)
                                {
                                    add_url(url, false);
                                }
                            }
                            
                        }
                        if (res->data != NULL)
                        {
                            std::string resp(res->data, res->size);
                            processdata(resp, ctype, url, res->url, mode);
                            free(res->data);
                        }
                    }else{
                        
                        if(res->data != NULL){
                            free(res->data);
                        }
                    }

                    free(res->url);
                    free(res);
                    remove_handle_cleanup(cm, cmmsg->easy_handle);
                }
            }   
        }while(msg_in_q > 0);


        if(handles_not_done > 0){
            curl_multi_wait(cm, NULL, 0, 5000, NULL);
        }

    } while(handles_not_done > 0 || urls_tobe_rqtd.size() > 0);

    
    CleanHandles();

    curl_multi_cleanup(cm);
    curl_global_cleanup();
    delete db;
    xmlCleanupParser();
    return 0;
}
