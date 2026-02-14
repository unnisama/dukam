#include <curl/curl.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/write_batch.h>
#include <iostream>
#include <deque>
#include <algorithm>
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <chrono>
#include <memory>
#include <regex>

// Assuming these custom headers are in your path
#include "proxy.h"
#include "city.h"
#include "turbobase64/turbob64.h"

using namespace rocksdb;


enum class CRAWL_TYPE { SAME_HOST = 1, EXTERNAL = 2 };

struct Response {
    std::string buffer;
    std::string original_url;
    int pidx = -1;
    bool ishead = false;
};
struct Config {
    std::string data_dir = "./data";
    int mode = (int)CRAWL_TYPE::SAME_HOST;
    int max_in_flight = 4;
    std::string proxy_file;
    std::vector<std::string> start_urls;
};

int handles_not_done = 0;
DB* db = nullptr;
std::vector<ColumnFamilyHandle*> cfhandles;
std::deque<std::pair<std::string, bool>> urls_tobe_rqtd;
ProxyManager proxym;


void PrintUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options] <url> [url2 ...]\n\n"
              << "Options:\n"
              << "  --data-dir <path>     RocksDB folder (default: ./data)\n"
              << "  --same-host           Crawl same host links\n"
              << "  --external            Crawl external links\n"
              << "  --max <n>             Max concurrent requests (default: 4)\n"
              << "  --proxy-file <file>   Load proxies from file\n"
              << "  --help                Show this message\n";
}

bool ParseArgs(int argc, char** argv, Config& cfg) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help") {
            PrintUsage(argv[0]);
            return false;
        }
        else if (arg == "--data-dir") {
            if (++i >= argc) {
                std::cerr << "Missing value for --data-dir\n";
                return false;
            }
            cfg.data_dir = argv[i];
        }
        else if (arg == "--same-host") {
            cfg.mode |= (int)CRAWL_TYPE::SAME_HOST;
        }
        else if (arg == "--external") {
            cfg.mode |= (int)CRAWL_TYPE::EXTERNAL;
        }
        else if (arg == "--max") {
            if (++i >= argc) {
                std::cerr << "Missing value for --max\n";
                return false;
            }
            cfg.max_in_flight = std::stoi(argv[i]);
            if (cfg.max_in_flight <= 0) {
                std::cerr << "--max must be > 0\n";
                return false;
            }
        }
        else if (arg == "--proxy-file") {
            if (++i >= argc) {
                std::cerr << "Missing value for --proxy-file\n";
                return false;
            }
            cfg.proxy_file = argv[i];
        }
        else if (arg.rfind("-", 0) == 0) {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }
        else {
            cfg.start_urls.push_back(arg);
        }
    }

    if (cfg.start_urls.empty()) {
        std::cerr << "At least one start URL is required\n";
        return false;
    }

    return true;
}


// Using the most robust URL normalization method for libcurl 8.18.0
std::string NormalizeURL(const std::string& url_str, const std::string& base_ctx = "") {
    CURLU *h = curl_url();
    if (!h) return "";

    if (!base_ctx.empty()) {
        curl_url_set(h, CURLUPART_URL, base_ctx.c_str(), 0);
    }

    // CURLU_ALLOW_SPACE is helpful for messy HTML
    CURLUcode rc = curl_url_set(h, CURLUPART_URL, url_str.c_str(), CURLU_DEFAULT_SCHEME | CURLU_ALLOW_SPACE);

    if (rc != CURLUE_OK) {
        curl_url_cleanup(h);
        return "";
    }

    char *tmp = nullptr;
    std::string result;
    if (curl_url_get(h, CURLUPART_URL, &tmp, 0) == CURLUE_OK) {
        result = tmp;
        curl_free(tmp);
    }
    
    curl_url_cleanup(h);
    return result;
}

std::string GetHost(const std::string& url) {
    CURLU *h = curl_url();
    curl_url_set(h, CURLUPART_URL, url.c_str(), 0);
    char *tmp;
    std::string host;
    if (curl_url_get(h, CURLUPART_HOST, &tmp, 0) == CURLUE_OK) {
        host = tmp;
        curl_free(tmp);
    }
    curl_url_cleanup(h);
    return host;
}

std::string GenerateSHA256(const std::string& data) {
    uint128 chash = CityHash128(data.data(), data.size());
    std::ostringstream oss;
    oss << std::hex << Uint128Low64(chash) << Uint128High64(chash);
    return oss.str();
}

std::string Base64Encode(const std::string& in) {
    std::string out(tb64enclen(in.size()), '\0');
    tb64enc((const unsigned char*)in.data(), in.size(), (unsigned char*)out.data());
    return out;
}

static size_t write_cb(char *data, size_t n, size_t l, void *userp) {
    size_t total = n * l;
    static_cast<Response*>(userp)->buffer.append(data, total);
    return total;
}

void add_url(const std::string& url, bool ishead) {
    std::string normalized = NormalizeURL(url);
    if (normalized.empty()) return;

    std::string v;
    if (db->Get(ReadOptions(), cfhandles[1], normalized, &v).IsNotFound()) {
        // Double check we aren't already queuing it
        auto it = std::find_if(urls_tobe_rqtd.begin(), urls_tobe_rqtd.end(), 
                  [&](const auto& p){ return p.first == normalized; });
        if (it == urls_tobe_rqtd.end()) {
            std::cout << "[+] Enqueued: " << normalized << (ishead ? " (HEAD)" : "") << std::endl;
            urls_tobe_rqtd.push_back({normalized, ishead});
        }
    }
}

void processdata(const std::string& resp, const std::string& ctype, const std::string& url, const std::string& ourl, int mode) {
    std::string hash = GenerateSHA256(resp);
    std::string host = GetHost(url);
    auto uxtime = std::chrono::system_clock::now().time_since_epoch().count();

    WriteBatch batch;
    batch.Put(hash, Base64Encode(resp));
    batch.Put(cfhandles[1], url, hash);
    batch.Put(cfhandles[3], ctype, hash);
    batch.Put(cfhandles[4], std::to_string(uxtime), hash);
    batch.Put(cfhandles[5], ourl, hash);
    db->Write(WriteOptions(), &batch);

    if (ctype.find("text/html") == std::string::npos) return;

    htmlDocPtr doc = htmlReadMemory(resp.data(), resp.size(), url.c_str(), NULL, HTML_PARSE_RECOVER | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);
    if (!doc) return;

    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
    xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression((xmlChar*)"//a/@href", xpathCtx);

    if (xpathObj && xpathObj->nodesetval) {
        for (int i = 0; i < xpathObj->nodesetval->nodeNr; ++i) {
            xmlNodePtr attr = xpathObj->nodesetval->nodeTab[i];
            xmlChar* href = xmlNodeGetContent(attr);
            if (href) {
                std::string link = NormalizeURL((char*)href, url);
                if (!link.empty()) {
                    std::string linkHost = GetHost(link);
                    bool isSame = (linkHost == host);
                    if ((isSame && (mode & (int)CRAWL_TYPE::SAME_HOST)) || (!isSame && (mode & (int)CRAWL_TYPE::EXTERNAL))) {
                        add_url(link, true);
                        db->Put(WriteOptions(), cfhandles[2], url, link);
                    }
                }
                xmlFree(href);
            }
        }
    }
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
}

void add_handle(CURLM *cm, const std::string& url, bool ishead) {
    CURL* eh = curl_easy_init();
    Response* res = new Response();
    res->ishead = ishead;
    res->original_url = url;

    curl_easy_setopt(eh, CURLOPT_URL, url.c_str());
    curl_easy_setopt(eh, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(eh, CURLOPT_PRIVATE, res);
    curl_easy_setopt(eh, CURLOPT_TIMEOUT, 15L); // Prevent hanging
    
    if (ishead) {
        curl_easy_setopt(eh, CURLOPT_NOBODY, 1L);
    } else {
        curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(eh, CURLOPT_WRITEDATA, res);
    }

    std::string px = proxym.GetProxy();
    if (!px.empty()) {
        curl_easy_setopt(eh, CURLOPT_PROXY, px.c_str());
        res->pidx = proxym.GetIdx();
    }

    curl_multi_add_handle(cm, eh);
    handles_not_done++;
}

int main(int argc, char **argv) {

    Config cfg;
    if (!ParseArgs(argc, argv, cfg)) {
        return -1;
    }

    if (!cfg.proxy_file.empty()) {
        proxym = ProxyManager(cfg.proxy_file);
    }

    // RocksDB Configuration
    Options options;
    options.create_if_missing = true;
    options.create_missing_column_families = true;

    std::vector<ColumnFamilyDescriptor> column_families = {
        {kDefaultColumnFamilyName, ColumnFamilyOptions()},
        {"URL", ColumnFamilyOptions()},
        {"Parent", ColumnFamilyOptions()},
        {"Content-Type", ColumnFamilyOptions()},
        {"Time", ColumnFamilyOptions()},
        {"OriginalURL", ColumnFamilyOptions()}
    };

    Status s = DB::Open(options, cfg.data_dir, column_families, &cfhandles, &db);
    if (!s.ok()) {
        std::cerr << "RocksDB Open Failed: " << s.ToString() << std::endl;
        return -1;
    }

    xmlInitParser();
    curl_global_init(CURL_GLOBAL_ALL);
    CURLM* cm = curl_multi_init();

    for (const auto& url : cfg.start_urls) {
        add_url(url, false);
    }

    int mode = cfg.mode;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-e") mode |= (int)CRAWL_TYPE::EXTERNAL;
        else if (arg == "-s") mode |= (int)CRAWL_TYPE::SAME_HOST;
        else add_url(arg, false);
    }
    if (mode == 0) mode = (int)CRAWL_TYPE::SAME_HOST;

    int running = 0;
    do {
        while (handles_not_done < cfg.max_in_flight && !urls_tobe_rqtd.empty()) {
            auto url_pair = urls_tobe_rqtd.front();
            urls_tobe_rqtd.pop_front();
            add_handle(cm, url_pair.first, url_pair.second);
        }

        CURLMcode mc = curl_multi_perform(cm, &running);
        
        int msgs_left;
        CURLMsg *msg;
        while ((msg = curl_multi_info_read(cm, &msgs_left))) {
            if (msg->msg == CURLMSG_DONE) {
                CURL *eh = msg->easy_handle;
                Response *res;
                curl_easy_getinfo(eh, CURLINFO_PRIVATE, &res);
                char *eff_url;
                curl_easy_getinfo(eh, CURLINFO_EFFECTIVE_URL, &eff_url);

                if (msg->data.result == CURLE_OK) {
                    char *ctype = nullptr;
                    curl_easy_getinfo(eh, CURLINFO_CONTENT_TYPE, &ctype);
                    std::string ctype_str = ctype ? ctype : "";

                    if (res->ishead) {
                        if (ctype_str.find("text/html") != std::string::npos) {
                            add_url(eff_url, false);
                        }
                    } else {
                        processdata(res->buffer, ctype_str, eff_url, res->original_url, mode);
                    }
                }
                
                std::cout << "[-] Finished: " << eff_url << " (" << msg->data.result << ")" << std::endl;
                curl_multi_remove_handle(cm, eh);
                curl_easy_cleanup(eh);
                delete res;
                handles_not_done--;
            }
        }
        if (running) curl_multi_wait(cm, NULL, 0, 100, NULL);

    } while (handles_not_done > 0 || !urls_tobe_rqtd.empty());

    // Clean shutdown
    for (auto* h : cfhandles) db->DestroyColumnFamilyHandle(h);
    delete db;
    curl_multi_cleanup(cm);
    curl_global_cleanup();
    xmlCleanupParser();
    return 0;
}