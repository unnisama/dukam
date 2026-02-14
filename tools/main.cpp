#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/utilities/options_util.h>
#include <iostream>
#include <memory>
#include <iomanip>
#include <vector>
#include "turbobase64/turbob64.h" // Assuming this is in your include path

// Standard Base64 Decode using your TurboBase64 library
std::string Base64Decode(const std::string& in) {
    if (in.empty()) return "";
    int decodedLen = tb64declen((unsigned char *)in.data(), in.size());
    std::string decodedData(decodedLen, '\0');
    tb64dec((unsigned char *)in.data(), in.size(), (unsigned char *)decodedData.data());
    return decodedData;
}

void print_hex(const std::string& data) {
    for (unsigned char c : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(c);
    }
    std::cout << std::dec << "\n";
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage:\n";
        std::cerr << "  " << argv[0] << " <db_path> scan <cf_name>\n";
        std::cerr << "  " << argv[0] << " <db_path> get <cf_name> <key> [--decode]\n";
        std::cerr << "CF Names: default, URL, Parent, Content-Type, Time, OriginalURL\n";
        return 1;
    }

    std::string db_path = argv[1];
    std::string command = argv[2];

    // 1. List all column families - Using the explicit DB:: scope
    std::vector<std::string> cf_names;
    rocksdb::Options options;
    rocksdb::Status s = rocksdb::DB::ListColumnFamilies(options, db_path, &cf_names);
    
    if (!s.ok()) {
        std::cerr << "Warning: Could not list CFs, defaulting to 'default'. Error: " << s.ToString() << "\n";
        cf_names.push_back(rocksdb::kDefaultColumnFamilyName);
    }

    // 2. Prepare descriptors
    std::vector<rocksdb::ColumnFamilyDescriptor> column_families;
    for (const auto& name : cf_names) {
        column_families.push_back(rocksdb::ColumnFamilyDescriptor(name, rocksdb::ColumnFamilyOptions()));
    }

    // 3. Open DB for ReadOnly
    rocksdb::DB* db_ptr_raw;
    std::vector<rocksdb::ColumnFamilyHandle*> handles;
    s = rocksdb::DB::OpenForReadOnly(rocksdb::DBOptions(), db_path, column_families, &handles, &db_ptr_raw);

    if (!s.ok()) {
        std::cerr << "Failed to open DB: " << s.ToString() << "\n";
        return 1;
    }

    std::unique_ptr<rocksdb::DB> db(db_ptr_raw);

    auto get_handle = [&](const std::string& name) -> rocksdb::ColumnFamilyHandle* {
        for (auto h : handles) {
            if (h->GetName() == name) return h;
        }
        return nullptr;
    };

    if (command == "get") {
        if (argc < 5) {
            std::cerr << "Usage: get <cf_name> <key> [--decode]\n";
            return 1;
        }
        std::string cf_name = argv[3];
        std::string key = argv[4];
        bool should_decode = (argc == 6 && std::string(argv[5]) == "--decode");
        std::string value;

        auto* h = get_handle(cf_name);
        if (!h) { std::cerr << "CF [" << cf_name << "] not found\n"; return 1; }

        s = db->Get(rocksdb::ReadOptions(), h, key, &value);
        if (s.ok()) {
            std::cout << "--- Value for [" << key << "] ---\n";
            if (should_decode) {
                std::cout << Base64Decode(value) << "\n";
            } else {
                std::cout << "Raw: " << value << "\n";
            }
        } else {
            std::cerr << "Key not found: " << s.ToString() << "\n";
        }
    } 
    
    else if (command == "scan") {
        std::string cf_name = argv[3];
        auto* h = get_handle(cf_name);
        if (!h) { std::cerr << "CF not found\n"; return 1; }

        std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions(), h));
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            std::cout << "Key: " << std::left << std::setw(50) << it->key().ToString() 
                      << " | Size: " << it->value().size() << "\n";
        }
    }

    for (auto h : handles) db->DestroyColumnFamilyHandle(h);
    return 0;
}
