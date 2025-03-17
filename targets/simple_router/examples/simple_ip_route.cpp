#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <bitset>
#include <cassert>
#include "bf_lpm_trie.h"

// Function to convert dotted decimal IPv4 to binary (stored in 4 bytes)
bool ip_to_binary(const std::string& ip, char* binary) {
    std::stringstream ss(ip);
    std::string segment;
    int i = 0;
    
    while (std::getline(ss, segment, '.')) {
        try {
            int octet = std::stoi(segment);
            if (octet < 0 || octet > 255) {
                return false;
            }
            binary[i++] = static_cast<char>(octet);
        } catch (...) {
            return false;
        }
    }
    
    return (i == 4); // Make sure we got all 4 octets
}

// Function to print binary representation of an IP
void print_binary_ip(const char* binary) {
    std::cout << "  Binary: ";
    for (int i = 0; i < 4; i++) {
        std::cout << std::bitset<8>(static_cast<unsigned char>(binary[i])) << " ";
    }
    std::cout << std::endl;
}

// Represents a route with IP, prefix length, and description
struct Route {
    std::string ip;
    int prefix_len;
    int value;
    std::string description;
    
    Route(const std::string& i, int p, int v, const std::string& d)
        : ip(i), prefix_len(p), value(v), description(d) {}
};

int main() {
    std::cout << "IP Routing Example using LPM Trie\n";
    std::cout << "================================\n\n";

    // Create an LPM trie with 4-byte keys (IPv4 addresses)
    bm::BfLpmTrie trie(4, true);

    // Define a set of routes from most specific to least specific
    std::vector<Route> routes = {
        Route("192.168.1.1", 32, 1, "Host route - 192.168.1.1"),
        Route("192.168.1.0", 24, 2, "Subnet - 192.168.1.0/24"),
        Route("192.168.0.0", 16, 3, "Network - 192.168.0.0/16"),
        Route("10.0.0.0", 8, 4, "Class A network - 10.0.0.0/8"),
        Route("0.0.0.0", 0, 5, "Default route - 0.0.0.0/0")
    };

    // Insert routes - starting with least specific (to ensure most specific take precedence)
    std::cout << "Inserting routes:\n";
    for (auto it = routes.rbegin(); it != routes.rend(); ++it) {
        const auto& route = *it;
        char binary_ip[4] = {0};
        
        if (!ip_to_binary(route.ip, binary_ip)) {
            std::cerr << "Error: Invalid IP address: " << route.ip << std::endl;
            continue;
        }
        
        std::cout << "  " << std::left << std::setw(16) << route.ip << "/"
                  << std::setw(2) << route.prefix_len << " - " 
                  << route.description << std::endl;
        
        trie.insert(binary_ip, route.prefix_len, route.value);
    }
    std::cout << std::endl;

    // Define test IPs that should match different route levels
    std::vector<std::pair<std::string, std::string>> test_ips = {
        {"192.168.1.1", "Should match the host route (/32)"},
        {"192.168.1.2", "Should match the subnet (/24)"},
        {"192.168.2.1", "Should match the network (/16)"},
        {"10.1.1.1", "Should match the Class A network (/8)"},
        {"8.8.8.8", "Should match the default route (/0)"}
    };

    // Test lookups
    std::cout << "Testing lookups:\n";
    for (const auto& test : test_ips) {
        char binary_ip[4] = {0};
        if (!ip_to_binary(test.first, binary_ip)) {
            std::cerr << "Error: Invalid IP address: " << test.first << std::endl;
            continue;
        }
        
        std::cout << "Looking up: " << std::left << std::setw(16) << test.first
                  << " (" << test.second << ")" << std::endl;
        print_binary_ip(binary_ip);
        
        bm::value_t value = 0;
        bool found = trie.lookup(binary_ip, &value);
        
        std::cout << "  Result: ";
        if (found) {
            bool matched = false;
            for (const auto& route : routes) {
                if (route.value == value) {
                    std::cout << "Matched " << route.description 
                              << " (value " << value << ")" << std::endl;
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                std::cout << "Matched unknown route with value " << value << std::endl;
            }
        } else {
            std::cout << "No matching route found!" << std::endl;
        }
        std::cout << std::endl;
    }
    
    // Demonstrate deleting a route and the effect on routing
    std::cout << "Deleting subnet route 192.168.1.0/24\n";
    char delete_ip[4] = {0};
    ip_to_binary("192.168.1.0", delete_ip);
    trie.delete_prefix(delete_ip, 24);
    
    // Look up an IP that previously matched the deleted subnet
    std::cout << "Looking up 192.168.1.2 after subnet deletion:\n";
    char test_ip[4] = {0};
    ip_to_binary("192.168.1.2", test_ip);
    print_binary_ip(test_ip);
    
    bm::value_t value = 0;
    bool found = trie.lookup(test_ip, &value);
    
    std::cout << "  Result: ";
    if (found) {
        bool matched = false;
        for (const auto& route : routes) {
            if (route.value == value) {
                std::cout << "Now matched " << route.description 
                          << " (value " << value << ")" << std::endl;
                matched = true;
                break;
            }
        }
        if (!matched) {
            std::cout << "Matched unknown route with value " << value << std::endl;
        }
    } else {
        std::cout << "No matching route found!" << std::endl;
    }
    
    return 0;
} 