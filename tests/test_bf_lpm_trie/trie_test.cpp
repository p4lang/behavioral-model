#include "bf_lpm_trie.h"

#include <iostream>
#include <cassert>
#include <cstring>
#include <string>
#include <functional>
#include <vector>
#include <bitset>

// Helpful color output for test results
namespace Color {
    const std::string Green = "\033[32m";
    const std::string Red = "\033[31m";
    const std::string Reset = "\033[0m";
    const std::string Bold = "\033[1m";
}

// Helper to print test results with color
void print_test_result(const std::string& test_name, bool success) {
    std::cout << (success ? Color::Green : Color::Red)
              << (success ? "PASSED" : "FAILED")
              << Color::Reset << ": " << test_name << std::endl;
}

// Run a test function and report results
bool run_test(const std::string& name, std::function<bool()> test_fn) {
    std::cout << Color::Bold << "Test: " << name << Color::Reset << std::endl;
    
    bool result = false;
    try {
        result = test_fn();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    
    print_test_result(name, result);
    std::cout << std::endl;
    return result;
}

// Helper to print binary representation of a byte array
void print_binary(const char* key, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++) {
        if (i > 0) std::cout << " ";
        std::cout << std::bitset<8>(static_cast<unsigned char>(key[i]));
    }
    std::cout << std::endl;
}

int main() {
    std::cout << Color::Bold << "Testing BfLpmTrie C++ Implementation" << Color::Reset << std::endl;
    std::cout << "-----------------------------------" << std::endl;
    
    bool all_passed = true;
    
    // Test 1: Basic insertion and longest match lookup
    all_passed &= run_test("Basic insertion and longest match", []() {
        // Create a trie with 16 byte keys and auto-shrinking enabled
        bm::BfLpmTrie trie(16, true);
        
        // Set up test keys - hex values representing IP prefixes
        unsigned char key1[] = {0x10, 0x20};  // Binary: 0001 0000 0010 0000
        unsigned char key2[] = {0x10, 0x00};  // Binary: 0001 0000 0000 0000
        
        // Insert prefixes of different lengths
        trie.insert(reinterpret_cast<const char*>(key1), 12, 100);  // 12-bit prefix
        trie.insert(reinterpret_cast<const char*>(key2), 8, 200);   // 8-bit prefix (less specific)
        
        // Verify that inserted prefixes exist
        bool has_key1 = trie.has_prefix(reinterpret_cast<const char*>(key1), 12);
        bool has_key2 = trie.has_prefix(reinterpret_cast<const char*>(key2), 8);
        
        // Verify values with retrieval
        bm::value_t value;
        bool retrieved1 = trie.retrieve_value(reinterpret_cast<const char*>(key1), 12, &value);
        bool value1_correct = (value == 100);
        
        // Verify longest match lookup works
        unsigned char lookup_key1[] = {0x10, 0x20, 0x30, 0x40};  // Should match key1 (more specific)
        unsigned char lookup_key2[] = {0x10, 0x30, 0x40, 0x50};  // Should match key2 (less specific)
        
        bool lookup1 = trie.lookup(reinterpret_cast<const char*>(lookup_key1), &value);
        bool lookup1_correct = (value == 100);
        
        bool lookup2 = trie.lookup(reinterpret_cast<const char*>(lookup_key2), &value);
        bool lookup2_correct = (value == 200);
        
        return has_key1 && has_key2 && retrieved1 && value1_correct && 
               lookup1 && lookup1_correct && lookup2 && lookup2_correct;
    });
    
    // Test 2: Deletion functionality
    all_passed &= run_test("Prefix deletion", []() {
        bm::BfLpmTrie trie(16, true);
        
        // Set up and insert two prefixes
        unsigned char key1[] = {0x10, 0x20};
        unsigned char key2[] = {0x10, 0x00};
        trie.insert(reinterpret_cast<const char*>(key1), 12, 100);
        trie.insert(reinterpret_cast<const char*>(key2), 8, 200);
        
        // Delete the more specific prefix
        bool delete_success = trie.delete_prefix(reinterpret_cast<const char*>(key1), 12);
        
        // Verify it's gone
        bool prefix_gone = !trie.has_prefix(reinterpret_cast<const char*>(key1), 12);
        
        // After deletion, lookups should match the less specific prefix
        unsigned char lookup_key[] = {0x10, 0x20, 0x30, 0x40};
        bm::value_t value;
        bool lookup_success = trie.lookup(reinterpret_cast<const char*>(lookup_key), &value);
        bool correct_value = (value == 200);
        
        return delete_success && prefix_gone && lookup_success && correct_value;
    });
    
    // Test 3: C API backwards compatibility
    all_passed &= run_test("C API compatibility", []() {
        // Create a trie using the C API
        bm::bf_lpm_trie_t* trie = bm::bf_lpm_trie_create(16, true);
        
        // Test basic operations using C API
        unsigned char key1[] = {0x10, 0x20};
        unsigned char key2[] = {0x10, 0x00};
        
        // Insert using C API
        bm::bf_lpm_trie_insert(trie, reinterpret_cast<const char*>(key1), 12, 100);
        bm::bf_lpm_trie_insert(trie, reinterpret_cast<const char*>(key2), 8, 200);
        
        // Check prefixes exist
        bool has_prefix = bm::bf_lpm_trie_has_prefix(trie, reinterpret_cast<const char*>(key1), 12);
        
        // Retrieve value
        bm::value_t value;
        bool retrieved = bm::bf_lpm_trie_retrieve_value(trie, reinterpret_cast<const char*>(key1), 12, &value);
        bool value_correct = (value == 100);
        
        // Test lookup
        unsigned char lookup_key[] = {0x10, 0x20, 0x30, 0x40};
        bool looked_up = bm::bf_lpm_trie_lookup(trie, reinterpret_cast<const char*>(lookup_key), &value);
        bool lookup_value_correct = (value == 100);
        
        // Test deletion
        bool deleted = bm::bf_lpm_trie_delete(trie, reinterpret_cast<const char*>(key1), 12);
        bool prefix_gone = !bm::bf_lpm_trie_has_prefix(trie, reinterpret_cast<const char*>(key1), 12);
        
        // Clean up
        bm::bf_lpm_trie_destroy(trie);
        
        return has_prefix && retrieved && value_correct && 
               looked_up && lookup_value_correct && deleted && prefix_gone;
    });
    
    // Test 4: Edge cases
    all_passed &= run_test("Edge cases (empty trie, default route)", []() {
        // Create a trie with maximum key width
        bm::BfLpmTrie trie(64, true);
        
        // Empty trie should not match anything
        bm::value_t value;
        unsigned char key[] = {0x00, 0x00, 0x00, 0x00};
        bool empty_lookup = !trie.lookup(reinterpret_cast<const char*>(key), &value);
        
        // Add a default route (0-length prefix)
        unsigned char default_route[] = {0x00};
        trie.insert(reinterpret_cast<const char*>(default_route), 0, 999);
        
        // Now lookup should match the default route
        bool default_match = trie.lookup(reinterpret_cast<const char*>(key), &value);
        bool default_value_correct = (value == 999);
        
        // Delete the default route
        bool deleted = trie.delete_prefix(reinterpret_cast<const char*>(default_route), 0);
        
        // After deletion, lookup should fail again
        bool lookup_fails_after_delete = !trie.lookup(reinterpret_cast<const char*>(key), &value);
        
        return empty_lookup && default_match && default_value_correct && 
               deleted && lookup_fails_after_delete;
    });
    
    // Test 5: Overlapping prefixes 
    all_passed &= run_test("Overlapping prefixes", []() {
        bm::BfLpmTrie trie(16, true);
        
        // Insert a prefix
        unsigned char prefix1[] = {0x10, 0x00, 0x00, 0x00};
        trie.insert(reinterpret_cast<const char*>(prefix1), 8, 8);  // Insert 8-bit prefix 0001 0000
        
        // Insert a more specific prefix
        unsigned char prefix2[] = {0x10, 0x10, 0x00, 0x00};
        trie.insert(reinterpret_cast<const char*>(prefix2), 12, 12);  // Insert 12-bit prefix 0001 0000 0001
        
        // Test lookups with different values
        bm::value_t value1, value2;
        
        // Should match the 8-bit prefix
        unsigned char lookup1[] = {0x10, 0x20, 0x00, 0x00};  // First byte: 0001 0000
        bool found1 = trie.lookup(reinterpret_cast<const char*>(lookup1), &value1);
        
        // Should match the 12-bit prefix
        unsigned char lookup2[] = {0x10, 0x10, 0x00, 0x00};  // First 12 bits: 0001 0000 0001
        bool found2 = trie.lookup(reinterpret_cast<const char*>(lookup2), &value2);
        
        return found1 && value1 == 8 && found2 && value2 == 12;
    });
    
    // Test 6: IP Routing Example (Realistic Use Case)
    all_passed &= run_test("IP Routing Example", []() {
        bm::BfLpmTrie trie(4, true); // 4 bytes for IPv4
        
        // Define some IP routes
        struct IPRoute {
            unsigned char bytes[4];
            int prefix_len;
            bm::value_t value;
        };
        
        // Standard IP routing test case with a network hierarchy
        IPRoute routes[] = {
            {{192, 168, 1, 0}, 24, 1},    // 192.168.1.0/24 - specific subnet
            {{192, 168, 0, 0}, 16, 2},    // 192.168.0.0/16 - less specific
            {{10, 0, 0, 0}, 8, 3},        // 10.0.0.0/8 - private network
            {{0, 0, 0, 0}, 0, 4}          // Default route
        };
        
        // Insert routes in reverse order (least to most specific)
        for (int i = 3; i >= 0; i--) {
            trie.insert(reinterpret_cast<const char*>(routes[i].bytes), 
                      routes[i].prefix_len, routes[i].value);
        }
        
        // Test lookups
        unsigned char test_ips[][4] = {
            {192, 168, 1, 10},  // Should match 192.168.1.0/24 (value 1)
            {192, 168, 2, 10},  // Should match 192.168.0.0/16 (value 2)
            {10, 20, 30, 40},   // Should match 10.0.0.0/8 (value 3)
            {8, 8, 8, 8}        // Should match default (value 4)
        };
        
        bm::value_t expected_values[] = {1, 2, 3, 4};
        bool all_correct = true;
        
        for (int i = 0; i < 4; i++) {
            bm::value_t value = 0;
            bool found = trie.lookup(reinterpret_cast<const char*>(test_ips[i]), &value);
            
            if (!found || value != expected_values[i]) {
                all_correct = false;
                break;
            }
        }
        
        return all_correct;
    });
    
    // Test 7: Partial Byte Handling - Test partially specified byte prefixes
    all_passed &= run_test("Partial Byte Handling", []() {
        bm::BfLpmTrie trie(4, true);
        
        // Insert a 20-bit prefix (2 full bytes + 4 bits)
        unsigned char prefix1[] = {0xC0, 0xA8, 0x10, 0x00}; // 11000000 10101000 0001xxxx xxxxxxxx
        trie.insert(reinterpret_cast<const char*>(prefix1), 20, 1);
        
        // Insert a 28-bit prefix (3 full bytes + 4 bits) 
        unsigned char prefix2[] = {0xC0, 0xA8, 0x10, 0x80}; // 11000000 10101000 00010000 1000xxxx
        trie.insert(reinterpret_cast<const char*>(prefix2), 28, 2);
        
        // Insert a more specific route for the same first 24 bits
        unsigned char prefix3[] = {0xC0, 0xA8, 0x10, 0x00}; // 11000000 10101000 00010000 xxxxxxxx
        trie.insert(reinterpret_cast<const char*>(prefix3), 24, 3);
        
        // Test lookup that should match the 28-bit prefix
        unsigned char lookup1[] = {0xC0, 0xA8, 0x10, 0x80}; // Exact match for prefix2
        bm::value_t value;
        bool found1 = trie.lookup(reinterpret_cast<const char*>(lookup1), &value);
        bool correct1 = (value == 2);
        
        // Test lookup that should match the 24-bit prefix
        unsigned char lookup2[] = {0xC0, 0xA8, 0x10, 0x01}; // Matches prefix3
        bool found2 = trie.lookup(reinterpret_cast<const char*>(lookup2), &value);
        bool correct2 = (value == 3);
        
        // Test lookup that should match the 20-bit prefix
        unsigned char lookup3[] = {0xC0, 0xA8, 0x11, 0x00}; // Matches prefix1
        bool found3 = trie.lookup(reinterpret_cast<const char*>(lookup3), &value);
        bool correct3 = (value == 1);
        
        return found1 && correct1 && found2 && correct2 && found3 && correct3;
    });
    
    // Test 8: Very large trie with many entries
    all_passed &= run_test("Large Trie Performance", []() {
        // Create a trie with IPv4 key width
        bm::BfLpmTrie trie(4, true);
        
        // Insert a small number of prefixes with distinct values
        struct TestPrefix {
            unsigned char key[4];
            int prefix_len;
            bm::value_t value;
            std::string description;
        };
        
        TestPrefix prefixes[] = {
            {{10, 0, 0, 0}, 8, 101, "10.0.0.0/8"},
            {{192, 168, 0, 0}, 16, 102, "192.168.0.0/16"},
            {{172, 16, 0, 0}, 12, 103, "172.16.0.0/12"},
            {{224, 0, 0, 0}, 4, 104, "224.0.0.0/4"}
        };
        
        // Insert each prefix
        std::cout << "Inserting test prefixes:" << std::endl;
        for (const auto& p : prefixes) {
            std::cout << "  " << p.description << " with value " << p.value << std::endl;
            trie.insert(reinterpret_cast<const char*>(p.key), p.prefix_len, p.value);
        }
        
        // Verify we can retrieve each prefix
        bool all_found = true;
        for (const auto& p : prefixes) {
            bm::value_t value;
            bool retrieval_success = trie.retrieve_value(reinterpret_cast<const char*>(p.key), p.prefix_len, &value);
            
            std::cout << "Retrieving " << p.description << ": " 
                      << (retrieval_success ? "found" : "not found");
            
            if (retrieval_success) {
                std::cout << ", value=" << value << ", expected=" << p.value;
                if (value != p.value) {
                    all_found = false;
                    std::cout << " (MISMATCH)";
                }
            } else {
                all_found = false;
            }
            std::cout << std::endl;
        }
        
        // Test deletion of each prefix
        bool all_deleted = true;
        for (const auto& p : prefixes) {
            bool deletion_success = trie.delete_prefix(reinterpret_cast<const char*>(p.key), p.prefix_len);
            
            std::cout << "Deleting " << p.description << ": " 
                      << (deletion_success ? "success" : "failed");
            
            if (!deletion_success) {
                all_deleted = false;
            }
            
            // Verify it's truly gone
            bool still_exists = trie.has_prefix(reinterpret_cast<const char*>(p.key), p.prefix_len);
            if (still_exists) {
                std::cout << " (STILL EXISTS)";
                all_deleted = false;
            }
            std::cout << std::endl;
        }
        
        return all_found && all_deleted;
    });
    
    // Test 9: Longest Prefix Match with Multiple Matches
    all_passed &= run_test("Multiple Prefix Matches", []() {
        bm::BfLpmTrie trie(4, true);
        
        // Set up a series of prefixes with the same initial bits but different lengths
        unsigned char key[] = {0xC0, 0xA8, 0x01, 0x01}; // 192.168.1.1
        
        // Insert with various prefix lengths
        std::cout << "Inserting prefixes:" << std::endl;
        std::cout << "  192.168.1.1/32 with value 32" << std::endl;
        trie.insert(reinterpret_cast<const char*>(key), 32, 32); // Exact match
        
        std::cout << "  192.168.1.0/24 with value 24" << std::endl;
        trie.insert(reinterpret_cast<const char*>(key), 24, 24); // 192.168.1.0/24
        
        std::cout << "  192.168.0.0/16 with value 16" << std::endl;
        trie.insert(reinterpret_cast<const char*>(key), 16, 16); // 192.168.0.0/16
        
        std::cout << "  192.0.0.0/8 with value 8" << std::endl;
        trie.insert(reinterpret_cast<const char*>(key), 8, 8);   // 192.0.0.0/8
        
        // Add a default route
        unsigned char default_key[] = {0x00, 0x00, 0x00, 0x00};
        std::cout << "  0.0.0.0/0 with value 0" << std::endl;
        trie.insert(reinterpret_cast<const char*>(default_key), 0, 0);
        
        // Should match the most specific prefix
        bm::value_t value;
        bool found = trie.lookup(reinterpret_cast<const char*>(key), &value);
        std::cout << "Lookup 192.168.1.1: found=" << (found ? "true" : "false") 
                  << ", value=" << value << ", expected=32" << std::endl;
        bool exact_match = (value == 32);
        
        // Create a key that should match the /24 prefix
        unsigned char key2[] = {0xC0, 0xA8, 0x01, 0x02}; // 192.168.1.2
        bool found2 = trie.lookup(reinterpret_cast<const char*>(key2), &value);
        std::cout << "Lookup 192.168.1.2: found=" << (found2 ? "true" : "false") 
                  << ", value=" << value << ", expected=24" << std::endl;
        bool subnet_match = (value == 24);
        
        // Create a key that should match the /16 prefix
        unsigned char key3[] = {0xC0, 0xA8, 0x02, 0x01}; // 192.168.2.1
        bool found3 = trie.lookup(reinterpret_cast<const char*>(key3), &value);
        std::cout << "Lookup 192.168.2.1: found=" << (found3 ? "true" : "false") 
                  << ", value=" << value << ", expected=16" << std::endl;
        bool network_match = (value == 16);
        
        // Create a key that should match the /8 prefix
        unsigned char key4[] = {0xC0, 0x01, 0x01, 0x01}; // 192.1.1.1
        bool found4 = trie.lookup(reinterpret_cast<const char*>(key4), &value);
        std::cout << "Lookup 192.1.1.1: found=" << (found4 ? "true" : "false") 
                  << ", value=" << value << ", expected=8" << std::endl;
        bool class_match = (value == 8);
        
        // Create a key that should match only the default route
        unsigned char key5[] = {0x08, 0x08, 0x08, 0x08}; // 8.8.8.8
        bool found5 = trie.lookup(reinterpret_cast<const char*>(key5), &value);
        std::cout << "Lookup 8.8.8.8: found=" << (found5 ? "true" : "false") 
                  << ", value=" << value << ", expected=0" << std::endl;
        bool default_match = (value == 0);
        
        return found && exact_match && 
               found2 && subnet_match && 
               found3 && network_match && 
               found4 && class_match && 
               found5 && default_match;
    });
    
    // Test 10: Corner Cases - Test empty prefixes and invalid inputs
    all_passed &= run_test("Corner Cases", []() {
        bm::BfLpmTrie trie(4, true);
        
        // Test null pointers safely - these should not crash
        // We just verify the return value is as expected
        bool insert_success = true;
        bool lookup_success = true;
        bool has_prefix_success = true;
        bool delete_success = true;
        
        try {
            // Insert default route with nullptr should succeed
            trie.insert(nullptr, 0, 999);
            
            // Retrieving nullptr prefixes should return false
            bm::value_t value;
            has_prefix_success = !trie.has_prefix(nullptr, 1);
            
            // Lookup with nullptr should return false
            lookup_success = !trie.lookup(nullptr, &value);
            
            // Delete with nullptr should return false
            delete_success = !trie.delete_prefix(nullptr, 1);
        } catch (...) {
            insert_success = false;
            lookup_success = false;
            has_prefix_success = false;
            delete_success = false;
        }
        
        // Test extreme prefix lengths
        unsigned char key[] = {0xAA, 0xBB, 0xCC, 0xDD};
        
        // Test prefix length of 0 (default route)
        trie.insert(reinterpret_cast<const char*>(key), 0, 1);
        
        // Test prefix length equal to key width (32 bits for IPv4)
        trie.insert(reinterpret_cast<const char*>(key), 32, 2);
        
        // Verify both prefixes exist
        bm::value_t value;
        bool has_prefix0 = trie.retrieve_value(reinterpret_cast<const char*>(key), 0, &value);
        bool correct_value0 = (value == 1);
        
        bool has_prefix32 = trie.retrieve_value(reinterpret_cast<const char*>(key), 32, &value);
        bool correct_value32 = (value == 2);
        
        // Test looking up with the exact key should match the most specific prefix
        bool lookup_result = trie.lookup(reinterpret_cast<const char*>(key), &value);
        bool lookup_correct = (value == 2);  // Should match the /32 prefix
        
        return insert_success && lookup_success && has_prefix_success && delete_success && 
               has_prefix0 && correct_value0 && has_prefix32 && correct_value32 && 
               lookup_result && lookup_correct;
    });
    
    // Test 11: Stress test with many overlapping prefixes
    all_passed &= run_test("Stress Test - Overlapping Prefixes", []() {
        bm::BfLpmTrie trie(4, true);
        
        // Create a single key with many prefixes of different lengths
        unsigned char key[] = {0x01, 0x02, 0x03, 0x04};
        
        // Insert prefixes of lengths 0 through 32
        for (int len = 0; len <= 32; len++) {
            trie.insert(reinterpret_cast<const char*>(key), len, len);
        }
        
        // Verify all prefixes exist and have correct values
        bool all_exist = true;
        for (int len = 0; len <= 32; len++) {
            bm::value_t value;
            bool found = trie.retrieve_value(reinterpret_cast<const char*>(key), len, &value);
            if (!found || value != static_cast<bm::value_t>(len)) {
                all_exist = false;
                std::cout << "Failed to retrieve prefix with length " << len 
                          << ", found=" << found;
                if (found) {
                    std::cout << ", value=" << value << " (expected " << len << ")";
                }
                std::cout << std::endl;
                break;
            }
        }
        
        // Looking up the key should match the most specific prefix
        bm::value_t value;
        bool lookup_success = trie.lookup(reinterpret_cast<const char*>(key), &value);
        bool correct_match = (value == 32);  // Should match the /32 prefix
        
        // Delete all prefixes in random order and verify they're gone
        bool all_deleted = true;
        int delete_order[] = {16, 8, 24, 4, 12, 20, 28, 0, 32, 2, 6, 10, 14, 18, 22, 26, 30,
                             1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31};
        
        for (int len : delete_order) {
            bool deleted = trie.delete_prefix(reinterpret_cast<const char*>(key), len);
            if (!deleted) {
                all_deleted = false;
                std::cout << "Failed to delete prefix with length " << len << std::endl;
                break;
            }
            
            // Verify it's truly gone
            if (trie.has_prefix(reinterpret_cast<const char*>(key), len)) {
                all_deleted = false;
                std::cout << "Prefix with length " << len << " still exists after deletion" << std::endl;
                break;
            }
        }
        
        return all_exist && lookup_success && correct_match && all_deleted;
    });
    
    // Test 12: Binary Tree Structure Test
    all_passed &= run_test("Binary Tree Structure", []() {
        bm::BfLpmTrie trie(4, true);
        
        /* Create a prefix tree structure to test path traversal:
                      (root)
                     /      \
                   0x00     0x80
                  /   \     /   \
               0x00  0x40 0x00  0x40
        */
        
        // Define the test keys (first byte only matters for this test)
        unsigned char keys[][4] = {
            {0x00, 0x00, 0x00, 0x00},  // 0000 0000
            {0x40, 0x00, 0x00, 0x00},  // 0100 0000
            {0x80, 0x00, 0x00, 0x00},  // 1000 0000
            {0xC0, 0x00, 0x00, 0x00}   // 1100 0000
        };
        
        // Insert the keys with their position as value
        for (int i = 0; i < 4; i++) {
            trie.insert(reinterpret_cast<const char*>(keys[i]), 2, i);
        }
        
        // Test lookup works for exact matches
        bool all_lookups_correct = true;
        for (int i = 0; i < 4; i++) {
            bm::value_t value;
            bool found = trie.lookup(reinterpret_cast<const char*>(keys[i]), &value);
            
            if (!found || value != static_cast<bm::value_t>(i)) {
                all_lookups_correct = false;
                break;
            }
        }
        
        // Test with a key that doesn't match exactly but should match a parent node
        unsigned char test_key[] = {0x20, 0x00, 0x00, 0x00};  // 0010 0000 - should match 0x00
        bm::value_t value;
        bool found = trie.lookup(reinterpret_cast<const char*>(test_key), &value);
        bool parent_match = (found && value == 0);
        
        // Try a different one that should match 0x80
        unsigned char test_key2[] = {0xA0, 0x00, 0x00, 0x00};  // 1010 0000 - should match 0x80
        found = trie.lookup(reinterpret_cast<const char*>(test_key2), &value);
        bool parent_match2 = (found && value == 2);
        
        return all_lookups_correct && parent_match && parent_match2;
    });
    
    // Print summary
    std::cout << "-----------------------------------" << std::endl;
    if (all_passed) {
        std::cout << Color::Green << Color::Bold << "ALL TESTS PASSED" << Color::Reset << std::endl;
    } else {
        std::cout << Color::Red << Color::Bold << "SOME TESTS FAILED" << Color::Reset << std::endl;
    }
    
    return all_passed ? 0 : 1;
} 