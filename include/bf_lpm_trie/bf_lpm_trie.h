#ifndef BF_LPM_TRIE_H
#define BF_LPM_TRIE_H

#include <cstdint>
#include <vector>
#include <memory>
#include <optional>
#include <string_view>

namespace bf {

using value_t = std::uintptr_t;
using byte_t = std::uint8_t;

class LpmTrie {
private:
    class Node;

    struct Branch;
    struct Prefix;

    std::unique_ptr<Node> root;
    size_t key_width_bytes;
    bool release_memory;

public:
    explicit LpmTrie(size_t key_width_bytes, bool auto_shrink = false);
    ~LpmTrie();

    // Disallow copy
    LpmTrie(const LpmTrie&) = delete;
    LpmTrie& operator=(const LpmTrie&) = delete;

    // Allow move
    LpmTrie(LpmTrie&&) noexcept;
    LpmTrie& operator=(LpmTrie&&) noexcept;

    void insert(std::string_view prefix, int prefix_length, value_t value);
    std::optional<value_t> retrieveValue(std::string_view prefix, int prefix_length) const;
    bool hasPrefix(std::string_view prefix, int prefix_length) const;
    std::optional<value_t> lookup(std::string_view key) const;
    bool deletePrefix(std::string_view prefix, int prefix_length);
};

} // namespace bf

#endif // BF_LPM_TRIE_H
