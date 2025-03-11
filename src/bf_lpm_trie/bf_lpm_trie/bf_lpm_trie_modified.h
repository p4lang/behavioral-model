/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas
 *
 */

#ifndef _BF_LPM_TRIE_H
#define _BF_LPM_TRIE_H


#include <cstdint>
#include <cassert>
#include <memory>
#include <vector>

namespace bm{
// Hao: uintptr_t is a c type, equivalent to unsigned long, but need to make sure
typedef std::uintptr_t value_t;
typedef unsigned char byte_t;

class Node;

struct Branch {
	byte_t v;
	std::unique_ptr<Node> next;
};

class BranchesVec {
	public:
		void addBranch(byte_t byte, std::unique_ptr<Node> nextNode);
		Node* getNextNode(byte_t byte) const;
		bool deleteBranch(byte_t byte);
		bool isEmpty() const { return branches.empty(); }
	
private:
	std::vector<Branch> branches;
};

struct Prefix {
	uint8_t prefix_length;
	byte_t key;
	value_t value;
	// replace prefix_cmp, order from long to short
	bool operator<(const Prefix& other) const {
		return (prefix_length == other.prefix_length) ? (key < other.key)
													  : (prefix_length > other.prefix_length);
	}
  };

class PrefixesVec {
public:
	void insertPrefix(uint8_t prefix_length, byte_t key, value_t value);
	Prefix* getPrefix(uint8_t prefix_length, byte_t key);
	bool deletePrefix(uint8_t prefix_length, byte_t key);
	bool isEmpty() const { return prefixes.empty(); }
	Prefix* back() { return prefixes.back().get(); }

private:
	std::vector<std::unique_ptr<Prefix>> prefixes;
};

class Node {
public:
	explicit Node(Node* parent = nullptr, byte_t child_id = 0)
		: parent(parent), child_id(child_id) {}

	Node* getNextNode(byte_t byte) const {
		return branches.getNextNode(byte);
	}

	void setNextNode(byte_t byte, std::unique_ptr<Node> nextNode) {
		branches.addBranch(byte, std::move(nextNode));
	}

	Prefix* getPrefix(uint8_t prefix_length, byte_t key) {
		return prefixes.getPrefix(prefix_length, key);
	}

	bool insertPrefix(uint8_t prefix_length, byte_t key, value_t value) {
		prefixes.insertPrefix(prefix_length, key, value);
		return true;
	}

	bool deletePrefix(uint8_t prefix_length, byte_t key) {
		return prefixes.deletePrefix(prefix_length, key);
	}

	bool isEmpty() const {
		return prefixes.isEmpty() && branches.isEmpty();
	}

	void deleteBranch(byte_t byte) {
		branches.deleteBranch(byte);
	}

	bool getEmptyPrefix(Prefix *prefix); 

	Node* getParent() const { return parent; }

	byte_t getChildID() const { return child_id; }

private:
	BranchesVec branches;
	PrefixesVec prefixes;
	Node* parent;
	byte_t child_id;
};

// Hao: check if bf_lpm_trie_destroy is needed, if not, rely on unique_ptr to manage memory
// destroy_node us only used in bf_lpm_trie_destroy
class BfLpmTrie {
public:
	BfLpmTrie(std::size_t key_width_bytes, bool auto_shrink)
		: key_width_bytes(key_width_bytes), release_memory(auto_shrink) {
		assert(key_width_bytes <= 64);
		root = std::make_unique<Node>();
	}

	void insert(const std::string& prefix, int prefix_length, value_t value);
	bool retrieveValue(const std::string& prefix, int prefix_length, value_t& value) const;
	bool hasPrefix(const std::string& prefix, int prefix_length) const;
	bool remove(const std::string& prefix, int prefix_length); 
	bool lookup(const std::string& key, value_t& value) const;

private:
	std::unique_ptr<Node> root;
	std::size_t key_width_bytes;
	// Hao: used to free up memo for trie deletion, not needed, remove
	bool release_memory;
};

}  // namespace bm
#endif
