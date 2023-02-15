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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <bf_lpm_trie/bf_lpm_trie.h>

typedef unsigned char byte_t;

#define _unused(x) ((void)(x))

typedef struct branch_s {
  byte_t v;
  struct node_s *next;
} branch_t;

typedef struct branches_vec_s {
  int16_t size;
  int16_t capacity;
  struct branch_s *branches;
} branches_vec_t;

typedef struct prefix_s {
  uint8_t prefix_length;
  byte_t key;
  value_t value;
} prefix_t;

typedef struct prefixes_vec_s {
  int16_t size;
  int16_t capacity;
  struct prefix_s *prefixes;
} prefixes_vec_t;

typedef struct node_s {
  branches_vec_t branches;
  prefixes_vec_t prefixes;
  struct node_s *parent;
  byte_t child_id;
} node_t;

struct bf_lpm_trie_s {
  node_t *root;
  size_t key_width_bytes;
  bool release_memory;
};

static inline void allocate_node(node_t ** node) {
  *node = (node_t *) malloc(sizeof(node_t));
  memset(*node, 0, sizeof(node_t));
}

bf_lpm_trie_t *bf_lpm_trie_create(size_t key_width_bytes, bool auto_shrink) {
  assert(key_width_bytes <= 64);
  bf_lpm_trie_t *trie = (bf_lpm_trie_t *) malloc(sizeof(bf_lpm_trie_t));
  trie->key_width_bytes = key_width_bytes;
  trie->release_memory = auto_shrink;
  allocate_node(&trie->root);
  return trie;
}

static void destroy_node(node_t *node) {
  free(node->prefixes.prefixes);
  int16_t i;
  for (i = 0; i < node->branches.size; i++) {
    destroy_node(node->branches.branches[i].next);
  }
  free(node->branches.branches);
  free(node);
}

void bf_lpm_trie_destroy(bf_lpm_trie_t *t) {
  destroy_node(t->root);
  free(t);
}

static inline node_t *get_next_node(const node_t *current_node, byte_t byte) {
  const branches_vec_t *branches = &current_node->branches;
  int a = 0;
  int b = branches->size;
  while (a < b) {
    int idx = a + (b - a) / 2;
    byte_t v = branches->branches[idx].v;
    if (byte < v) {
      b = idx;
    } else if (byte > v) {
      a = idx + 1;
    } else {
      return branches->branches[idx].next;
    }
  }
  return NULL;
}

static inline void set_next_node(node_t *current_node, byte_t byte,
				 node_t *next_node) {
  branches_vec_t *branches = &current_node->branches;
  int a = 0;
  int b = branches->size;
  while (a < b) {
    int idx = a + (b - a) / 2;
    byte_t v = branches->branches[idx].v;
    if (byte < v) {
      b = idx;
    } else if (byte > v) {
      a = idx + 1;
    } else {
      return;
    }
  }

  if (branches->size == branches->capacity) {
    branches->capacity += 4;
    branches->branches = realloc(
        branches->branches, branches->capacity * sizeof(*branches->branches));
  }
  size_t size = (branches->size - a) * sizeof(*branches->branches);
  memmove(&branches->branches[a + 1], &branches->branches[a], size);
  branches->branches[a].v = byte;
  branches->branches[a].next = next_node;
  branches->size++;
}

static inline int delete_branch(node_t *current_node, byte_t byte) {
  branches_vec_t *branches = &current_node->branches;
  int a = 0;
  int b = branches->size;
  int idx = 0;
  while (a < b) {
    idx = a + (b - a) / 2;
    byte_t v = branches->branches[idx].v;
    if (byte < v) {
      b = idx;
    } else if (byte > v) {
      a = idx + 1;
    } else {
      break;
    }
  }
  if (a == b) return 0;

  size_t size = (branches->size - idx - 1) * sizeof(*branches->branches);
  memmove(&branches->branches[idx], &branches->branches[idx + 1], size);
  branches->size--;
  return 1;
}

static inline int prefix_cmp(const prefix_t *p1, const prefix_t *p2) {
  if (p1->prefix_length == p2->prefix_length) {
    return (int) p1->key - (int) p2->key;
  }
  return (int) p2->prefix_length - (int) p1->prefix_length;
}

/* returns 1 if was present, 0 otherwise */
static inline int insert_prefix(node_t *current_node,
                                uint8_t prefix_length,
                                byte_t key,
                                value_t value) {
  prefixes_vec_t *prefixes = &current_node->prefixes;
  prefix_t prefix = {prefix_length, key, value};
  int a = 0;
  int b = prefixes->size;
  while (a < b) {
    int idx = a + (b - a) / 2;
    prefix_t *p = &prefixes->prefixes[idx];
    int c = prefix_cmp(&prefix, p);
    if (c < 0) {
      b = idx;
    } else if (c > 0) {
      a = idx + 1;
    } else {
      p->value = value;
      return 1;
    }
  }

  if (prefixes->size == prefixes->capacity) {
    prefixes->capacity += 4;
    prefixes->prefixes = realloc(
        prefixes->prefixes, prefixes->capacity * sizeof(*prefixes->prefixes));
  }
  size_t size = (prefixes->size - a) * sizeof(*prefixes->prefixes);
  memmove(&prefixes->prefixes[a + 1], &prefixes->prefixes[a], size);
  prefixes->prefixes[a] = prefix;
  prefixes->size++;
  return 0;
}

static inline prefix_t *get_prefix(const node_t *current_node,
                                   uint8_t prefix_length,
                                   byte_t key) {
  const prefixes_vec_t *prefixes = &current_node->prefixes;
  prefix_t prefix = {prefix_length, key, 0};
  int a = 0;
  int b = prefixes->size;
  while (a < b) {
    int idx = a + (b - a) / 2;
    prefix_t *p = &prefixes->prefixes[idx];
    int c = prefix_cmp(&prefix, p);
    if (c < 0) {
      b = idx;
    } else if (c > 0) {
      a = idx + 1;
    } else {
      return p;
    }
  }
  return NULL;
}

static inline prefix_t *get_empty_prefix(const node_t *current_node) {
  const prefixes_vec_t *prefixes = &current_node->prefixes;
  if (prefixes->size == 0) return NULL;
  prefix_t *p = &prefixes->prefixes[prefixes->size - 1];
  return (p->prefix_length == 0) ? p : NULL;
}

/* returns 1 if was present, 0 otherwise */
static inline int delete_prefix(node_t *current_node,
                                uint8_t prefix_length,
                                byte_t key) {
  prefixes_vec_t *prefixes = &current_node->prefixes;
  prefix_t prefix = {prefix_length, key, 0};
  int a = 0;
  int b = prefixes->size;
  int idx;
  while (a < b) {
    idx = a + (b - a) / 2;
    prefix_t *p = &prefixes->prefixes[idx];
    int c = prefix_cmp(&prefix, p);
    if (c < 0) {
      b = idx;
    } else if (c > 0) {
      a = idx + 1;
    } else {
      break;
    }
  }
  if (a == b) return 0;

  size_t size = (prefixes->size - idx - 1) * sizeof(*prefixes->prefixes);
  memmove(&prefixes->prefixes[idx], &prefixes->prefixes[idx + 1], size);
  prefixes->size--;
  return 1;
}

void bf_lpm_trie_insert(bf_lpm_trie_t *trie,
			const char *prefix, int prefix_length,
			const value_t value) {
  node_t *current_node = trie->root;
  byte_t byte;

  while(prefix_length >= 8) {
    byte = (byte_t) *prefix;
    node_t *node = get_next_node(current_node, byte);
    if(!node) {
      allocate_node(&node);
      node->parent = current_node;
      node->child_id = byte;
      set_next_node(current_node, byte, node);
    }

    prefix++;
    prefix_length -= 8;
    current_node = node;
  }

  unsigned key = (unsigned) (unsigned char) *prefix >> (8 - prefix_length);

  insert_prefix(current_node, (uint8_t) prefix_length, key, value);
}

bool bf_lpm_trie_retrieve_value(const bf_lpm_trie_t *trie,
                                const char *prefix, int prefix_length,
                                value_t *pvalue) {
  node_t *current_node = trie->root;
  byte_t byte;

  while(prefix_length >= 8) {
    byte = (byte_t) *prefix;
    node_t *node = get_next_node(current_node, byte);
    if(!node)
      return false;

    prefix++;
    prefix_length -= 8;
    current_node = node;
  }

  unsigned key = (unsigned) (unsigned char) *prefix >> (8 - prefix_length);

  prefix_t *p = get_prefix(current_node, prefix_length, key);
  if (p == NULL) {
    return false;
  }

  *pvalue = p->value;
  return true;
}

bool bf_lpm_trie_has_prefix(const bf_lpm_trie_t *trie,
			    const char *prefix, int prefix_length) {
  value_t value;
  return bf_lpm_trie_retrieve_value(trie, prefix, prefix_length, &value);
}

bool bf_lpm_trie_lookup(const bf_lpm_trie_t *trie, const char *key,
			value_t *pvalue) {
  const node_t *current_node = trie->root;
  unsigned byte;
  size_t key_width = trie->key_width_bytes;
  bool found = false;
  int16_t i;
  prefix_t *p;

  while(current_node) {
    if (key_width == 0) {
      p = get_empty_prefix(current_node);
      if (p) {
        *pvalue = p->value;
        found = true;
      }
      break;
    }

    for (i = 0; i < current_node->prefixes.size; i++) {
      p = &current_node->prefixes.prefixes[i];
      byte = (unsigned) (unsigned char) *key >> (8 - p->prefix_length);
      if (p->key == byte) {
        found = true;
        *pvalue = p->value;
        break;
      }
    }

    current_node = get_next_node(current_node, *key);
    key++;
    key_width--;
  }

  return found;
}

bool bf_lpm_trie_delete(bf_lpm_trie_t *trie, const char *prefix,
			int prefix_length) {
  node_t *current_node = trie->root;
  byte_t byte;

  while(prefix_length >= 8) {
    byte = (byte_t) *prefix;
    node_t *node = get_next_node(current_node, byte);
    if(!node) return NULL;

    prefix++;
    prefix_length -= 8;
    current_node = node;
  }

  byte_t key = (unsigned) (unsigned char) *prefix >> (8 - prefix_length);

  if (!get_prefix(current_node, prefix_length, key)) return false;

  int success;
  _unused(success);
  if(trie->release_memory) {
    success = delete_prefix(current_node, prefix_length, key);
    assert(success == 1);
    while(current_node->prefixes.size == 0 && current_node->branches.size == 0) {
      node_t *tmp = current_node;
      current_node = current_node->parent;
      if(!current_node) break;
      success = delete_branch(current_node, tmp->child_id);
      assert(success == 1);
      free(tmp->branches.branches);
      free(tmp->prefixes.prefixes);
      free(tmp);
    }
  }

  return true;
}

#undef _unused
