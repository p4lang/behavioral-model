# Create bflpmtrie library
add_library(bflpmtrie OBJECT
  bf_lpm_trie.c
)

# Set include directories
target_include_directories(bflpmtrie PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)
