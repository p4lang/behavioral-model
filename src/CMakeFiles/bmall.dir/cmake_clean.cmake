file(REMOVE_RECURSE
  "libbmall.pdb"
  "libbmall.so"
)

# Per-language clean rules from dependency scanning.
foreach(lang C CXX)
  include(CMakeFiles/bmall.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
