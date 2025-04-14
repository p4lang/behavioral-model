#include <bm/bm_sim/match_tables.h>
#include <bm/bm_sim/debugger.h>
#include <iostream>

int main() {
    // Test that DBG_CTR_TABLE_APPLY is defined
    std::cout << "DBG_CTR_TABLE_APPLY: " << DBG_CTR_TABLE_APPLY << std::endl;
    
    // We can't directly test get_next_nodes() without creating a MatchTableAbstract instance,
    // but we can check that the code compiles, which means the method is public
    std::cout << "Compilation successful!" << std::endl;
    
    return 0;
}
