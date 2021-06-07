

#ifndef PSA_SWITCH_PSA_CHECKSUM_H_
#define PSA_SWITCH_PSA_CHECKSUM_H_

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/calculations.h>


namespace bm {

namespace psa {

class PSA_Checksum : public bm::ExternType {
 public:
  static constexpr p4object_id_t spec_id = 0xfffffffd;

  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(hash);
  }

  void init() override;

  void get(Field& dst);

  void get_verify(Field& dst, Field& equOp);
  
  void clear();

  void update(const NamedCalculation& calculation);

 private:
  std::string hash;
  Data internal;

};

}  // namespace bm::psa

}  // namespace bm
#endif
