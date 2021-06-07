

#include "psa_checksum.h"
#include <iostream>

namespace bm {

namespace psa {

void
PSA_Checksum::init() {
  this->clear();
}

void PSA_Checksum:: get(Field& dst) {
  dst.set(internal.get<uint64_t>());
}

void PSA_Checksum::get_verify(Field& dst, Field& equOp) {
  if (equOp.get<uint64_t>()!=internal.get<uint64_t>()) {
    dst.set(false);
  } else {
    dst.set(true);
  }
}

void PSA_Checksum::clear() {
  internal.set(0);
}

void PSA_Checksum::update(const NamedCalculation& calculation) {
  const uint64_t cksum = calculation.output(get_packet());
  this->internal.set(cksum);
}

BM_REGISTER_EXTERN_W_NAME(Checksum,PSA_Checksum);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum,update, const NamedCalculation&);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum,get, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum,get_verify, Field &, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum,clear);

}  // namespace bm::psa

}  // namespace bm

int import_checksums() {
  return 0;
}
