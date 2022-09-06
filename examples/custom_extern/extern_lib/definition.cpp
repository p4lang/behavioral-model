#include <bm/bm_sim/extern.h>

// Example custom extern function.
void custom_set(bm::Data & a, const bm::Data & b) {
	a.set(b);
}
BM_REGISTER_EXTERN_FUNCTION(custom_set, bm::Data &, const bm::Data &);

// Example custom extern object.
class CustomCounter : public bm::ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(init_count);
  }

  void init() override {
    reset();
  }

  void reset() {
    count = init_count;
  }

  void read(bm::Data &count) const {
    count = this->count;
  }

  void increment_by(const bm::Data &amount) {
    count.set(count.get<size_t>() + amount.get<size_t>());
  }

 private:
  bm::Data init_count{0};
  bm::Data count{0};
};
BM_REGISTER_EXTERN(CustomCounter);
BM_REGISTER_EXTERN_METHOD(CustomCounter, reset);
BM_REGISTER_EXTERN_METHOD(CustomCounter, read, bm::Data &);
BM_REGISTER_EXTERN_METHOD(CustomCounter, increment_by, const bm::Data &);
