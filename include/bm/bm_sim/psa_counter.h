#include "extern.h"
#include "named_p4object.h"
#include "packet.h"

#include <vector>

namespace bm {

  class PSA_Counter {
    public:
      using counter_value_t = uint64_t;

      enum CounterErrorCode {
        SUCCESS = 0,
        INVALID_COUNTER_NAME,
        INVALID_INDEX,
        ERROR
      };

      void increment_counter(const Packet &pkt){
        bytes += pkt.get_ingress_length();
        packets += 1;
        std::cout << "??????\n" << std::endl;
      };
      CounterErrorCode query_counter(counter_value_t *bytes,
                                     counter_value_t *packets) const;
      CounterErrorCode reset_counter();
      CounterErrorCode write_counter(counter_value_t bytes,
                                     counter_value_t packets);

      void serialize(std::ostream *out) const;
      void deserialize(std::istream *in);

    private:
      std::atomic<std::uint_fast64_t> bytes{0u};
      std::atomic<std::uint_fast64_t> packets{0u};
  };

  class ExternCounter : public ExternType {
   public:
    static constexpr unsigned int BYTES = 0;
    static constexpr unsigned int PACKETS = 1;
    static constexpr unsigned int PACKETS_AND_BYTES = 2;

    BM_EXTERN_ATTRIBUTES {
      BM_EXTERN_ATTRIBUTE_ADD(n_counters);
      BM_EXTERN_ATTRIBUTE_ADD(type);
    }

    void init() {
      std::cout << "Initializing counter with " << n_counters.get_uint() << std::endl;
      counters = std::vector<PSA_Counter>(n_counters.get_uint());
    }

    PSA_Counter &get_counter(size_t idx) {
      return counters[idx];
    }

    const PSA_Counter &get_counter(size_t idx) const {
      return counters[idx];
    }

    PSA_Counter &operator[](size_t idx) {
      assert(idx < size());
    }

    const PSA_Counter &operator[](size_t idx) const {
      assert(idx < size());
    }

    size_t size() const { return counters.size(); }

   private:
    // declared attributes
    Data n_counters;
    Data type;
    std::vector<PSA_Counter> counters;

  };
}  // namespace bm
