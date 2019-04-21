#ifndef BM_BM_SIM_PSA_COUNTER_H_
#define BM_BM_SIM_PSA_COUNTER_H_

#include "extern.h"
#include "named_p4object.h"
#include "packet.h"

#include <vector>

namespace bm {

class P_Counter {
    public:
      using counter_value_t = uint64_t;

      enum CounterErrorCode {
        SUCCESS = 0,
        INVALID_COUNTER_NAME,
        INVALID_INDEX,
        ERROR
      };

      void increment_counter(const Packet &pkt);
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

  class PSA_Counter : public ExternType {
   public:
    static constexpr unsigned int BYTES = 0;
    static constexpr unsigned int PACKETS = 1;
    static constexpr unsigned int PACKETS_AND_BYTES = 2;

    BM_EXTERN_ATTRIBUTES {
      BM_EXTERN_ATTRIBUTE_ADD(n_counters);
      BM_EXTERN_ATTRIBUTE_ADD(type);
    }

    void init();

    P_Counter &get_counter(size_t idx);

    const P_Counter &get_counter(size_t idx) const;

    P_Counter &operator[](size_t idx);

    const P_Counter &operator[](size_t idx) const;

    size_t size() const;

   private:
    // declared attributes
    Data n_counters;
    Data type;
    std::vector<P_Counter> counters;

  };
}  // namespace br
#endif
