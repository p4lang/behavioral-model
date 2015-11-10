#include <iostream>

#include <nanomsg/pubsub.h>

#include <cassert>

#include <netinet/in.h>

#include "nn.h"

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include <thrift/protocol/TMultiplexedProtocol.h>

#include "Standard.h"
#include "SimplePre.h"

typedef struct {
  int switch_id;
  int list_id;
  unsigned long long buffer_id;
  unsigned int num_samples;
} __attribute__((packed)) learn_hdr_t;

typedef struct {
  char src_addr[6];
  short ingress_port;
} __attribute__((packed)) sample_t;

using namespace bm_runtime::standard;

using namespace p4::thrift;
using namespace p4::thrift::protocol;
using namespace p4::thrift::transport;

int main() {

  boost::shared_ptr<TTransport> socket(new TSocket("localhost", 9090));
  boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
  boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

  boost::shared_ptr<TMultiplexedProtocol> standard_protocol(
    new TMultiplexedProtocol(protocol, "standard")
  );

  StandardClient client(standard_protocol);

  transport->open();

  nn::socket s(AF_SP, NN_SUB);
  s.setsockopt(NN_SUB, NN_SUB_SUBSCRIBE, "", 0);
  s.connect("ipc:///tmp/test_bm_learning.ipc");

  struct nn_msghdr msghdr;
  struct nn_iovec iov[2];
  learn_hdr_t learn_hdr;
  char data[2048];
  iov[0].iov_base = &learn_hdr;
  iov[0].iov_len = sizeof(learn_hdr);
  iov[1].iov_base = data;
  iov[1].iov_len = sizeof(data); // apparently only max size needed ?
  memset(&msghdr, 0, sizeof(msghdr));
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 2;

  while(s.recvmsg(&msghdr, 0) >= 0) {
    std::cout << "I received " << learn_hdr.num_samples << " samples"
	      << std::endl;

    for(unsigned int i = 0; i < learn_hdr.num_samples; i++) {
      sample_t *sample = ((sample_t *) data) + i;

      std::cout << "ingress port is " << ntohs(sample->ingress_port)
		<< std::endl;

      BmMatchParam match_param;
      match_param.type = BmMatchParamType::type::EXACT;
      BmMatchParamExact match_param_exact;
      match_param_exact.key =
	std::string(sample->src_addr, sizeof(sample->src_addr));
      match_param.__set_exact(match_param_exact);

      BmAddEntryOptions options;

      client.bm_mt_add_entry("smac", {match_param},
			     "_nop", std::vector<std::string>(),
			     options);

      std::vector<std::string> action_data =
	{std::string((char *) &sample->ingress_port, 2)};

      client.bm_mt_add_entry("dmac", {match_param},
			     "forward", std::move(action_data),
			     options);
    }

    client.bm_learning_ack_buffer(learn_hdr.list_id, learn_hdr.buffer_id);
  }

  return 0;
}
