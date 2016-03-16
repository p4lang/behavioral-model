/* Copyright 2013-present Barefoot Networks, Inc.
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
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifdef P4THRIFT
#include <p4thrift/protocol/TBinaryProtocol.h>
#include <p4thrift/server/TSimpleServer.h>
#include <p4thrift/server/TThreadedServer.h>
#include <p4thrift/transport/TServerSocket.h>
#include <p4thrift/transport/TBufferTransports.h>
#include <p4thrift/processor/TMultiplexedProcessor.h>

namespace thrift_provider = p4::thrift;
#else
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/processor/TMultiplexedProcessor.h>

namespace thrift_provider = apache::thrift;
#endif

#include <thread>
#include <mutex>

#include "Standard_server.ipp"
#include "SimplePre_server.ipp"
#include "SimplePreLAG_server.ipp"

using namespace ::thrift_provider;
using namespace ::thrift_provider::protocol;
using namespace ::thrift_provider::transport;
using namespace ::thrift_provider::server;

using boost::shared_ptr;

using ::bm_runtime::standard::StandardHandler;
using ::bm_runtime::standard::StandardProcessor;
using ::bm_runtime::simple_pre::SimplePreHandler;
using ::bm_runtime::simple_pre::SimplePreProcessor;
using ::bm_runtime::simple_pre_lag::SimplePreLAGHandler;
using ::bm_runtime::simple_pre_lag::SimplePreLAGProcessor;

namespace bm_runtime {

bm::SwitchWContexts *switch_;
TMultiplexedProcessor *processor_;

namespace {

std::mutex m_ready;
std::condition_variable cv_ready;
bool ready = false;

template<typename T>
bool switch_has_component() {
  // TODO(antonin): do something more resilient (i.e. per context)
  return (switch_->get_cxt_component<T>(0) != nullptr);
}

int serve(int port) {
  shared_ptr<TMultiplexedProcessor> processor(new TMultiplexedProcessor());
  processor_ = processor.get();

  shared_ptr<StandardHandler> standard_handler(new StandardHandler(switch_));
  processor->registerProcessor(
    "standard",
    shared_ptr<TProcessor>(new StandardProcessor(standard_handler))
  );

  if(switch_has_component<bm::McSimplePre>()) {
    shared_ptr<SimplePreHandler> simple_pre_handler(new SimplePreHandler(switch_));
    processor->registerProcessor(
      "simple_pre",
      shared_ptr<TProcessor>(new SimplePreProcessor(simple_pre_handler))
    );
  }

  if(switch_has_component<bm::McSimplePreLAG>()) {
    shared_ptr<SimplePreLAGHandler> simple_pre_handler(new SimplePreLAGHandler(switch_));
    processor->registerProcessor(
      "simple_pre_lag",
      shared_ptr<TProcessor>(new SimplePreLAGProcessor(simple_pre_handler))
    );
  }

  shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
  shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
  shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());

  {
    std::unique_lock<std::mutex> lock(m_ready);
    ready = true;
    cv_ready.notify_one();
  }

  TThreadedServer server(processor, serverTransport, transportFactory, protocolFactory);
  server.serve();
  return 0;  
}

}

int start_server(bm::SwitchWContexts *sw, int port) {
  switch_ = sw;
  std::thread server_thread(serve, port);
  printf("Thrift server was started\n");
  std::unique_lock<std::mutex> lock(m_ready);
  while(!ready) cv_ready.wait(lock);
  server_thread.detach();
  return 0;
}

}
