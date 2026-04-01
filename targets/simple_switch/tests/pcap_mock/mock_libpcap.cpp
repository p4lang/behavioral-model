/* * Copyright 2025.
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
 * Francois-R.Boyer@PolyMtl.ca
 *
 */

/* A libpcap mock for testing the BMI code in P4 behavioral-model.
It is not meant to be a full mock of libpcap, it only implements the functions
required for this special purpose.
Can be compiled as a static library libpcap.a and be linked instead of
standard libpcap.a.
By Francois-R.Boyer@PolyMtl.ca
2024-07
*/

#include "pcap_mock.hpp"
#include <pcap/pcap.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <vector>
#include <map>
#include <list>
#include <mutex>
#include <thread>
#include <sstream>
#include <utility>
#include <cassert>
#include <functional>

#define SHOULD_TRACE 1
#if SHOULD_TRACE
#define IF_TRACE(X) X
#else
#define IF_TRACE(X)
#endif

namespace {
std::mutex pcap_objects_by_name_mutex;
std::map<std::string, pcap*> pcap_objects_by_name;
}

struct pcap {
#define PCAP_ERROR_IF_ACTIVATED if (is_activated_) return PCAP_ERROR_ACTIVATED;
  using Packet = pcap_mock::Packet;
  struct MutexedPacketList { 
    std::mutex list_mutex; 
    std::list<Packet> packets; 
  };
  using FileDescriptor = int;
  static constexpr FileDescriptor invalid_file_descriptor = -1;
  static constexpr int no_error = 0;
  pcap(const char* source, char* errbuf) :
    name_(source),
    file_descriptor_(eventfd(0, 0))  
    //NOTE: Could use EFD_SEMAPHORE and decrement count each 
    //time we give a packet.
  {
    IF_TRACE(printf("pcap_open(%s) %p\n", source, this););
    add_pcap(this, source);
  }

  ~pcap() {
    IF_TRACE(printf("pcap_close(%p %s)\n", this, name_.c_str()););
    clear();
    close(file_descriptor_);
    remove_pcap(this);
  }

  int set_promisc(int promisc) { 
    PCAP_ERROR_IF_ACTIVATED; 
    is_promisc_ = promisc != 0; 
    return no_error; 
  }
  int set_timeout(int to_ms) { 
    PCAP_ERROR_IF_ACTIVATED timeout_ms_ = to_ms; 
    return no_error; 
  }
  int set_immediate_mode(int immediate_mode) { 
    PCAP_ERROR_IF_ACTIVATED; 
    is_immediate_mode_ = immediate_mode != 0; 
    return no_error; 
  }

  int activate() { 
    PCAP_ERROR_IF_ACTIVATED; 
    is_activated_ = true; 
    return no_error; 
  }

  int	sendpacket(const u_char* buf, int size) {
    IF_TRACE(printf("%p %s->sendpacket(,%d)\n", this, name_.c_str(), size););
    std::lock_guard lock(packets_sent_.list_mutex);
    timeval t; gettimeofday(&t, nullptr);
    packets_sent_.packets.push_back({t, std::vector<u_char>(buf, buf+size), 
                                    this});
    return no_error;
  }
  FileDescriptor get_selectable_fd() { return file_descriptor_; }

  int next_ex(struct pcap_pkthdr** pkt_header, const u_char** pkt_data) {
    std::lock_guard lock(packets_receive_buffer_.list_mutex);
    if (packets_receive_buffer_.packets.empty())
      return 0;
    
    current_receive_packet_ = std::move(
      packets_receive_buffer_.packets.front());
    packets_receive_buffer_.packets.pop_front();
    if (packets_receive_buffer_.packets.empty())
      read_eventfd();

    current_receive_packet_header_.ts = current_receive_packet_.time_stamp;
    current_receive_packet_header_.caplen = current_receive_packet_header_.len = 
      current_receive_packet_.data.size();
    *pkt_header = &current_receive_packet_header_;
    *pkt_data = current_receive_packet_.data.data();
    return 1;
  }

  std::string get_name() const;

  bool is_promisc() const;
  bool is_immediate_mode() const;

  void simulate_packets_received(std::vector<std::vector<u_char>> packets_data);
  static pcap* get_pcap_object(const std::string& name);
    static Packet get_sent_packet(int timeout_ms = -1);
  void clear();

#undef PCAP_ERROR_IF_ACTIVATED
private:
  uint64_t read_eventfd() { 
    uint64_t val; 
    assert(read(file_descriptor_, &val, sizeof(val)) == sizeof(val)); 
    return val; 
  }
  void write_eventfd(uint64_t to_add = 1) { 
    assert(write(file_descriptor_, &to_add, sizeof(to_add)) == sizeof(to_add));
  }

  static void add_pcap(pcap* object, const std::string& name) {
    std::lock_guard lock(pcap_objects_by_name_mutex);
    assert(pcap_objects_by_name.count(name) == 0);
    pcap_objects_by_name[name] = object;
  }
  static void remove_pcap(pcap* object) {
    std::lock_guard lock(pcap_objects_by_name_mutex);
    pcap_objects_by_name.erase(object->name_);
  }

  std::string name_;

  bool is_activated_ = false;
  bool is_promisc_ = false;
  int timeout_ms_ = -1;
  bool is_immediate_mode_ = false;

  FileDescriptor file_descriptor_ = invalid_file_descriptor;

  static MutexedPacketList packets_sent_;
  MutexedPacketList packets_receive_buffer_;
  Packet current_receive_packet_; 
  pcap_pkthdr current_receive_packet_header_;
};

pcap::MutexedPacketList pcap::packets_sent_;

std::string pcap::get_name() const  { return name_; }

bool pcap::is_promisc() const { return is_promisc_; }
bool pcap::is_immediate_mode() const { 
  return timeout_ms_ == 0 && is_immediate_mode_; 
}

void pcap::simulate_packets_received(
  std::vector<std::vector<u_char>> packets_data) {
  IF_TRACE(printf("%p %s->simulate_packets_received([%d])\n", 
                  this, name_.c_str(), packets_data.size()););
  std::lock_guard lock(packets_receive_buffer_.list_mutex);
  timeval t; gettimeofday(&t, nullptr);
  for (auto&& p : packets_data)
    packets_receive_buffer_.packets.push_back({t, p});
  write_eventfd(packets_data.size());
}
pcap* pcap::get_pcap_object(const std::string& name) {
  std::lock_guard lock(pcap_objects_by_name_mutex);
  auto it = pcap_objects_by_name.find(name);
  return (it != pcap_objects_by_name.end()) ? it->second : nullptr;
}
pcap::Packet pcap::get_sent_packet(int timeout_ms) {
  //TODO: timeout_ms
  //TODO: wait intelligently
  while (true) {
    if (std::lock_guard lock(packets_sent_.list_mutex); 
    !packets_sent_.packets.empty()) {
      Packet result = packets_sent_.packets.front();
      packets_sent_.packets.pop_front();
      IF_TRACE(printf("get_sent_packet got %s %d \n", 
        result.pcap_object->get_name().c_str(), result.data.size()););
      return result;
    }
    using namespace std::literals::chrono_literals;
    std::this_thread::sleep_for(1ms);
  }
}
void pcap::clear() {
  IF_TRACE(printf("%p %s->clear()\n", this, name_.c_str()););
  {
  std::lock_guard lock(packets_receive_buffer_.list_mutex);
  packets_receive_buffer_.packets.clear();
  }
  {
  std::lock_guard lock(packets_sent_.list_mutex);
  packets_sent_.packets.clear();
  }
}

namespace pcap_mock {
  std::string get_name(const pcap* p) { return p->get_name(); }
  bool is_promisc(const pcap* p) { return p->is_promisc(); }
  bool is_immediate_mode(const pcap* p) { return p->is_immediate_mode(); }
  void simulate_packets_received(pcap* p, 
    std::vector<std::vector<u_char>> packets_data) { 
      p->simulate_packets_received(move(packets_data)); 
    }

  pcap* get_pcap_object(const std::string& name) { 
    return pcap::get_pcap_object(name); 
  }
    Packet get_sent_packet(int timeout_ms) { 
      return pcap::get_sent_packet(timeout_ms); 
    }
  void clear(pcap* p) { p->clear(); }
}

extern "C" {
pcap_t* pcap_create(const char* source, char* errbuf) { 
  return new pcap(source, errbuf); 
}

int pcap_set_promisc(pcap_t* p, int promisc) { 
  return p->set_promisc(promisc); 
}

int pcap_set_timeout(pcap_t* p, int to_ms) { 
  return p->set_timeout(to_ms); 
}

int pcap_set_immediate_mode(pcap_t* p, int immediate_mode) { 
  return p->set_immediate_mode(immediate_mode); 
}

int pcap_activate(pcap_t* p) { return p->activate(); }

void pcap_close(pcap_t* p) { delete p; }

int	pcap_sendpacket(pcap_t* p, const u_char* buf, int size) { 
  return p->sendpacket(buf, size); 
}
int pcap_get_selectable_fd(pcap_t* p) { return p->get_selectable_fd(); }
int pcap_next_ex(pcap_t* p, struct pcap_pkthdr** pkt_header, 
                const u_char** pkt_data) { 
    return p->next_ex(pkt_header, pkt_data); 
  }

// Not actually used by behavioral-model.
const char* pcap_statustostr(int error) {
  std::ostringstream os; os << "Unknown error: " << error;
  static std::string errorString; errorString = os.str();
  return errorString.c_str();
}

// "Empty" stubs, so P4 behavioral-model compiles, but should not be used 
// for testing.
struct pcap_dumper {};
pcap_dumper_t* pcap_dump_open(pcap_t* p, const char *fname) { 
  static pcap_dumper nothing; return &nothing; 
}
void pcap_dump_close(pcap_dumper_t* p) {}
void pcap_dump(u_char* user, const struct pcap_pkthdr* h, const u_char* sp) {}
int pcap_dump_flush(pcap_dumper_t* p) { return 0; }

pcap_t* pcap_open_dead(int linktype, int snaplen) { return nullptr; }
pcap_t* pcap_open_offline(const char* fname, char* errbuf) { return nullptr; }
}
// vi: ts=4
