/* * Copyright 2025.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
#include <sys/time.h>
#include <vector>
#include <string>

struct pcap;
namespace pcap_mock {
  struct Packet { 
    timeval time_stamp; 
    std::vector<u_char> data; 
    pcap* pcap_object; 
  };
  std::string get_name(const pcap*);
  bool is_promisc(const pcap*);
  bool is_immediate_mode(const pcap*);
  void simulate_packets_received(pcap*, 
                                 std::vector<std::vector<u_char>>packets_data);

  pcap* get_pcap_object(const std::string& name);
  Packet get_sent_packet(int timeout_ms = -1);
  void clear(pcap*);
}
