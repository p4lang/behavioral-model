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

#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <memory> 
#include <cstring>
#include <string.h>
#include <stdexcept>
#include <pcap/pcap.h>
#include "bmi_interface.h"

enum class DumperKind{
  Input,
  Output
};

 class bmi_interface_t{
    private:
    pcap_t *pcap;
    int fd;
    pcap_dumper_t *pcap_input_dumper;
    pcap_dumper_t *pcap_output_dumper;

    public:
  bmi_interface_t(const std::string& device):pcap(nullptr),fd(-1),pcap_input_dumper(nullptr),pcap_output_dumper(nullptr){
char errbuff[PCAP_ERRBUF_SIZE];
pcap=pcap_create(device.c_str(),errbuff);


if(pcap_set_promisc( pcap,1)!=0){
  pcap_close(pcap);
  throw  std::runtime_error("Failed to set promiscuos mode");
}

#ifdef WITH_PCAP_FIX

if(pcap_set_timeout(pcap,1)!=0){
  pcap_close(pcap);
  throw std::runtime_error("Failed to set timeout");
}

if(pcap_set_immediate_mode(pcap,1)!=0){
  pcap_close(pcap);
  throw std::runtime_error("Failed to set immediate mode");
}

#endif

if(pcap_activate(pcap)!=0){
  pcap_close(pcap);
  throw std::runtime_error("Failed to activate pcap");
}

fd=pcap_get_selectable_fd(pcap);
if(fd<0){
  pcap_close(pcap);
  throw std::runtime_error("Failed to set fd");
}


}
 ~bmi_interface_t(){
 if(pcap){
  pcap_close(pcap);
  pcap=nullptr;
 }
  if(pcap_input_dumper){
    pcap_dump_close(pcap_input_dumper);
    pcap_input_dumper=nullptr;
  }
  if(pcap_output_dumper){
    pcap_dump_close(pcap_output_dumper);
    pcap_output_dumper=nullptr;
  }
  

 } 

 int get_fd(){
  return fd;
 }

 int add_dumper(const std::string& filename, DumperKind dumperKind){
  pcap_dumper_t* dumper=pcap_dump_open(pcap,filename.c_str());
  if(dumper==NULL)throw std::runtime_error("Failed to open pcap dumper file"+filename);

  switch(dumperKind){
    case DumperKind::Input:
      pcap_input_dumper=dumper;
      break;
    
    case DumperKind::Output:
      pcap_output_dumper=dumper;
      break;
    
    default:
      throw std::invalid_argument("Invalid Dumper kind");

  }
  return 0;
 }


 int send(const char* data,int len){
  if(bmi_output_dumper){
    struct pcap_pkthdr pkt_header;
    std::memset(&pkt_header,0,sizeof(pkt_header));

    gettimeofday(&pkt_header.ts,NULL);
    pkt_header.caplen=len;
    pkt_header.len=len;

    pcap_dump(reinterpret_cast<u_char*>(pcap_output_dumper),&pkt_header,reinterpret_cast<const u_char*>(data));
    pcap_dump_flush(pcap_output_dumper);
  }
  return pcap_sendpacket(pcap,reinterpret_cast<const u_char *>(data),len);
 }


int recv(const char **data ){
  struct pcap_pkthdr *pkt_header=nullptr;
  const unsigned char* pkt_data=nullptr;

  if(pcap_next_ex(pcap,&pkt_header,&pkt_data)!=1){
    throw std::runtime_error("Failed to recieve packet");
  }

  if(pkt_header->caplen !=pkt_header->len){
    throw std::runtime_error("Captured pkt length and original length are not same");
  }

  if(pcap_input_dumper){
    pcap_dump(reinterpret_cast<u_char*>(pcap_input_dumper),pkt_header,pkt_data);
    pcap_dump_flush(pcap_input_dumper);
  }

  *data= reinterpret_cast<const char*>(pkt_data);
  
  return pkt_header->len;
}


 int recv_with_copy(char* data, int max_len){
  int rv;
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt_data;

  if(pcap_next_ex(pcap, &pkt_header, &pkt_data)!=1){
    throw std::runtime_error("Failed to recieve packet");
  }

  if(pkt_header->caplen!= pkt_header->len){
    throw std::runtime_error("Truncated packet");
  }

  if(pcap_input_dumper){
    pcap_dump(reinterpret_cast<u_char*>(pcap_input_dumper), pkt_header, pkt_data);
    pcap_dump_flush(pcap_input_dumper);
  }

  rv=std::min(max_len,static_cast<int>(pkt_header->len));
  std::memcpy(data,pkt_data,rv);
  return rv;
 }
 };

 