/* Copyright 2022 University of Oxford
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

#ifndef BM_GRPC__SSL_OPTIONS_H_
#define BM_GRPC__SSL_OPTIONS_H_

#include <string>

struct SSLOptions {
  std::string pem_root_certs;
  std::string pem_private_key;
  std::string pem_cert_chain;
  bool with_client_auth;
};

#endif // BM_GRPC__SSL_OPTIONS_H_
