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

//! @file extern.h

#ifndef BM_BM_SIM_EXTERN_H_
#define BM_BM_SIM_EXTERN_H_

#include <unordered_map>
#include <string>
#include <memory>
#include <type_traits>
#include <mutex>

#include "actions.h"
#include "named_p4object.h"

namespace bm {

class P4Objects;
class ExternType;

class ExternFactoryMap {
 public:
  using ExternFactoryFn = std::function<std::unique_ptr<ExternType>()>;

  static ExternFactoryMap *get_instance();

  int register_extern_type(const char *extern_type_name, ExternFactoryFn fn);

  std::unique_ptr<ExternType> get_extern_instance(
      const std::string &extern_type_name) const;

 private:
  std::unordered_map<std::string, ExternFactoryFn> factory_map{};
};

#define _BM_EXTERN_TO_STRING(name) #name

#define BM_REGISTER_EXTERN_W_NAME(extern_name, extern__)                \
  static_assert(std::is_default_constructible<extern__>::value,         \
                "User-defined extern type " #extern__                   \
                " needs to be default-constructible");                  \
  int _extern_##extern_name##_create_ =                                 \
      ::bm::ExternFactoryMap::get_instance()->register_extern_type(     \
           #extern_name,                                                \
           [](){ return std::unique_ptr<ExternType>(new extern__()); });

#define BM_REGISTER_EXTERN(extern_name) \
  BM_REGISTER_EXTERN_W_NAME(extern_name, extern_name)

#define BM_REGISTER_EXTERN_W_NAME_METHOD(extern_name, extern__,           \
                                         extern_method_name, ...)         \
  template <typename... Args>                                             \
  struct _##extern_name##_##extern_method_name##_0                        \
      : public ::bm::ActionPrimitive<::bm::ExternType *, Args...> {       \
    void operator ()(::bm::ExternType *instance, Args... args) override { \
      auto lock = instance->_unique_lock();                               \
      instance->_set_packet_ptr(&this->get_packet());                     \
      dynamic_cast<extern__ *>(instance)->extern_method_name(args...);    \
    }                                                                     \
  };                                                                      \
  struct _##extern_name##_##extern_method_name                            \
      : public _##extern_name##_##extern_method_name##_0<__VA_ARGS__> {}; \
  REGISTER_PRIMITIVE_W_NAME(                                              \
    _BM_EXTERN_TO_STRING(_##extern_name##_##extern_method_name),          \
    _##extern_name##_##extern_method_name)

#define BM_REGISTER_EXTERN_METHOD(extern_name, extern_method_name, ...)   \
  template <typename... Args>                                             \
  struct _##extern_name##_##extern_method_name##_0                        \
      : public ::bm::ActionPrimitive<::bm::ExternType *, Args...> {       \
    void operator ()(::bm::ExternType *instance, Args... args) override { \
      auto lock = instance->_unique_lock();                               \
      instance->_set_packet_ptr(&this->get_packet());                     \
      dynamic_cast<extern_name *>(instance)->extern_method_name(args...); \
    }                                                                     \
  };                                                                      \
  struct _##extern_name##_##extern_method_name                            \
      : public _##extern_name##_##extern_method_name##_0<__VA_ARGS__> {}; \
  REGISTER_PRIMITIVE(_##extern_name##_##extern_method_name)

#define BM_EXTERN_ATTRIBUTES void _register_attributes() override

#define BM_EXTERN_ATTRIBUTE_ADD(attr_name) \
  _add_attribute(#attr_name, static_cast<void *>(&attr_name));


// TODO(Antonin): have it inherit from NamedP4Object? It is a bit tricky because
// extern types need to be default constructible
class ExternType {
 public:
  virtual ~ExternType() { }

  // needs to be called before init() when setting up the extern instance, in
  // case init's implementation relies on p4objects (e.g. to resolve names to
  // objects, such as register arrays)
  void _set_p4objects(P4Objects *p4objects);

  template <typename T>
  void _set_attribute(const std::string &attr_name, const T &v) {
    T *attr = static_cast<T *>(attributes.at(attr_name));
    *attr = v;
  }

  bool _has_attribute(const std::string &attr_name) const {
    return attributes.find(attr_name) != attributes.end();
  }

  void _set_packet_ptr(Packet *pkt_ptr) { pkt = pkt_ptr; }

  // called in P4Objects after constructing the instance
  void _set_name_and_id(const std::string &name, p4object_id_t id);

  const std::string &get_name() const { return name; }
  p4object_id_t get_id() const { return id; }

  using UniqueLock = std::unique_lock<std::mutex>;
  UniqueLock _unique_lock() { return UniqueLock(mutex); }

  virtual void _register_attributes() = 0;

  virtual void init() { }

 protected:
  void _add_attribute(const std::string &name, void *ptr) {
    attributes[name] = ptr;
  }

  Packet &get_packet() const { return *pkt; }

  P4Objects &get_p4objects() const { return *p4objects; }

 private:
  // will use static_cast to cast from T * to void * and vice-versa
  std::unordered_map<std::string, void *> attributes;
  mutable std::mutex mutex{};
  Packet *pkt{nullptr};
  // set by _set_name_and_id
  std::string name{};
  p4object_id_t id{};
  // while we improve the extern support in bmv2, it is useful to expose this to
  // extern implementations, to give them maximum flexibility
  // non-owning pointer, as ExternType instances themselves are owned by the
  // P4Object instance
  P4Objects *p4objects{nullptr};
};

}  // namespace bm

#endif  // BM_BM_SIM_EXTERN_H_
