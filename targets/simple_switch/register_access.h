/* Copyright 2019-present Cisco Systems, Inc.
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
 * Andy Fingerhut (jafinger@cisco.com)
 *
 */

#define PACKET_LENGTH_REG_IDX             0

#define CLONE_MIRROR_SESSION_ID_REG_IDX   1
#define CLONE_MIRROR_SESSION_ID_MASK      0x000000000000ffff
#define CLONE_MIRROR_SESSION_ID_SHIFT     0
#define CLONE_FIELD_LIST_REG_IDX          1
#define CLONE_FIELD_LIST_MASK             0x00000000ffff0000
#define CLONE_FIELD_LIST_SHIFT            16
#define LF_FIELD_LIST_REG_IDX             1
#define LF_FIELD_LIST_MASK                0x0000ffff00000000
#define LF_FIELD_LIST_SHIFT               32
#define RESUBMIT_FLAG_REG_IDX             1
#define RESUBMIT_FLAG_MASK                0xffff000000000000
#define RESUBMIT_FLAG_SHIFT               48

#define RECIRCULATE_FLAG_REG_IDX          2
#define RECIRCULATE_FLAG_MASK             0x000000000000ffff
#define RECIRCULATE_FLAG_SHIFT            0

//#define CLONE_SPEC_REG_IDX       1


class RegisterAccess {
 public:
    static void clear_all(Packet &pkt) {
        // except do not clear packet length
        pkt.set_register(1, 0);
        pkt.set_register(2, 0);
    }
    static uint16_t get_clone_mirror_session_id(Packet &pkt) {
        uint64_t rv = pkt.get_register(CLONE_MIRROR_SESSION_ID_REG_IDX);
        return (uint16_t) ((rv & CLONE_MIRROR_SESSION_ID_MASK) >>
                           CLONE_MIRROR_SESSION_ID_SHIFT);
    }
    static void set_clone_mirror_session_id(Packet &pkt,
                                            uint16_t mirror_session_id) {
        uint64_t rv = pkt.get_register(CLONE_MIRROR_SESSION_ID_REG_IDX);
        rv = ((rv & ~CLONE_MIRROR_SESSION_ID_MASK) |
              (((uint64_t) mirror_session_id) <<
               CLONE_MIRROR_SESSION_ID_SHIFT));
        pkt.set_register(CLONE_MIRROR_SESSION_ID_REG_IDX, rv);
    }
    static uint16_t get_clone_field_list(Packet &pkt) {
        uint64_t rv = pkt.get_register(CLONE_FIELD_LIST_REG_IDX);
        return (uint16_t) ((rv & CLONE_FIELD_LIST_MASK) >>
                           CLONE_FIELD_LIST_SHIFT);
    }
    static void set_clone_field_list(Packet &pkt, uint16_t field_list_id) {
        uint64_t rv = pkt.get_register(CLONE_FIELD_LIST_REG_IDX);
        rv = ((rv & ~CLONE_FIELD_LIST_MASK) |
              (((uint64_t) field_list_id) << CLONE_FIELD_LIST_SHIFT));
        pkt.set_register(CLONE_FIELD_LIST_REG_IDX, rv);
    }
    static uint16_t get_lf_field_list(Packet &pkt) {
        uint64_t rv = pkt.get_register(LF_FIELD_LIST_REG_IDX);
        return (uint16_t) ((rv & LF_FIELD_LIST_MASK) >> LF_FIELD_LIST_SHIFT);
    }
    static void set_lf_field_list(Packet &pkt, uint16_t field_list_id) {
        uint64_t rv = pkt.get_register(LF_FIELD_LIST_REG_IDX);
        rv = ((rv & ~LF_FIELD_LIST_MASK) |
              (((uint64_t) field_list_id) << LF_FIELD_LIST_SHIFT));
        pkt.set_register(LF_FIELD_LIST_REG_IDX, rv);
    }
    static uint16_t get_resubmit_flag(Packet &pkt) {
        uint64_t rv = pkt.get_register(RESUBMIT_FLAG_REG_IDX);
        return (uint16_t) ((rv & RESUBMIT_FLAG_MASK) >> RESUBMIT_FLAG_SHIFT);
    }
    static void set_resubmit_flag(Packet &pkt, uint16_t field_list_id) {
        uint64_t rv = pkt.get_register(RESUBMIT_FLAG_REG_IDX);
        rv = ((rv & ~RESUBMIT_FLAG_MASK) |
              (((uint64_t) field_list_id) << RESUBMIT_FLAG_SHIFT));
        pkt.set_register(RESUBMIT_FLAG_REG_IDX, rv);
    }
    static uint16_t get_recirculate_flag(Packet &pkt) {
        uint64_t rv = pkt.get_register(RECIRCULATE_FLAG_REG_IDX);
        return (uint16_t) ((rv & RECIRCULATE_FLAG_MASK) >>
                           RECIRCULATE_FLAG_SHIFT);
    }
    static void set_recirculate_flag(Packet &pkt, uint16_t field_list_id) {
        uint64_t rv = pkt.get_register(RECIRCULATE_FLAG_REG_IDX);
        rv = ((rv & ~RECIRCULATE_FLAG_MASK) |
              (((uint64_t) field_list_id) << RECIRCULATE_FLAG_SHIFT));
        pkt.set_register(RECIRCULATE_FLAG_REG_IDX, rv);
    }
};
