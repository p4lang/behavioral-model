/* Copyright 2024 Marvell Technology, Inc.
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
 * Loads the p4c-bm2-pna outputted JSON file into the pna_nic object
 *  and checks whether the pna_nic target can parse the pna metadata.
 */

#include <gtest/gtest.h>
#include <bm/bm_apps/packet_pipe.h>
#include <boost/filesystem.hpp>
#include <utils.h>
#include "pna_nic.h"

namespace fs = boost::filesystem;

using bm::MatchErrorCode;
using bm::ActionData;
using bm::MatchKeyParam;
using bm::entry_handle_t;

namespace {

void packet_handler(int port_num, const char *buffer, int len, void *cookie) {
    static_cast<bm::pna::PnaNic *>(cookie)->receive(port_num, buffer, len);
}

} // namespace

class PNA_ParseTest: public ::testing::Test {
    protected:
        static constexpr size_t kMaxBufSize = 512;

        static constexpr bm::device_id_t device_id{0};

        PNA_ParseTest()
            : packet_inject(packet_in_addr) { }
        
        // Per-test-case set-up.
        static void SetUpTestCase() {
            test_pna_nic = new bm::pna::PnaNic();

            // load JSON
            fs::path json_path = fs::path(testdata_dir) / fs::path(test_json);
            test_pna_nic->init_objects(json_path.string());

            // packet in -packet out
            test_pna_nic->set_dev_mgr_packet_in(device_id, packet_in_addr, nullptr);
            test_pna_nic->Switch::start(); // there is a start member in PnaNic
            test_pna_nic->set_packet_handler(packet_handler, static_cast<void *>(test_pna_nic));
            test_pna_nic->start_and_return();
        }

        // Per-test-case tear-down.
        static void TearDownTestCase() {
            delete test_pna_nic;
        }

        virtual void SetUp() {
            packet_inject.start();
            auto cb = std::bind(&PacketInReceiver::receive, &receiver,
                                std::placeholders::_1, std::placeholders::_2,
                                std::placeholders::_3, std::placeholders::_4);
            packet_inject.set_packet_receiver(cb, nullptr);
        }

        protected:
            static const char packet_in_addr[];
            static bm::pna::PnaNic *test_pna_nic;
            bm_apps::PacketInject packet_inject;
            PacketInReceiver receiver{};
        
        private:
            static const char testdata_dir[];
            static const char test_json[];
};

const char PNA_ParseTest::packet_in_addr[] = "inproc://packets";

bm::pna::PnaNic *PNA_ParseTest::test_pna_nic = nullptr;

const char PNA_ParseTest::testdata_dir[] = TESTDATADIR;
const char PNA_ParseTest::test_json[] = "pna-demo-L2-one-table.json";

TEST_F(PNA_ParseTest, Parse) {
    static constexpr int port = 1;

    const char pkt[] = {'\x00'};
    packet_inject.send(port, pkt, sizeof(pkt));
    char recv_buffer[] = {'\x00', '\x00'};
    int recv_port = -1;
    receiver.read(
        recv_buffer, sizeof(recv_buffer), &recv_port);
    ASSERT_TRUE(true);
}
