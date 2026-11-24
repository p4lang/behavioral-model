// Copyright 2024 Marvell Technology, Inc.
// SPDX-FileCopyrightText: 2024 Marvell Technology, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Loads the p4c-bm2-pna outputted JSON file into the pna_nic object
 *  and checks whether the pna_nic target can parse the pna metadata.
 */

#include <bm/bm_apps/packet_pipe.h>
#include <gtest/gtest.h>
#include <utils.h>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

#include "pna_nic.h"

namespace fs = std::filesystem;

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
            ASSERT_EQ(0, test_pna_nic->init_objects(json_path.string()));

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

        // read() blocks with no timeout, so poll for the packet first
        bool wait_for_packet(std::chrono::milliseconds timeout) {
            auto deadline = std::chrono::steady_clock::now() + timeout;
            while (receiver.check_status() !=
                   PacketInReceiver::Status::CAN_READ) {
                if (std::chrono::steady_clock::now() > deadline) return false;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            return true;
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

    // Ethernet header (dst, src, etherType 0x0800) and two payload bytes
    const char pkt[] = {'\x00', '\x11', '\x22', '\x33', '\x44', '\x55',
                        '\x00', '\x66', '\x77', '\x88', '\x99', '\xaa',
                        '\x08', '\x00', '\xab', '\xcd'};
    packet_inject.send(port, pkt, sizeof(pkt));
    ASSERT_TRUE(wait_for_packet(std::chrono::seconds(10)));
    char recv_buffer[kMaxBufSize];
    int recv_port = -1;
    size_t recv_size = receiver.read(recv_buffer, sizeof(recv_buffer),
                                     &recv_port);
    // no send_to_port in this program, so egress_port stays at its default 0
    EXPECT_EQ(0, recv_port);
    EXPECT_EQ(std::string(pkt, sizeof(pkt)),
              std::string(recv_buffer, recv_size));
}
