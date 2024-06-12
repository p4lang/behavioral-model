# !/usr/bin/env python3
# Copyright 2024 Marvell Technology, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Rupesh Chiluka (rchiluka@marvell.com)
#
#

import runtime_CLI

from functools import wraps
import sys
import os

from pnic_runtime import PnaNic

class PnaNicAPI(runtime_CLI.RuntimeAPI):
    @staticmethod
    def get_thrift_services():
        return [("pna_nic", PnaNic.Client)]

    def __init__(self, pre_type, standard_client, mc_client, pnic_client):
        runtime_CLI.RuntimeAPI.__init__(self, pre_type,
                                        standard_client, mc_client)
        self.pnic_client = pnic_client

    @runtime_CLI.handle_bad_input
    def do_get_time_elapsed(self, line):
        "Get time elapsed (in microseconds) since the nic started: get_time_elapsed"
        print(self.pnic_client.get_time_elapsed_us())

    @runtime_CLI.handle_bad_input
    def do_get_time_since_epoch(self, line):
        "Get time elapsed (in microseconds) since the nic clock's epoch: get_time_since_epoch"
        print(self.pnic_client.get_time_since_epoch_us())

def load_json_pna(json):
    pass

def main():
    args = runtime_CLI.get_parser().parse_args()

    args.pre = runtime_CLI.PreType.none

    services = runtime_CLI.RuntimeAPI.get_thrift_services(args.pre)
    services.extend(PnaNicAPI.get_thrift_services())

    standard_client, mc_client, pnic_client = runtime_CLI.thrift_connect(
        args.thrift_ip, args.thrift_port, services
    )

    runtime_CLI.load_json_config(standard_client, args.json, load_json_pna)

    PnaNicAPI(args.pre, standard_client, mc_client, pnic_client).cmdloop()

if __name__ == '__main__':
    main()
