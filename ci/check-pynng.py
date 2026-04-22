# SPDX-FileCopyrightText: 2026 Fabian Ruffy
#
# SPDX-License-Identifier: Apache-2.0

import sys
import time

import pynng

address = "inproc://foo"

pub = pynng.Pub0(listen=address)
sub = pynng.Sub0(dial=address, recv_timeout=500)
sub.subscribe("")

ok = False
for _ in range(5):
    pub.send(b"hello, world")
    try:
        recv = sub.recv()
    except pynng.Timeout:
        time.sleep(0.05)
        continue
    if recv == b"hello, world":
        ok = True
        break

pub.close()
sub.close()

if not ok:
    sys.exit(1)
