/*
 * Copyright 2024 Marvell Technology, Inc.
 * SPDX-FileCopyrightText: 2024 Marvell Technology, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

namespace cpp pnic_runtime
namespace py pnic_runtime

service PnaNic {

  // these methods are here as an experiment, prefer get_time_elapsed_us() when
  // possible
  i64 get_time_elapsed_us();
  i64 get_time_since_epoch_us();

}
