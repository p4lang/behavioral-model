# The BMv2 Simple Switch target

The bmv2 framework lets developers implement their own P4-programmable
architecture as a software switch. The simple_switch architecture is the
de-facto architecture for most users, as it is roughly equivalent to the
"abstract switch model" described in the [P4_14 spec](https://p4.org/specs).

The P4_16 language has been designed such that there can be multiple
architectures, e.g. one or more architectures for a switch device, one
or more architectures for a NIC device, etc.  The v1model architecture
is included with the p4c compiler, and was designed to be identical to
the P4_14 switch architecture, enabling straightforward
auto-translation from P4_14 programs to P4_16 programs that use the
v1model architecture.  There are a few tiny differences between P4_14
and v1model called out below, primarily in the names of a few metadata
fields.

The P4_16 language also now has a Portable Switch Architecture (PSA)
defined in [its own specification](https://p4.org/specs).  As of
September 2018, a partial implementation of the PSA architecture has
been done, but it is not yet complete.  It will be implemented in a
separate executable program named `psa_switch`, separate from the
`simple_switch` program described here.

This document aims at providing P4 programmers with important information
regarding the simple_switch architecture.

## Standard metadata

For a P4_16 program using the v1model architecture and including the
file `v1model.p4`, all of the fields below are part of the struct with
type `standard_metadata_t`.

For a P4_14 program, all of the fields below are part of the header
named `standard_metadata`, which is predefined for you.

The following abbreviations are used to mark field names below, to
indicate where they appear:

- sm14 - the field is defined in v1.0.4 of the P4_14 language
  specification, Section 6 titled "Standard Intrinsic Metadata".
- v1m - the field is defined in the include file `p4include/v1model.p4`
  of the [p4c](https://github.com/p4lang/p4c) repository, intended
  to be included in P4_16 programs compiled for the v1model
  architecture.

Here are the fields:

- `ingress_port` (sm14, v1m) - For new packets, the number of the
  ingress port on which the packet arrived to the device.  Read only.
- `packet_length` (sm14, v1m) - For new packets from a port, or
  recirculated packets, the length of the packet in bytes.  For cloned
  or resubmitted packets, you may need to include this in a list of
  fields to preserve, otherwise its value will become 0.
- `egress_spec` (sm14, v1m) - Can be assigned a value in ingress code
  to control which output port a packet will go to.  The P4_14
  primitive `drop`, and the v1model primitive action `mark_to_drop`,
  have the side effect of assigning an implementation specific value
  to this field (511 decimal for simple_switch), such that if
  `egress_spec` has that value at the end of ingress processing, the
  packet will be dropped and not stored in the packet buffer, nor sent
  to egress processing.  See the "after-ingress pseudocode" for
  relative priority of this vs. other possible packet operations at
  end of ingress.
- `egress_port` (sm14, v1m) - Only intended to be accessed during
  egress processing, read only.  The output port this packet is
  destined to.
- `egress_instance` (sm14) - Renamed `egress_rid` in simple_switch.
  See `egress_rid` below.
- `instance_type` (sm14, v1m) - Contains a value that can be read by
  your P4 code.  In ingress code, the value can be used to distinguish
  whether the packet is newly arrived from a port (`NORMAL`), it was
  the result of a resubmit primitive action (`RESUBMIT`), or it was the
  result of a recirculate primitive action (`RECIRC`).  In egress processing,
  can be used to determine whether the packet was produced as the
  result of an ingress-to-egress clone primitive action (`INGRESS_CLONE`),
  egress-to-egress clone primitive action (`EGRESS_CLONE`), multicast
  replication specified during ingress processing (`REPLICATION`), or
  none of those, so a normal unicast packet from ingress (`NORMAL`).
  Until such time as similar constants are pre-defined for you, you
  may copy [this
  list](https://github.com/p4lang/p4c/blob/master/testdata/p4_14_samples/switch_20160512/includes/intrinsic.p4#L62-L68)
  of constants into your code.
- `parser_status` (sm14) or `parser_error` (v1m) - `parser_status` is
  the name in the P4_14 language specification.  It has been renamed
  to `parser_error` in v1model.  The value 0 (sm14) or error.NoError
  (P4_16 + v1model) means no error.  Otherwise, the value indicates
  what error occurred during parsing.
- `parser_error_location` (sm14) - Not present in v1model.p4, and not
  implemented in simple_switch.
- `clone_spec` (v1m): should not be accessed directly. It is set by
  the `clone` and `clone3` action primitives and is required for the
  packet clone (aka mirror) feature. The "ingress to egress" clone
  primitive action must be called from the ingress pipeline, and the
  "egress to egress" clone primitive action must be called from the
  egress pipeline.

## Intrinsic metadata

Each architecture usually defines its own intrinsic metadata fields, which are
used in addition to the standard metadata fields to offer more advanced
features. In the case of simple_switch, we have two separate intrinsic metadata
headers. These headers are not strictly required by the architecture as it is
possible to write a P4 program and run it through simple_switch without them
being defined. However, their presence is required to enable some features of
simple_switch. For most of these fields, there is no strict requirement as to
the bitwidth, but we recommend that you follow our suggestions below. Some of
these intrinsic metadata fields can be accessed (read and / or write) directly,
others should only be accessed through primitive actions.

### `intrinsic_metadata` header

For a P4_16 program using the v1model architecture and including the
file `v1model.p4`, all of the fields below are part of the struct with
type `standard_metadata_t`.  There is no need to define your own
struct type for these fields.

For a P4_14 program, we recommend that you define and instantiate this
metadata header for every P4 program that you write for the
simple_switch architecture, with the following code:
```
header_type intrinsic_metadata_t {
    fields {
        ingress_global_timestamp : 48;
        egress_global_timestamp : 48;
        lf_field_list : 8;
        mcast_grp : 16;
        egress_rid : 16;
        resubmit_flag : 8;
        recirculate_flag : 8;
    }
}
metadata intrinsic_metadata_t intrinsic_metadata;
```
- `ingress_global_timestamp`: a timestamp, in microseconds, set when the packet
shows up on ingress. The clock is set to 0 every time the switch starts. This
field can be read directly from either pipeline (ingress and egress) but should
not be written to.
- `egress_global_timestamp`: a timestamp, in microseconds, set when the packet
starts egress processing. The clock is the same as for
`ingress_global_timestamp`. This field should only be read from the egress
pipeline, but should not be written to.
- `lf_field_list`: used to store the learn id when calling `generate_digest`; do
not access directly.
- `mcast_grp`: needed for the multicast feature. This field needs to be written
in the ingress pipeline when you wish the packet to be multicast. A value of 0
means no multicast. This value must be one of a valid multicast group configured
through bmv2 runtime interfaces. See the "after-ingress pseudocode" for
relative priority of this vs. other possible packet operations at
end of ingress.
- `egress_rid`: needed for the multicast feature. This field is only valid in
the egress pipeline and can only be read from. It is used to uniquely identify
multicast copies of the same ingress packet.
- `resubmit_flag`: should not be accessed directly. It is set by the
`resubmit` action primitive and is required for the resubmit
feature. As a reminder, `resubmit` needs to be called in the ingress
pipeline. See the "after-ingress pseudocode" for relative priority of
this vs. other possible packet operations at end of ingress.
- `recirculate_flag`: should not be accessed directly. It is set by the
`recirculate` action primitive and is required for the recirculate feature. As a
reminder, `recirculate` needs to be called from the egress pipeline.
See the "after-egress pseudocode" for the relative priority of this
vs. other possible packet operations at the end of egress processing.

Several of these fields should be considered internal implementation
details for how simple_switch implements some packet processing
features.  They are: `lf_field_list`, `resubmit_flag`,
`recirculate_flag`, and `clone_spec`.  They have the following
properties in common:

- They are initialized to 0, and are assigned a compiler-chosen non-0
  value when the corresponding primitive action is called.
- Your P4 program should never assign them a value directly.
- Reading the values may be helpful for debugging.
- Reading them may also be useful for knowing whether the
  corresponding primitive action was called earlier in the
  execution of the P4 program, but if you want to know whether such a
  use is portable to P4 implementations other than simple_switch, you
  will have to check the documentation for that other implementation.

### `queueing_metadata` header

For a P4_16 program using the v1model architecture and including the
file `v1model.p4`, all of the fields below are part of the struct with
type `standard_metadata_t`.  There is no need to define your own
struct type for these fields.

For a P4_14 program,
you only need to define this P4 header if you want to access queueing
information - as a reminder, the packet is queued between the ingress and
egress pipelines. Note that this header is "all or nothing". Either you do not
define it or you define it with all its fields (there are 4 of them). We
recommend that you use the following P4_14 code:
```
header_type queueing_metadata_t {
    fields {
        enq_timestamp : 48;
        enq_qdepth : 16;
        deq_timedelta : 32;
        deq_qdepth : 16;
        qid : 8;
    }
}
metadata queueing_metadata_t queueing_metadata;
```
Of course, all of these fields can only be accessed from the egress pipeline and
they are read-only.
- `enq_timestamp`: a timestamp, in microseconds, set when the packet is first
enqueued.
- `enq_qdepth`: the depth of the queue when the packet was first enqueued.
- `deq_timedelta`: the time, in microseconds, that the packet spent in the
queue.
- `deq_qdepth`: the depth of queue when the packet was dequeued.
- `qid`: when there are multiple queues servicing each egress port (e.g. when
priority queueing is enabled), each queue is assigned a fixed unique id, which
is written to this field. Otherwise, this field is set to 0.
TBD: `qid` is not currently part of type `standard_metadata_t` in v1model.
Perhaps it should be added?

## Supported primitive actions

We mostly support the standard P4_14 primitive actions. One difference is that
optional parameters are not supported in bmv2, so all parameters are always
required (see `resubmit` for example).
The full list of primitives can be seen in this [C++ source
file](../targets/simple_switch/primitives.cpp).

## Pseudocode for what happens at the end of ingress and egress processing

After-ingress pseudocode - the short version:

```
if (clone_spec != 0) {      // because your code called clone or clone3
    make a clone of the packet with details configured for the clone session
}
if (lf_field_list != 0) {   // because your code called generate_digest
    send a digest message to the control plane software
}
if (resubmit_flag != 0) {   // because your code called resubmit
    start ingress processing over again for the original packet
} else if (mcast_grp != 0) {  // because your code assigned a value to mcast_grp
    multicast the packet to the output port(s) configured for group mcast_grp
} else if (egress_spec == 511) {  // because your code called drop/mark_to_drop
    Drop packet.
} else {
    unicast the packet to the port equal to egress_spec
}
```

After-ingress pseudocode - for determining what happens to a packet
after ingress processing is complete.  The longer more detailed
version:

```
if (clone_spec != 0) {
    // This condition will be true if your code called the clone or
    // clone3 primitive action during ingress processing.
    Make a clone of the packet destined for the egress_port configured
    in the clone (aka mirror) session id number that was given when the
    last clone or clone3 primitive action was called.

    The packet contents will be the same as when it most recently
    began the ingress processing, where the clone operation was
    performed, without any modifications that may have been made
    during the execution of that ingress code.  (That may not be the
    packet as originally received by the switch, if the packet reached
    this occurrence of ingress processing via a recirculate operation,
    for example.)

    If it was a clone3 action, also preserve the final ingress values
    of the metadata fields specified in the field list argument,
    except assign clone_spec a value of 0 always, and instance_type a
    value of PKT_INSTANCE_TYPE_INGRESS_CLONE.
    // fall through to code below
}
if (lf_field_list != 0) {
    // This condition will be true if your code called the
    // generate_digest primitive action during ingress processing.
    Send a digest message to the control plane that contains the
    values of the fields in the specified field list.
    // fall through to code below
}
if (resubmit_flag != 0) {
    // This condition will be true if your code called the resubmit
    // primitive action during ingress processing.
    Start ingress over again for this packet, with its original
    unmodified packet contents and metadata values.  Preserve the
    final ingress values of any fields specified in the field list
    given as an argument to the last resubmit() primitive operation
    called, except assign resubmit_flag a value of 0 always, and
    instance_type a value of PKT_INSTANCE_TYPE_RESUBMIT.
} else if (mcast_grp != 0) {
    // This condition will be true if your code made an assignment to
    // standard_metadata.mcast_grp during ingress processing.  There
    // are no special primitive actions built in to simple_switch for
    // you to call to do this -- use a normal P4_16 assignment
    // statement, or P4_14 modify_field() primitive action.
    Make 0 or more copies of the packet based upon the list of
    (egress_port, egress_rid) values configured by the control plane
    for the mcast_grp value.  Enqueue each one in the appropriate
    packet buffer queue.  The instance_type of each will be
    PKT_INSTANCE_TYPE_REPLICATION.
} else if (egress_spec == 511) {
    // This condition will be true if your code called the
    // mark_to_drop (P4_16) or drop (P4_14) primitive action during
    // ingress processing.
    Drop packet.
} else {
    Enqueue one copy of the packet destined for egress_port equal to
    egress_spec.
}
```

After-egress pseudocode - the short version:

```
if (clone_spec != 0) {    // because your code called clone or clone3
    make a clone of the packet with details configured for the clone session
}
if (egress_spec == 511) {  // because your code called drop/mark_to_drop
    Drop packet.
} else if (recirculate_flag != 0) {  // because your code called recirculate
    start ingress processing over again for deparsed packet
} else {
    Send the packet to the port in egress_port.
}
```

After-egress pseudocode - for determining what happens to a packet
after egress processing is complete.  The longer more detailed
version:

```
if (clone_spec != 0) {
    // This condition will be true if your code called the clone or
    // clone3 primitive action during egress processing.
    Make a clone of the packet destined for the egress_port configured
    in the clone (aka mirror) session id number that was given when the
    last clone or clone3 primitive action was called.

    The packet contents will be as constructed by the deparser after
    egress processing, with any modifications made to the packet
    during both ingress and egress processing.

    If it was a clone3 action, also preserve the final egress values
    of the metadata fields specified in the field list argument,
    except assign clone_spec a value of 0 always, and instance_type a
    value of PKT_INSTANCE_TYPE_EGRESS_CLONE.
    // fall through to code below
}
if (egress_spec == 511) {
    // This condition will be true if your code called the
    // mark_to_drop (P4_16) or drop (P4_14) primitive action during
    // egress processing.
    Drop packet.
} else if (recirculate_flag != 0) {
    // This condition will be true if your code called the recirculate
    // primitive action during egress processing.
    Start ingress over again, for the packet as constructed by the
    deparser, with any modifications made to the packet during both
    ingress and egress processing.  Preserve the final egress values
    of any fields specified in the field list given as an argument to
    the last recirculate primitive action called, except assign
    recirculate_flag a value of 0 always, and instance_type a value of
    PKT_INSTANCE_TYPE_RECIRC.
} else {
    Send the packet to the port in egress_port.  Since egress_port is
    read only during egress processing, note that its value must have
    been determined during ingress processing for normal packets.  One
    exception is that a clone primitive action executed during egress
    processing will have its egress_port determined from the port that
    the control plane configured for that clone session).
}
```
