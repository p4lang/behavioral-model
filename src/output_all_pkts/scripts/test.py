'''Test cases for P4 program action-profile.p4'''

import pprint as pp

from scapy.all import *
# The following line isn't really necessary given the previous import
# line, but it does help avoid many 'undefined variable' pylint
# warnings
from scapy.all import TCP, Ether, IP
import runtime_CLI
import sstf_lib as sstf
import bm_runtime.standard.ttypes as ttypes


def ipv4_addr_str(addr_int):
    assert 0 <= addr_int and addr_int < (1 << 32)
    addr_str = ('%d.%d.%d.%d' % (addr_int >> 24,
                                 (addr_int >> 16) & 0xff,
                                 (addr_int >>  8) & 0xff,
                                 (addr_int >>  0) & 0xff))
    return addr_str


@sstf.test_wrap
def test_table_add_errors(hdl, table_info):
    # Verify that simple_switch disallows adding a 'normal' table
    # entry to a table with implementation action_profile() or
    # action_selector().
    for table_name in table_info.keys():
        t = table_info[table_name]
        if 'act_prof_name' in t:
            exc_expected = True
        else:
            # Adding a normal table entry to a table with no action
            # profile should succeed.
            exc_expected = False
        exc_raised = False
        try:
            entry_hdl = hdl.do_table_add(table_name + " foo1 0xdead => 0xbeef")
        except ttypes.InvalidTableOperation:
            exc_raised = True
        if exc_expected:
            assert exc_raised
            print("Expected: exception InvalidTableOperation was raised")
        else:
            assert not exc_raised
            print("Expected: no exception InvalidTableOperation was raised")
            # Remove the entry that was added
            hdl.do_table_delete(table_name + " " + str(entry_hdl))


@sstf.test_wrap
def test_act_prof_create_group_fails_on_indirect_table(hdl, table_info):
    # Verify that it is an error to try to create groups for tables
    # with implementation action_profile().  They have type 'indirect'
    # in compiled JSON files.
    for table_name in table_info.keys():
        t = table_info[table_name]
        if t['type'] != 'indirect':
            continue
        exc_expected = True
        exc_raised = False
        try:
            grp_handle = hdl.do_act_prof_create_group(t['act_prof_name'])
        except runtime_CLI.UIn_Error:
            exc_raised = True
        assert exc_raised
        print("Expected: exception runtime_CLI.UIn_Error was raised")


@sstf.test_wrap
def test_table_indirect_add_all_table_types(hdl, table_info):
    print('== table_indirect_add should fail for a normal table')
    for table_name in table_info.keys():
        t = table_info[table_name]
        member_hdl = None
        if 'act_prof_name' in t:
            exc_type_expected = None
            member_hdl = hdl.do_act_prof_create_member(t['act_prof_name'] +
                                                       " foo1 0xdead")
            # The commented-out code below confirmed that after doing
            # act_prof_create_member on a table's action profile, but
            # before doing table_indirect_add on the table, its
            # num_entries was 0.
            #num_entries = hdl.do_table_num_entries(table_name)
            #print("Table %s num_entries = %d" % (table_name, num_entries))
            #print("")
            #hdl.do_table_dump(table_name)
            #print("----------")
        else:
            exc_type_expected = runtime_CLI.UIn_Error
        exc_raised = None
        try:
            entry_hdl = hdl.do_table_indirect_add(table_name + " 0xdead => 0")
        except Exception as e:
            exc_raised = e
            print('Exception type %s raised' % (str(type(e))))
        print('')
        print('table %s exc_type_expected %s type(exc_raised) %s'
              '' % (table_name, exc_type_expected, type(exc_raised)))
        if exc_type_expected is None:
            assert exc_raised is None
            print("Expected: no exception was raised")
            assert hdl.do_table_num_entries(table_name) == 1
            print("Table %s has expected 1 entry" % (table_name))

            # Verify that trying to remove the member, while it still
            # has a table entry referring to it, causes an error.
            exc2_type_expected = ttypes.InvalidTableOperation
            exc2_raised = None
            try:
                hdl.do_act_prof_delete_member(t['act_prof_name'] + " " +
                                              str(member_hdl))
            except Exception as e:
                exc2_raised = e
            assert isinstance(exc2_raised, exc2_type_expected)
            print("Expected: While attempting act_prof_delete_member"
                  " on a member still referred to by an entry of table %s,"
                  " exception of type %s was raised"
                  "" % (table_name, exc2_type_expected))

            # Remove the entry that was added
            hdl.do_table_indirect_delete(table_name + " " + str(entry_hdl))
            # Remove the member that was added
            hdl.do_act_prof_delete_member(t['act_prof_name'] + " " +
                                          str(member_hdl))
            assert hdl.do_table_num_entries(table_name) == 0
            print("Table %s has expected 0 entries" % (table_name))
        else:
            assert isinstance(exc_raised, exc_type_expected)
            print("Expected: exception of type %s was raised"
                  "" % (exc_type_expected))
        print("----------------------------------------")


def ipv4_dst_addr_to_member_action_id(dst_addrs, tcp_source_port, port_int_map,
                                      ipv4_addr_str_to_member):
    src_addr = '10.11.12.13'
    dst_addr_to_member = collections.OrderedDict()
    for dst_addr in dst_addrs:
        pkt = (Ether() / IP(src=src_addr, dst=dst_addr) /
               TCP(sport=tcp_source_port))

        # We expect the output packet to be the same, except that the
        # IP src address will be modified by one of the foo1 actions
        # to be equal to the action parameter of that foo1 action.
        # Since we have added all action parameters with unique
        # values, we should be able to determine which member action
        # was executed on the packet.
        cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                              [{'port': 1, 'packet': pkt}])
        pkts_by_port = sstf.packets_by_port(cap_pkts, [1])
        # Expect the packets to be sent out of port 0
        assert len(pkts_by_port[0]) == 1
        cap_pkt = pkts_by_port[0][0]['packet']
        #print("Captured packet: %s" % (cap_pkt.command()))
        #print("Captured packet IP src=%s" % (cap_pkt[IP].src))

        # Verify that the output packet is the same as the input
        # packet, except with the IPv4 source address changed.
        exp_pkt = Ether(str(pkt))
        exp_pkt[IP].src = cap_pkt[IP].src
        assert str(cap_pkt) == str(exp_pkt)
        
        # Determine which action was run on this packet
        assert cap_pkt[IP].src in ipv4_addr_str_to_member
        member_id = ipv4_addr_str_to_member[cap_pkt[IP].src]
        #print("Member action run on this packet=%d"
        #      "" % (member_id))
        dst_addr_to_member[dst_addr] = member_id
    return dst_addr_to_member


@sstf.test_wrap
def test_action_selector_traffic_distribution(hdl, table_info, port_int_map):

    # Create a single group in table t2, with implementation
    # action_selector().  Add 3 members to this group, and send
    # packets that differ only in the match_kind 'selector' field to
    # see which packets have which member actions in the group
    # performed on them.

    tcp_source_port = 9000
    # All members will have action foo2, with one of the values below
    # as the action parameter.
    members = {
        0: {'action_name': 'foo2',
            'action_parameter': 200},
        1: {'action_name': 'foo2',
            'action_parameter': 201},
        2: {'action_name': 'foo2',
            'action_parameter': 202},
        3: {'action_name': 'foo2',
            'action_parameter': 203},
        4: {'action_name': 'foo2',
            'action_parameter': 204},
        5: {'action_name': 'foo2',
            'action_parameter': 205}
        }

    # Create a table that maps IPv4 addresses that we expect to see in
    # output packets, back to the key in dict 'members' above that
    # corresponds to the action that would assign that IPv4 address in
    # an output packet.
    ipv4_addr_str_to_member = {}
    for member_num in members:
        m = members[member_num]
        addr_str = ipv4_addr_str(m['action_parameter'])
        ipv4_addr_str_to_member[addr_str] = member_num

    table_name = 't2'
    t = table_info[table_name]
    for i in members:
        m = members[i]
        member_hdl = hdl.do_act_prof_create_member(t['act_prof_name'] + " " +
                                                   m['action_name'] + " " +
                                                   str(m['action_parameter']))
        m['member_hdl'] = member_hdl
    group_hdl = hdl.do_act_prof_create_group(t['act_prof_name'])

    # Verify that there is an error when attempting to add a table
    # entry pointing at an empty group.
    exc_type_expected = ttypes.InvalidTableOperation
    exc_raised = None
    try:
        entry_hdl = hdl.do_table_indirect_add_with_group(table_name + " " +
                                                         str(tcp_source_port) +
                                                         " => " +
                                                         str(group_hdl))
    except Exception as e:
        exc_raised = e
    assert isinstance(exc_raised, exc_type_expected)
    print("Expected: While attempting table_indirect_add_with_group"
          " with an empty group for an entry of table %s,"
          " exception of type %s was raised"
          "" % (table_name, exc_type_expected))

    # List of IPv4 destination addresses to test with.  One packet
    # will be sent for each member of this list, for each of several
    # different number of members in the group.  Sending and checking
    # each packet currently takes about 2 seconds, so making this list
    # long will make the test take significant time before it
    # completes.
    dst_addrs = ['192.168.0.%d' % (x) for x in range(15)]
    #dst_addrs = ['192.168.0.%d' % (x) for x in range(6)]

    results = {}

    # Add 3 members to the group, then add a table entry using the
    # group.
    member_list = [0, 1, 2]
    for i in member_list:
        m = members[i]
        hdl.do_act_prof_add_member_to_group(t['act_prof_name'] + " " +
                                            str(m['member_hdl']) + " " +
                                            str(group_hdl))
    entry_hdl = hdl.do_table_indirect_add_with_group(table_name + " " +
                                                     str(tcp_source_port) +
                                                     " => " + str(group_hdl))
    hdl.do_table_dump(table_name)
    print("Sending %d packets to test behavior when group %d has members %s"
          "" % (len(dst_addrs), group_hdl, member_list))
    dst_addr_to_member = ipv4_dst_addr_to_member_action_id(
        dst_addrs, tcp_source_port, port_int_map, ipv4_addr_str_to_member)
    results[0] = {'member_list': copy.copy(member_list),
                  'dst_addr_to_member': dst_addr_to_member}

    # Add a 4th member to the group and collect forwarding behavior
    # results again.
    member_id = 3
    member_list.append(member_id)
    m = members[member_id]
    hdl.do_act_prof_add_member_to_group(t['act_prof_name'] + " " +
                                        str(m['member_hdl']) + " " +
                                        str(group_hdl))
    print("Sending %d packets to test behavior when group %d has members %s"
          "" % (len(dst_addrs), group_hdl, member_list))
    dst_addr_to_member = ipv4_dst_addr_to_member_action_id(
        dst_addrs, tcp_source_port, port_int_map, ipv4_addr_str_to_member)
    results[1] = {'member_list': copy.copy(member_list),
                  'dst_addr_to_member': dst_addr_to_member}

    # Add a 5th member to the group and collect forwarding behavior
    # results again.
    member_id = 4
    member_list.append(member_id)
    m = members[member_id]
    hdl.do_act_prof_add_member_to_group(t['act_prof_name'] + " " +
                                        str(m['member_hdl']) + " " +
                                        str(group_hdl))
    print("Sending %d packets to test behavior when group %d has members %s"
          "" % (len(dst_addrs), group_hdl, member_list))
    dst_addr_to_member = ipv4_dst_addr_to_member_action_id(
        dst_addrs, tcp_source_port, port_int_map, ipv4_addr_str_to_member)
    results[2] = {'member_list': copy.copy(member_list),
                  'dst_addr_to_member': dst_addr_to_member}

    # Remove 2 of the members 'from the middle' and collect results
    # again.
    for member_id in [1, 3]:
        member_list.remove(member_id)
        m = members[member_id]
        hdl.do_act_prof_remove_member_from_group(t['act_prof_name'] + " " +
                                                 str(m['member_hdl']) + " " +
                                                 str(group_hdl))
    hdl.do_table_dump(table_name)
    print("Sending %d packets to test behavior when group %d has members %s"
          "" % (len(dst_addrs), group_hdl, member_list))
    dst_addr_to_member = ipv4_dst_addr_to_member_action_id(
        dst_addrs, tcp_source_port, port_int_map, ipv4_addr_str_to_member)
    results[3] = {'member_list': copy.copy(member_list),
                  'dst_addr_to_member': dst_addr_to_member}

    pp.pprint(results)

    # TBD: Remove all members and groups from table t2, perhaps
    # checking for some kinds of disallowed order of such operations
    # in the process.


def main():
    # port_int_map represents the desired correspondence between P4
    # program port numbers and Linux interfaces.  The data structure
    # returned by port_intf_mapping() is used in multiple places
    # throughout the code.
    port_int_map = sstf.port_intf_mapping({0: 'veth0',
                                           1: 'veth2',
                                           2: 'veth4',
                                           3: 'veth6',
                                           4: 'veth8',
                                           5: 'veth10',
                                           6: 'veth12'})
    args = sstf.get_args()
    ss_process_obj = sstf.start_simple_switch(args, port_int_map)
    hdl = runtime_CLI.test_init(args)

    # This info I obtained from manually inspecting the contents of
    # the file action-profile.json compiled from action-profile.p4.
    # Is there is a way to use annotations in the P4_16 source code to
    # force the names of the action profiles?
    table_info = collections.OrderedDict()
    table_info['t0'] = {'type': 'simple'}
    table_info['t1'] = {
        'type': 'indirect',
        'act_prof_name': 'action_profile_0'
    }
    table_info['t2'] = {
        'type': 'indirect_ws',
        'act_prof_name': 'action_profile_1'
    }
    
    test_table_add_errors(hdl, table_info)
    test_act_prof_create_group_fails_on_indirect_table(hdl, table_info)
    test_table_indirect_add_all_table_types(hdl, table_info)
    test_action_selector_traffic_distribution(hdl, table_info, port_int_map)

    ss_process_obj.kill()


if __name__ == '__main__':
    main()