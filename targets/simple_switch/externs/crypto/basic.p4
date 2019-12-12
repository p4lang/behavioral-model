/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CONTROLLER_PORT 16

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;
const bit<16> TYPE_LLDP = 0x88cc;
const bit<16> TYPE_MACSEC = 0x88e5;
const bit<16> TYPE_BDDP = 0x8999;

const bit<16> DST_MAC_UNKNOWN = 1;
const bit<16> SRC_MAC_UNKNOWN = 2;
const bit<16> SRC_MAC_TIMEOUT = 3;
const bit<16> SRC_MAC_CHANGED_PORT = 4;
const bit<16> ARP_IN = 10;
const bit<16> LLDP_IN = 11;
const bit<16> PACKET_OUT_ON_PORT = 60001;
const bit<16> FULL_PROCESS = 60002;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header cpu_header_t {
    bit<64> zeros;
    bit<16> reason;
    bit<16> port;
    bit<48> timestamp;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header sectag_t {
    bit<1>  tci_v;
    bit<1>  tci_es;
    bit<1>  tci_sc;
    bit<1>  tci_scb;
    bit<1>  tci_e;
    bit<1>  tci_c;
    bit<2>  an;
    bit<8>  sl;
    bit<32> pn;
    bit<64> sci;
}

struct user_metadata_t {
    bit<128>       SAK;
    bit<48>        SYSTEM_ID;
    bit<8>         REGISTER_NUMBER;
    bit<48>        src_mac_timeout;
    egressSpec_t   src_mac_table_port;
    bool           from_controller;
    bool	   recirculated;
}

struct intrinsic_metadata_t {
	bit<16>   recirculate_flag;
    bit<48>   ingress_global_timestamp;
}

struct metadata {
    @metadata @name("intrinsic_metadata")
    intrinsic_metadata_t intrinsic_metadata;
    user_metadata_t      user_metadata;
}

struct headers {
    cpu_header_t cpu_header;
    ethernet_t   ethernet;
    sectag_t     sectag;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(packet.lookahead<cpu_header_t>().zeros) {
            (bit<64>)0 : parse_cpu_header;
            default: parse_ethernet;
        }
    }

    state parse_cpu_header {
        packet.extract(hdr.cpu_header);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_MACSEC: parse_sectag;
	        TYPE_LLDP: accept;
	        TYPE_BDDP: accept;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_sectag {
        packet.extract(hdr.sectag);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

extern ExternCrypt {
    ExternCrypt();
    void protect(in bit<128> SAK,
                in bit<64> SCI,
                in bit<32> PN,
                in bit<48> src_addr,
                in bit<48> dst_addr,
                in bit<128> sectag,
                in bit<16> ethertype,
                in bit<8> prepend_ipv4_hdr,
                in bit<160> ipv4_hdr);
    void validate(in bit<128> SAK,
                in bit<64> SCI,
                in bit<32> PN,
                in bit<48> src_addr,
                in bit<48> dst_addr,
                in bit<128> sectag,
                out bit<8> valid,
                out bit<16> ethertype);
}

ExternCrypt() crypt;


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action send_to_controller(bit<16> reason, egressSpec_t port){
        standard_metadata.egress_spec = CONTROLLER_PORT;
        hdr.cpu_header.setValid();
        hdr.cpu_header.reason = reason;
        hdr.cpu_header.port = (bit<16>)port;
        hdr.cpu_header.timestamp = standard_metadata.ingress_global_timestamp;
    }

    action l2_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action flood() {
        send_to_controller(DST_MAC_UNKNOWN, standard_metadata.ingress_port);
    }

    action learn_src_mac() {
        send_to_controller(SRC_MAC_UNKNOWN, standard_metadata.ingress_port);
    }

    action src_known(egressSpec_t port, bit<48> timestamp) {
        meta.user_metadata.src_mac_table_port = port;
        meta.user_metadata.src_mac_timeout = timestamp;
    }

    action validate_packet(bit<128> key) {
        meta.user_metadata.SAK = key;
    }

    table mac_src {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            learn_src_mac;
            src_known;
        }
        size = 1024;
        default_action = learn_src_mac();
    }

    table mac_dst {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            l2_forward;
            flood;
            drop;
        }
        size = 1024;
        default_action = flood();
    }

    table validate_tbl {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            NoAction;
            validate_packet;
        }
    }

    apply {
        //packet from controller, go through full pipeline
        if (hdr.cpu_header.isValid() && hdr.cpu_header.reason == FULL_PROCESS) {
            hdr.cpu_header.setInvalid();
            meta.user_metadata.from_controller = true;
    	}
        else {
            meta.user_metadata.from_controller = false;
        }

        // packet from controller, send out on specified port
    	if (hdr.cpu_header.isValid() && hdr.cpu_header.reason == PACKET_OUT_ON_PORT) {
            standard_metadata.egress_spec = (bit<9>)hdr.cpu_header.port;
            hdr.cpu_header.setInvalid();
    	}

        // packet encrypted with macsec
        else if (hdr.sectag.isValid()) {
            if (validate_tbl.apply().hit) {
                //key found, decrypt the packet
                bit<128> SAK = meta.user_metadata.SAK;
                bit<64> SCI = hdr.sectag.sci;
                bit<32> PN = hdr.sectag.pn;
                bit<128> sectag = TYPE_MACSEC ++ hdr.sectag.tci_v ++ hdr.sectag.tci_es ++ hdr.sectag.tci_sc ++ hdr.sectag.tci_scb ++ hdr.sectag.tci_e ++ hdr.sectag.tci_c ++ hdr.sectag.an ++ hdr.sectag.sl ++ hdr.sectag.pn ++ hdr.sectag.sci;
                bit<48> src_addr = hdr.ethernet.srcAddr;
                bit<48> dst_addr = hdr.ethernet.dstAddr;
                bit<8> valid;
                bit<16> ethertype;

                crypt.validate(SAK, SCI, PN, src_addr, dst_addr, sectag, valid, ethertype);

                hdr.ethernet.etherType = ethertype;
                hdr.sectag.setInvalid();

                //headers from decrypted payload not parsed -> recirculate packet
                meta.user_metadata.recirculated = true;
                recirculate({meta.intrinsic_metadata, standard_metadata, meta.user_metadata});
            }
        }

        // LLDP or BDDP packet, send to controller
        else if (hdr.ethernet.isValid() && (hdr.ethernet.etherType == TYPE_LLDP || hdr.ethernet.etherType == TYPE_BDDP)) {
            send_to_controller(LLDP_IN, standard_metadata.ingress_port);
        }

        // ARP packet, send to controller
        else if (hdr.ethernet.isValid() && hdr.ethernet.etherType == TYPE_ARP) {
            send_to_controller(ARP_IN, standard_metadata.ingress_port);
        }

        // all other ethernet packets
        else if (hdr.ethernet.isValid()) {
            // refresh source mac entry
            if(!meta.user_metadata.from_controller && mac_src.apply().hit) {
                if(standard_metadata.ingress_global_timestamp > meta.user_metadata.src_mac_timeout) {
                    send_to_controller(SRC_MAC_TIMEOUT, standard_metadata.ingress_port);
                }
                else if (meta.user_metadata.src_mac_table_port != standard_metadata.ingress_port) {
                    send_to_controller(SRC_MAC_CHANGED_PORT, standard_metadata.ingress_port);
                }
            }

            // get port for dst amc
            // drop if port unknown and packet was decrypted (=recirculated)
            // (prevents flooding decrypted packet)
            if(!hdr.cpu_header.isValid()) {
                if(!mac_dst.apply().hit && meta.user_metadata.recirculated) {
        		    drop();
                }
            }

            // drop packet if premilinary egress port
            if (standard_metadata.egress_spec == 0x1FF) {
                drop();
            }

            // drop packet if ingress port == egress port
            if (standard_metadata.egress_spec != CONTROLLER_PORT && standard_metadata.egress_spec == standard_metadata.ingress_port) {
                drop();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

//16 register, bei mehr Ports entsprechend anpassen
register<bit<32>>(32w64) outgoing_packet_numbers;

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action protect_packet(bit<128> key, bit<48> system_id, bit<8> reg) {
        meta.user_metadata.SAK = key;
        meta.user_metadata.SYSTEM_ID = system_id;
	    meta.user_metadata.REGISTER_NUMBER = reg;
    }

    table protect_tbl {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            NoAction;
            protect_packet;
        }
    }

    apply {
        if (!hdr.cpu_header.isValid() && hdr.ethernet.isValid() && hdr.ethernet.etherType != TYPE_ARP
                && hdr.ethernet.etherType != TYPE_BDDP && protect_tbl.apply().hit){
            bit<128> SAK = meta.user_metadata.SAK;
            //get the PN from the corresponding counter
            bit<32> PN;
            outgoing_packet_numbers.read(PN, (bit<32>) meta.user_metadata.REGISTER_NUMBER);
            outgoing_packet_numbers.write((bit<32>) meta.user_metadata.REGISTER_NUMBER, PN + 1);

            //combine the System and Port Id to get the SCI
            bit<64> SCI = meta.user_metadata.SYSTEM_ID ++ (bit<16>) standard_metadata.egress_port;

            //set the macsec Header fragments to valid
            hdr.sectag.setValid();

            //set the neccesary data for the sectag and the new ethertype
            hdr.sectag.tci_v = 0;
            hdr.sectag.tci_es = 0;
            hdr.sectag.tci_sc = 1;
            hdr.sectag.tci_scb = 0;
            hdr.sectag.tci_e = 1;
            hdr.sectag.tci_c = 1;
            hdr.sectag.an = 0;
            hdr.sectag.sl = 0;
            hdr.sectag.pn = PN;
            hdr.sectag.sci = SCI;
            bit<128> sectag = TYPE_MACSEC ++ hdr.sectag.tci_v ++ hdr.sectag.tci_es ++ hdr.sectag.tci_sc ++ hdr.sectag.tci_scb ++ hdr.sectag.tci_e ++ hdr.sectag.tci_c ++ hdr.sectag.an ++ hdr.sectag.sl ++ hdr.sectag.pn ++ hdr.sectag.sci;

            bit<8> prepend_ipv4 = 0x46;
            bit<160> ipv4 = 0;
            if (hdr.ipv4.isValid()) {
                prepend_ipv4 = 0x54;
                ipv4 = hdr.ipv4.version ++ hdr.ipv4.ihl ++ hdr.ipv4.diffserv ++ hdr.ipv4.totalLen ++ hdr.ipv4.identification ++ hdr.ipv4.flags ++ hdr.ipv4.fragOffset ++ hdr.ipv4.ttl ++ hdr.ipv4.protocol ++ hdr.ipv4.hdrChecksum ++ hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr;
                hdr.ipv4.setInvalid();
            }

            crypt.protect(SAK, SCI, PN, hdr.ethernet.srcAddr, hdr.ethernet.dstAddr, sectag, hdr.ethernet.etherType, prepend_ipv4, ipv4);

            hdr.ethernet.etherType = TYPE_MACSEC;
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.cpu_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.sectag);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
