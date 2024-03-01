/* -*- P4_16 -*- */

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;

const bit<16>       TYPE_RECIRC = 0x88B5;
const bit<16>       TYPE_IPV4 = 0x800;
const bit<8>        TYPE_TCP = 6;
const bit<8>        TYPE_UDP = 17;
const bit<32>       MAX_REGISTER_ENTRIES = 65536;

#define INDEX_WIDTH 16
#define timeout_threshold 512