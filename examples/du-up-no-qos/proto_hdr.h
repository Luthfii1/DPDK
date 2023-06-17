#ifndef PROPTO_HDR_H_
#define PROPTO_HDR_H_

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_SCTP 132

#define UDP_PORT_UE5G 9527

#define GTP_MSG_TYPE_G_PDU 255
#define GTP_EXT_HDR_TYPE_NR_RAN_CONTAINER 0b10000100

struct drb_ind_hdr {
    uint8_t drb_id : 6;
    uint8_t R: 1;
    uint8_t sdap_hdr_presence : 1;
} __rte_packed;

struct pdcp_hdr_sn_12 {
    uint8_t pdcp_sn_first_4_bits : 4;
    uint8_t reserved : 3;
    uint8_t DC : 1;

    uint8_t pdcp_sn_last_8_bits;
} __rte_packed;

struct pdcp_hdr_sn_18 {
    uint8_t pdcp_sn_first_2_bits : 2;
    uint8_t reserved : 5;
    uint8_t DC : 1;

    uint16_t pdcp_sn_last_16_bits;
} __rte_packed;

struct sdap_hdr {
    uint8_t qfi : 6;
    uint8_t reserved : 1;
    uint8_t DC : 1;
} __rte_packed;

struct gtp_ext_info {
    uint16_t seq_num;
    uint8_t n_pdu;
    uint8_t next_ext_hdr_type;
} __rte_packed;

/* We currently only include mandatory part of PDU type 0 */
struct ran_container_type0 {
	uint8_t report_polling : 1;
    uint8_t dl_flush : 1;
    uint8_t dl_discard_blocks : 1;
    uint8_t spare_1 : 1;
    uint8_t pdu_type : 4;

    uint8_t retr_flag : 1;
    uint8_t assist_report_polling_flag : 1;
    uint8_t user_data_exist_flag : 1;
    uint8_t report_deliverd : 1;
    uint8_t req_out_of_seq_report : 1;
    uint8_t spare : 3;

    uint32_t nr_seq : 24;
} __rte_packed;

/* We currently only include mandatory part of PDU type 1 */
struct ran_container_type1 {
    uint8_t lost_pkt_report : 1;
    uint8_t final_frame_ind : 1;
    uint8_t hd_pdcp_sn_ind : 1; /* Highest Delivered PDCP SN Ind. */
    uint8_t ht_pdcp_sn_ind : 1; /* Highest Transmitted PDCP SN Ind. */
    uint8_t pdu_type : 4;

    uint8_t cause_report : 1;
    uint8_t delivered_retr_pdcp_sn_ind : 1;
    uint8_t retr_pdcp_sn_ind : 1;
    uint8_t data_rate_ind : 1; /* Desired data rate */
    uint8_t delivered_pdcp_sn_range_ind : 1; /* successfully delivered out of sequence PDCP SN range */
    uint8_t spare : 3;

    uint32_t desired_buffer_size;
} __rte_packed;

#endif /* PROPTO_HDR_H_ */