#define WS_BUILD_DLL
#include <wireshark.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-rtp.h>
#include <math.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

#define AXIA_MAGIC_NUMBER 0x03000207
#define FAST_CLOCK_ADDR "239.192.255.1"
#define FAST_CLOCK_PORT 5004
#define SLOW_CLOCK_ADDR "239.192.255.2"
#define SLOW_CLOCK_PORT 7000
#define LWADV_ADDR "239.192.255.3"
#define LWADV_PORT 4001 
#define LWGPIO_ADDR "239.192.255.4"
#define LWGPIO_CONSOLE_PORT 2060 
#define LWGPIO_NODE_PORT 2055 
#define LWRTP_PORT 5004

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

static int proto_lwadv = -1;
static int proto_lwgpio = -1;
static int proto_lwclock = -1;

static int hf_lw_magic_num;
static int hf_lw_seq;
static int hf_lw_opcode;
static int hf_lw_msg_count;
static int hf_lw_pver;
static int hf_lw_advt;
static int hf_lw_unk_u8;
static int hf_lw_unk_u16;
static int hf_lw_unk_u32;
static int hf_lw_unk_data;
static int hf_lw_unk_str;

static int hf_lw_term;
static int hf_lw_term_inip;
static int hf_lw_term_advv;
static int hf_lw_term_hwid;
static int hf_lw_term_udpc;
static int hf_lw_term_nums;
static int hf_lw_term_atrn;
static int hf_lw_term_type;

static int hf_lw_src;
static int hf_lw_src_psid;
static int hf_lw_src_shab;
static int hf_lw_src_fsid;
static int hf_lw_src_bsid;
static int hf_lw_src_psnm;
static int hf_lw_src_lpid;
static int hf_lw_src_setup_frm;
static int hf_lw_src_is_mm;

static int hf_lw_busy;
static int hf_lw_busy_hwid;
static int hf_lw_busy_fader;
static int hf_lw_busy_ip;
static int hf_lw_busy_prefix;

static int hf_lw_gpio;
static int hf_lw_gpio_lcid;
static int hf_lw_gpio_state;
static int hf_lw_gpio_state2;
static int hf_lw_gpio_pmult;
static int hf_lw_gpio_plen;

static int hf_lw_clock_prio;
static int hf_lw_clock_hwid;
static int hf_lw_clock_mac;
static int hf_lw_clock_samp;
static int hf_lw_clock_fast;
static int hf_lw_clock_seq;
static int hf_lw_clock_rate;
static int hf_lw_clock_type;

static int ett_lwadv;

static wmem_tree_t *lwadv_sources;
static wmem_tree_t *lwadv_nodes;

static address fast_clock_address;
static address slow_clock_address;
static address advertisement_address;
static address gpio_address;

typedef enum {
    SECTION_ADV_BASE,
    SECTION_TERM,
    SECTION_SOURCE,
    SECTION_GPIO,
} lw_adv_section_e;

typedef struct {
    uint16_t hwid;
    char* atrn;
    ws_in4_addr inip;
    uint16_t udpc;
    conversation_t *conversation;
    uint32_t nums;
} lw_term_info_t;
typedef struct {
    uint32_t psid;
    ws_in4_addr fsid;
    ws_in4_addr bsid;
    char* psnm;
    lw_term_info_t* term;
    ws_in4_addr rtp_added;
    uint32_t setup_frame;
} lw_src_info_t;

typedef struct {
    lw_term_info_t *term_info;
    lw_src_info_t *src_info;
    int16_t lpid;
    int32_t nums;
} lw_info_t;

static dissector_handle_t lwadv_handle;
static dissector_handle_t lwgpio_handle;
static dissector_handle_t lwclock_handle;
static const value_string advtypenames[] = {
    { 0x1, "Verbose announcement" },
    { 0x2, "Periodic announcement" },
    { 0x3, "Source allocation state" },
    { 0, NULL }
};
static const value_string clocktypenames[] = {
    { 0x0a, "Fast clock sync" },
    { 0x0b, "Fast clock follow-up" },
    { 0x0c, "Slow clock sync" },
    { 0, NULL },
};
static char* get_opcode_description(char* opcode)
{
    if (!opcode) return 0;
    if (!opcode[0]) return 0;
    if (strcmp(opcode,"INDI") == 0)
        return "Value Indication";
    if (strcmp(opcode, "WRNI") == 0)
        return "Write value - returning the value indication is not requested";
    if (strcmp(opcode, "WRIN") == 0)
        return "Write value - returning the value indication is requested";
    if (strcmp(opcode, "READ") == 0)
        return "Read value";
    if (strcmp(opcode, "STAT") == 0)
        return "Status indication";
    if (strcmp(opcode, "NEST") == 0)
        return "No operation - container for nested messages";
    return 0;
}
static void setup_lw_transport(packet_info *pinfo, uint16_t psid){
    if (pinfo->fd->visited) {
        return;
    }
    lw_src_info_t *src_info = (lw_src_info_t*)wmem_tree_lookup32(lwadv_sources, psid);
    if (src_info && src_info->fsid && src_info->rtp_added != src_info->fsid) {
        // set up an rtp stream here
        address rtp_address;
        rtp_dyn_payload_t *dyn_payload = rtp_dyn_payload_new();
        rtp_dyn_payload_insert(dyn_payload, 96, "L24", 48000, 2);
        rtp_dyn_payload_insert(dyn_payload, 99, "L24", 48000, 8);
        rtp_dyn_payload_insert(dyn_payload, 101, "L24", 48000, 1);
        rtp_dyn_payload_insert(dyn_payload, 103, "L24", 48000, 3);
        rtp_dyn_payload_insert(dyn_payload, 104, "L24", 48000, 4);
        rtp_dyn_payload_insert(dyn_payload, 105, "L24", 48000, 5);
        rtp_dyn_payload_insert(dyn_payload, 106, "L24", 48000, 6);
        rtp_dyn_payload_insert(dyn_payload, 107, "L24", 48000, 7);
        rtp_dyn_payload_insert(dyn_payload, 111, "L16", 48000, 1);
        rtp_dyn_payload_insert(dyn_payload, 112, "L16", 48000, 2);
        rtp_dyn_payload_insert(dyn_payload, 113, "L16", 48000, 3);
        rtp_dyn_payload_insert(dyn_payload, 114, "L16", 48000, 4);
        rtp_dyn_payload_insert(dyn_payload, 115, "L16", 48000, 5);
        rtp_dyn_payload_insert(dyn_payload, 116, "L16", 48000, 6);
        rtp_dyn_payload_insert(dyn_payload, 117, "L16", 48000, 7);
        rtp_dyn_payload_insert(dyn_payload, 118, "L16", 48000, 8);
        alloc_address_wmem(wmem_file_scope(), &rtp_address, AT_IPv4, sizeof(ws_in4_addr), &src_info->fsid);
        rtp_add_address(pinfo, PT_UDP, &rtp_address, LWRTP_PORT, 0, "Livewire", pinfo->num, RTP_MEDIA_AUDIO, dyn_payload);
        free_address_wmem(wmem_file_scope(), &rtp_address);
        rtp_dyn_payload_free(dyn_payload);
        src_info->rtp_added = src_info->fsid;
    }
}
static void setup_adv_conversation(packet_info *pinfo, lw_term_info_t *term_info) {
    if (term_info->conversation) 
        return;
    if (term_info->inip && term_info->udpc){
        address node_address;
        alloc_address_wmem(wmem_file_scope(), &node_address, AT_IPv4, sizeof(ws_in4_addr), &term_info->inip);
        term_info->conversation = conversation_new(pinfo->num, &node_address, NULL, CONVERSATION_UDP, term_info->udpc, 0, NO_ADDR2|NO_PORT2);
        free_address_wmem(wmem_file_scope(), &node_address);
        conversation_set_dissector(term_info->conversation, lwadv_handle);
    }
}
static bool validate_header(tvbuff_t* tvb)
{
    if (tvb_captured_length(tvb) < 16) {
        return false;
    }
    else if (tvb_get_ntohl(tvb, 0) != AXIA_MAGIC_NUMBER) {
        return false;
    }
    for (int i = 8; i < 16; i++) {
        if (tvb_get_uint8(tvb, i) != 0) {
            return false;
        }
    }
    return true;
}
static void write_src_info(lw_info_t* info){
    bool is_backfeed = info->src_info->fsid && info->src_info->bsid &&
        info->src_info->fsid == info->src_info->bsid;
    if (is_backfeed) {
        info->src_info->psid = (uint32_t)(0 - (int32_t)info->src_info->psid);
    }
    lw_src_info_t *existing = (lw_src_info_t *)wmem_tree_lookup32(lwadv_sources, info->src_info->psid);
    if (existing) {
        if (info->src_info->fsid) existing->fsid = info->src_info->fsid;
        if (info->src_info->bsid) existing->bsid = info->src_info->bsid;
        if (info->src_info->psnm) existing->psnm = info->src_info->psnm;
        if (info->src_info->term) existing->term = info->src_info->term;
        if (info->src_info->rtp_added) existing->rtp_added = info->src_info->rtp_added;
        if (info->src_info->setup_frame) existing->setup_frame = info->src_info->setup_frame;
        wmem_free(wmem_file_scope(), info->src_info);
        info->src_info = existing;
    }
    else {
        wmem_tree_insert32(lwadv_sources, info->src_info->psid, (void *)info->src_info);
    }
}
static int tree_add_value(proto_tree *tree, tvbuff_t* tvb, int offset, int hf)
{
    switch(tvb_get_uint8(tvb, offset))
    {
        case 0x0:
        case 0x7:
            proto_tree_add_item(tree, hf, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            return 2;
        case 0x1:
            proto_tree_add_item(tree, hf, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
            return 5;
        case 0x3:
            int str_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf, tvb, offset + 3, str_len, ENC_ASCII | ENC_NA);
            return str_len + 3;
        case 0x6:
        case 0x8:
            proto_tree_add_item(tree, hf, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
            return 3;
        case 0x9:
            proto_tree_add_item(tree, hf, tvb, offset + 1, 8, ENC_BIG_ENDIAN);
            return 9;
    }
    return 0;
}
static int dissect_lwadv_unk(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    if (offset < 4) return 0;
    int len = 0;
    unsigned char* msg_type = tvb_get_string_enc(pinfo->pool, tvb, offset - 4, 4, ENC_ASCII|ENC_NA);
    proto_item *ti;
    switch(tvb_get_uint8(tvb, offset))
    {
        case 0x0:
        case 0x7:
            ti = proto_tree_add_item(tree, hf_lw_unk_u8, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            len = 2;
            break;
        case 0x1:
            ti = proto_tree_add_item(tree, hf_lw_unk_u32, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
            len = 5;
            break;
        case 0x3:
            int str_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
            ti = proto_tree_add_item(tree, hf_lw_unk_str, tvb, offset + 3, str_len, ENC_ASCII | ENC_NA);
            len = (str_len + 3);
            break;
        case 0x6:
        case 0x8:
            ti = proto_tree_add_item(tree, hf_lw_unk_u16, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
            len = 3;
            break;
        case 0x9:
            ti = proto_tree_add_item(tree, hf_lw_unk_data, tvb, offset + 1, 8, ENC_BIG_ENDIAN);
            len = 9;
            break;
    }
    proto_item_append_text(ti, " (%s)", msg_type);
    return len;
}
static int dissect_lwadv_msg(tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree, int offset, lw_adv_section_e section, lw_info_t *info) {
    char* msg_type;
    msg_type = tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII|ENC_NA);
    offset += 4;
    if (info == NULL) {
        info = wmem_new0(pinfo->pool, lw_info_t);
    }
    if (get_opcode_description(msg_type)){
        int msg_count = tvb_get_uint8(tvb, offset + 1);
        proto_tree_add_string_format(tree, hf_lw_opcode, tvb, offset - 4, 4, msg_type, 
            "Operation: %s (%s)", get_opcode_description(msg_type), msg_type);
        //proto_tree *nest_tree = proto_item_add_subtree(ti, ett_lwadv);
        offset += tree_add_value(tree, tvb, offset, hf_lw_msg_count);
        for (int i = 0; i < msg_count; i++) {
            increment_dissection_depth(pinfo);
            offset = dissect_lwadv_msg(tvb, pinfo, tree, offset, section, info);
            decrement_dissection_depth(pinfo);
        }
        if (section == SECTION_ADV_BASE && info->src_info &&
             info->term_info && info->term_info->nums){
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%d of %d Sources)", info->nums, info->term_info->nums);
        }
        return offset;
    } else if (section == SECTION_GPIO) offset -= 4;
    switch (section) {
        case SECTION_ADV_BASE:
            ws_assert(msg_type);
            if (strcmp(msg_type,"PVER") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_pver);
            }
            else if (strcmp(msg_type,"ADVT") == 0){
                col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_uint8(tvb, offset + 1),
                advtypenames, "Unknown Livewire Advertisement (0x%02x)"));
                return offset + tree_add_value(tree, tvb, offset, hf_lw_advt);
            }
            else if (strcmp(msg_type,"TERM") == 0){
                int len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                proto_item *ti = proto_tree_add_item(tree, hf_lw_term, tvb, offset - 4, len + 7, ENC_NA);
                proto_tree *term_tree = proto_item_add_subtree(ti, ett_lwadv);
                proto_item_set_text(ti, "Terminal Information");
                info->term_info = wmem_new0(wmem_file_scope(), lw_term_info_t);
                increment_dissection_depth(pinfo);
                dissect_lwadv_msg(tvb, pinfo, term_tree, offset + 3, SECTION_TERM, info);
                decrement_dissection_depth(pinfo);
                if (info->term_info->inip && info->term_info->atrn){
                    add_ipv4_name(info->term_info->inip, info->term_info->atrn, false);
                }
                if (info->term_info->inip && info->term_info->udpc){
                    setup_adv_conversation(pinfo, info->term_info);
                }
                return offset + len + 3;
            }
            else if (msg_type[0] == 'S' &&
                msg_type[1] >= '0' && msg_type[1] <= '9' &&
                msg_type[2] >= '0' && msg_type[2] <= '9' &&
                msg_type[3] >= '0' && msg_type[3] <= '9' 
                ){
                info->nums++;
                int src_num = ((msg_type[1] - '0') * 100) + ((msg_type[2] - '0') * 10) + (msg_type[3] - '0');
                int len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                proto_item *ti = proto_tree_add_item(tree, hf_lw_src, tvb, offset - 4, len + 7, ENC_NA);
                proto_tree *source_tree = proto_item_add_subtree(ti, ett_lwadv);
                proto_item_set_text(ti, "Source %d", src_num);
                info->src_info = wmem_new0(wmem_file_scope(), lw_src_info_t);
                increment_dissection_depth(pinfo);
                dissect_lwadv_msg(tvb, pinfo, source_tree, offset + 3, SECTION_SOURCE, info);
                decrement_dissection_depth(pinfo);
                if (info->term_info) info->src_info->term = info->term_info;
                proto_item_append_text(ti, ": %d", info->src_info->psid);
                write_src_info(info);
                if (info->src_info->psnm){
                    proto_item_append_text(ti, " [%s", info->src_info->psnm);
                    if (info->src_info->term && info->src_info->term->atrn) {
                        proto_item_append_text(ti, "@%s",info->src_info->term->atrn);
                    }
                    proto_item_append_text(ti, "]");
                    if (!info->src_info->setup_frame) info->src_info->setup_frame = pinfo->num;
                    else if (info->src_info->setup_frame != pinfo->num) {
                        ti = proto_tree_add_uint(source_tree, hf_lw_src_setup_frm, tvb, 0, 0, info->src_info->setup_frame);
                        proto_item_set_generated(ti);
                    }
                    if (info->src_info->fsid && info->src_info->bsid){
                        bool is_mm = info->src_info->bsid == info->src_info->fsid;
                        ti = proto_tree_add_boolean(source_tree, hf_lw_src_is_mm, 
                            tvb, 0, 0, is_mm);
                        if (is_mm) {
                            proto_item_set_text(ti, "Source is a backfeed");
                        }
                        else {
                            proto_item_set_hidden(ti);                            
                        }
                        proto_item_set_generated(ti);
                    }
                } 
                setup_lw_transport(pinfo, info->src_info->psid);
                return offset + len + 3;
            }
            break;
        case SECTION_TERM:
            ws_assert(msg_type);
            if (strcmp(msg_type,"INIP") == 0){
                info->term_info->inip = tvb_get_ipv4(tvb, offset + 1);
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_inip);
            }
            else if (strcmp(msg_type,"HWID") == 0){
                info->term_info->hwid = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                lw_term_info_t *existing = (lw_term_info_t *)wmem_tree_lookup32(lwadv_nodes, info->term_info->hwid);
                if (existing) {
                    if (info->term_info->atrn) existing->atrn = info->term_info->atrn;
                    if (info->term_info->inip) existing->inip = info->term_info->inip;
                    if (info->term_info->udpc) existing->udpc = info->term_info->udpc;
                    wmem_free(wmem_file_scope(), info->term_info);
                    info->term_info = existing;
                }
                else {
                    wmem_tree_insert32(lwadv_nodes, info->term_info->hwid, (void *)info->term_info);
                }
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_hwid);
            }
            else if (strcmp(msg_type,"ADVV") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_advv);
            }
            else if (strcmp(msg_type,"UDPC") == 0){
                info->term_info->udpc = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_udpc);
            }
            else if (strcmp(msg_type,"NUMS") == 0){
                info->term_info->nums = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_nums);
            }
            else if (strcmp(msg_type,"ATRN") == 0){
                int str_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                char* atrn = tvb_get_string_enc(wmem_file_scope(), tvb, offset + 3, str_len, ENC_ASCII|ENC_NA);
                info->term_info->atrn = atrn;
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_atrn);
            }
            else if (strcmp(msg_type,"TYPE") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_type);
            }
            break;
        case SECTION_SOURCE:
            ws_assert(msg_type);
            if (strcmp(msg_type,"PSID") == 0){
                info->src_info->psid = tvb_get_uint32(tvb, offset + 1, ENC_BIG_ENDIAN);
                /*
                lw_src_info_t *existing = (lw_src_info_t *)wmem_tree_lookup32(lwadv_sources, info->src_info->psid);
                if (existing) {
                    if (info->src_info->psnm) existing->psnm = info->src_info->psnm;
                    if (info->src_info->term) existing->term = info->src_info->term;
                    if (info->src_info->fsid) existing->fsid = info->src_info->fsid;
                    wmem_free(wmem_file_scope(), info->src_info);
                    info->src_info = existing;
                }
                else {
                    wmem_tree_insert32(lwadv_sources, info->src_info->psid, (void *)info->src_info);
                }
                */
                return offset + tree_add_value(tree, tvb, offset, hf_lw_src_psid);
            }
            else if (strcmp(msg_type,"PSNM") == 0){
                int str_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                char* psnm = tvb_get_string_enc(wmem_file_scope(), tvb, offset + 3, str_len, ENC_ASCII|ENC_NA);
                info->src_info->psnm = psnm;
                return offset + tree_add_value(tree, tvb, offset, hf_lw_src_psnm);
            }
            else if (strcmp(msg_type,"FSID") == 0){
                ws_in4_addr fsid = tvb_get_ipv4(tvb, offset + 1);
                info->src_info->fsid = fsid;
                return offset + tree_add_value(tree, tvb, offset, hf_lw_src_fsid);
            }
            else if (strcmp(msg_type,"BSID") == 0){
                info->src_info->bsid = tvb_get_ipv4(tvb, offset + 1);
                return offset + tree_add_value(tree, tvb, offset, hf_lw_src_bsid);
            }
            else if (strcmp(msg_type,"SHAB") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_src_shab);
            }
            else if (strcmp(msg_type,"LPID") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_src_lpid);
            }
            else if (strcmp(msg_type,"BUSY") == 0 && tvb_get_uint8(tvb, offset) == 0x9){
                proto_item *ti = proto_tree_add_item(tree, hf_lw_busy, tvb, offset + 1, 8, ENC_BIG_ENDIAN);
                if (tvb_get_uint64(tvb, offset + 1, ENC_BIG_ENDIAN) == 0){
                    // free
                    proto_item_append_text(ti, ": Free");
                }
                else {
                    ws_in4_addr console_ip;
                    uint32_t prefix;
                    uint32_t hwid;
                    unsigned fader_num; 
                    char addr_str[16];
                    proto_tree *busy_tree = proto_item_add_subtree(ti, ett_lwadv);
                    proto_tree_add_item_ret_uint(busy_tree, hf_lw_busy_hwid, tvb, offset + 3, 2, ENC_BIG_ENDIAN, &hwid);
                    proto_tree_add_item_ret_uint(busy_tree, hf_lw_busy_prefix, tvb, offset + 7, 2, ENC_BIG_ENDIAN, &prefix);
                    console_ip = (ws_in4_addr)((g_htonl(prefix) >> 16) + g_htonl(hwid)); 
                    ws_inet_ntop4(&console_ip, addr_str, sizeof(addr_str));
                    proto_tree_add_ipv4(busy_tree, hf_lw_busy_ip, tvb, offset + 3, 6, console_ip);
                    proto_item *fader = proto_tree_add_item_ret_uint(busy_tree, hf_lw_busy_fader, tvb, offset + 6, 1, ENC_BIG_ENDIAN, &fader_num);
                    proto_item_set_text(fader, "Fader: %d", fader_num + 1);
                    lw_term_info_t *console = wmem_tree_lookup32(lwadv_nodes, tvb_get_uint16(tvb, offset + 3, ENC_BIG_ENDIAN));
                    bool have_name = false;
                    if (console && console->atrn) have_name = true;
                    proto_item_append_text(ti, " [Console %s, Fader %d]", have_name ? console->atrn : addr_str, fader_num + 1);
                }
                return offset + 9;
            }
            break;
        case SECTION_GPIO:
            uint32_t lpid;
            uint32_t lcid;
            uint32_t state;
            uint32_t mult;
            uint32_t len;
            bool gpi = false;
            bool source_is_new = false;
            proto_item *ti = proto_tree_add_item(tree, hf_lw_gpio, tvb, offset + 1, 5, ENC_NA);
            proto_tree *gpio_tree = proto_item_add_subtree(ti, ett_lwadv);
            proto_item *lpid_item = proto_tree_add_item_ret_uint(gpio_tree, hf_lw_src_lpid, tvb, offset + 1, 2, ENC_BIG_ENDIAN, &lpid);
            if (lpid != 0xFF) {
                if (info->lpid != lpid) source_is_new = true;
                info->lpid = lpid;
            }
            else lpid = info->lpid;
            lw_src_info_t *source = wmem_tree_lookup32(lwadv_sources, lpid);
            lw_term_info_t *term;
            if (source) term = source->term;
            if (source && source->psnm && term && term->atrn){
                proto_item_append_text(lpid_item, " [%s@%s]", source->psnm, term->atrn);
                proto_tree *setup_tree = proto_item_add_subtree(lpid_item, ett_lwadv);
                proto_item *setup_frm = proto_tree_add_uint(setup_tree, hf_lw_src_setup_frm, tvb, 0, 0, source->setup_frame);
                proto_item_set_generated(setup_frm);
            }
            proto_item *lcid_item = proto_tree_add_item_ret_uint(gpio_tree, hf_lw_gpio_lcid, tvb, offset + 3, 1, ENC_BIG_ENDIAN, &lcid);
            if (lcid < 9) lcid = 9-lcid;
            else {
                lcid = 14-lcid;
                gpi = true;
            }
            proto_item_append_text (lcid_item, gpi ? " [GPI Pin %d]" :  " [GPO Pin %d]", lcid);
            proto_item *pmult_item = proto_tree_add_item_ret_uint(gpio_tree, hf_lw_gpio_pmult, tvb, offset + 5, 1, ENC_BIG_ENDIAN, &mult);
            proto_item *state_item = proto_tree_add_item_ret_uint(gpio_tree, hf_lw_gpio_state, tvb, offset + 5, 1, ENC_BIG_ENDIAN, &state);
            proto_item *plen_item = proto_tree_add_item_ret_uint(gpio_tree, hf_lw_gpio_plen, tvb, offset + 5, 1, ENC_BIG_ENDIAN, &len);
            len *= mult ? 20 : 500;
            if (!state && !mult && !len) {
                proto_item_append_text(state_item, " [Ignored]");
                state_item = proto_tree_add_item_ret_uint(gpio_tree, hf_lw_gpio_state2, tvb, offset + 5, 1, ENC_BIG_ENDIAN, &state);
            }
            proto_item_append_text (state_item, " [%s]", state ? "Low" : "High");
            proto_item_append_text (pmult_item, " [%s]", mult ? "20 mS" : "500 mS");
            if (len) proto_item_append_text(plen_item, " [%d mS]", len);
            proto_item_append_text(ti, ": LPID=%d ", lpid);
            if (source_is_new) col_append_fstr(pinfo->cinfo, COL_INFO, "LPID=%d ", lpid);
            if (source && source->psnm && term && term->atrn) {
                proto_item_append_text(ti, "[%s@%s] ", source->psnm, term->atrn);
                if (source_is_new) col_append_fstr(pinfo->cinfo, COL_INFO, "[%s@%s] ", source->psnm, term->atrn);
            }
            proto_item_append_text(ti, "Pin=%s %d State=", gpi ? "GPI" : "GPO", lcid);
            col_append_fstr(pinfo->cinfo, COL_INFO, "Pin=%s %d State=", gpi ? "GPI" : "GPO", lcid);
            if (len) {
                proto_item_append_text(ti, "Pulse ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "Pulse ");
            }
            proto_item_append_text(ti, "%s ", state? "Low" : "High");
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", state? "Low" : "High");
            if (len) {
                proto_item_append_text(ti, "for %dmS ", len);
                col_append_fstr(pinfo->cinfo, COL_INFO, "for %dmS ", len);
            }
            return offset + 6;
            break;

    }
    return offset + dissect_lwadv_unk(tvb, pinfo, tree, offset);
}
static int dissect_lwadv(tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (!validate_header(tvb)) /* This is not an Axia packet */ 
        return 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AXIA");
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_lwadv, tvb, 0, -1, ENC_NA);
    proto_tree *lwadv_tree = proto_item_add_subtree(ti, ett_lwadv);
    proto_tree_add_item(lwadv_tree, hf_lw_magic_num, tvb, 0, 4, ENC_NA);
    proto_tree_add_item(lwadv_tree, hf_lw_seq, tvb, 4, 4, ENC_BIG_ENDIAN);
    int offset = 16;
    dissect_lwadv_msg(tvb, pinfo, lwadv_tree, offset, SECTION_ADV_BASE, NULL);
    return offset;
}
static int dissect_lwgpio(tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (!validate_header(tvb)) /* This is not an Axia packet */ 
        return 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AXIA");
    col_clear(pinfo->cinfo,COL_INFO);
    proto_item *ti = proto_tree_add_item(tree, proto_lwgpio, tvb, 0, -1, ENC_NA);
    proto_tree *lwadv_tree = proto_item_add_subtree(ti, ett_lwadv);
    proto_tree_add_item(lwadv_tree, hf_lw_magic_num, tvb, 0, 4, ENC_NA);
    proto_tree_add_item(lwadv_tree, hf_lw_seq, tvb, 4, 4, ENC_BIG_ENDIAN);
    int offset = 16;
    dissect_lwadv_msg(tvb, pinfo, lwadv_tree, offset, SECTION_GPIO, NULL);
    return offset;
}
static int dissect_lwclock(tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (tvb_captured_length(tvb) != 36)
        return 0;
    uint32_t timestamp;
    uint32_t seq;
    uint32_t type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AXIA");
    col_clear(pinfo->cinfo, COL_INFO);
    proto_item *ti = proto_tree_add_item(tree, proto_lwclock, tvb, 0, -1, ENC_NA);
    proto_tree *lwclock_tree = proto_item_add_subtree(ti, ett_lwadv);
    proto_tree_add_item_ret_uint(lwclock_tree, hf_lw_clock_seq, tvb, 2, 2, ENC_BIG_ENDIAN, &seq);
    proto_tree_add_item_ret_uint(lwclock_tree, hf_lw_clock_samp, tvb, 4, 4, ENC_BIG_ENDIAN, &timestamp);
    proto_tree_add_item(lwclock_tree, hf_lw_clock_fast, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(lwclock_tree, hf_lw_clock_type, tvb, 20, 1, ENC_NA, &type);
    proto_tree_add_item(lwclock_tree, hf_lw_clock_prio, tvb, 27, 1, ENC_NA);
    proto_tree_add_item(lwclock_tree, hf_lw_clock_mac, tvb, 30, 6, ENC_NA);
    
    bool fast_rate = type == 0x0a || type == 0x0b;
    ti = proto_tree_add_boolean(lwclock_tree, hf_lw_clock_rate, tvb, 0, 0, fast_rate);
    proto_item_set_generated(ti);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq=%u, Time=%u", val_to_str_const(type, clocktypenames, "Unknown clock packet"), seq, timestamp);
    return 36;
}
static bool test_lwadv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (cmp_address(&pinfo->net_dst, &advertisement_address))
        return false;
    if (!validate_header(tvb))
        return false;
    if (pinfo->destport != LWADV_PORT)
        return false;
    if (dissect_lwadv(tvb, pinfo, tree, data))
    {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, lwadv_handle);
        return true;
    }
    return false;
}
static bool test_lwgpio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (cmp_address(&pinfo->net_dst, &gpio_address))
        return false;
    if (pinfo->destport != LWGPIO_CONSOLE_PORT && pinfo->destport != LWGPIO_NODE_PORT)
        return false;
    if (!validate_header(tvb))
        return false;
    if (dissect_lwgpio(tvb, pinfo, tree, data))
    {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, lwgpio_handle);
        return true;
    }
    return false;
}
static bool test_lwclock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (cmp_address(&pinfo->net_dst, &fast_clock_address) && cmp_address(&pinfo->net_dst, &slow_clock_address))
        return false;
    if (!cmp_address(&pinfo->net_dst, &fast_clock_address) && pinfo->destport != FAST_CLOCK_PORT)
        return false;
    if (!cmp_address(&pinfo->net_dst, &slow_clock_address) && pinfo->destport != SLOW_CLOCK_PORT)
        return false;
    if (tvb_captured_length(tvb) != 36)
        return false;
    if (tvb_get_uint8(tvb, 0) != 0x90)
        return false;
    if (tvb_get_uint8(tvb, 1) != 0xff)
        return false;
    if (dissect_lwclock(tvb, pinfo, tree, data))
    {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, lwclock_handle);
        return true;
    }
    return false;
}
static bool dissect_lwadv_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return test_lwadv(tvb, pinfo, tree, data);
}
static bool dissect_lwgpio_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return test_lwgpio(tvb, pinfo, tree, data);
}
static bool dissect_lwclock_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return test_lwclock(tvb, pinfo, tree, data);
}
void proto_register_lwadv(void)
{
    static hf_register_info hf[] = {
        { &hf_lw_magic_num,     { "Axia Magic Number",      "axia_adv.magic_number",       FT_NONE,    BASE_NONE,  NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_seq,           { "Sequence",               "axia_adv.seq",                FT_UINT32,  BASE_DEC,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_msg_count,     { "Nested message count",   "axia_adv.msgcount",           FT_UINT8,   BASE_DEC,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_pver,          { "Protocol Version",       "axia_adv.pver",               FT_UINT16,  BASE_DEC,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_advt,          { "Advertisement type",     "axia_adv.advt",               FT_UINT8,   BASE_HEX,   VALS(advtypenames),  0x0,    NULL,   HFILL } },
        { &hf_lw_unk_u8,        { "Unknown Byte",           "axia_adv.unknown",            FT_UINT8,   BASE_HEX,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_unk_u16,       { "Unknown Int",            "axia_adv.unknown",            FT_UINT16,  BASE_DEC,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_unk_u32,       { "Unknown Int",            "axia_adv.unknown",            FT_UINT32,  BASE_DEC,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_unk_data,      { "Unknown Data",           "axia_adv.unknown",            FT_BYTES,   SEP_COLON,  NULL,                0x0,    "",     HFILL } },
        { &hf_lw_unk_str,       { "Unknown String",         "axia_adv.unknown",            FT_STRING,  BASE_NONE,  NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_opcode,        { "Operation",              "axia_adv.opcode",             FT_STRING,  BASE_NONE,  NULL,                0x0,    NULL,   HFILL } },

        { &hf_lw_term,          { "Terminal Information",   "axia_adv.term",               FT_NONE,    BASE_NONE,  NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_term_inip,     { "IP Address",             "axia_adv.term.inip",          FT_IPv4,    BASE_NONE,  NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_term_hwid,     { "Hardware ID",            "axia_adv.term.hwid",          FT_UINT16,  BASE_HEX,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_term_advv,     { "Advertisement Version",  "axia_adv.term.advv",          FT_UINT32,  BASE_DEC,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_term_udpc,     { "UDP Port",               "axia_adv.term.udpc",          FT_UINT16,  BASE_DEC,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_term_nums,     { "Number of Sources",      "axia_adv.term.nums",          FT_UINT16,  BASE_DEC,   NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_term_atrn,     { "Terminal Name",          "axia_adv.term.atrn",          FT_STRING,  BASE_NONE,  NULL,                0x0,    NULL,   HFILL } },
        { &hf_lw_term_type,     { "Type",                   "axia_adv.term.type",          FT_STRING,  BASE_NONE,  NULL,                0x0,    NULL,   HFILL } },

        { &hf_lw_src,           { "Source Information",     "axia_adv.src",                FT_NONE,    BASE_NONE,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_psid,      { "Livewire Source ID",     "axia_adv.src.psid",           FT_UINT32,  BASE_DEC,    NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_shab,      { "Sharable",               "axia_adv.src.shab",           FT_BOOLEAN, BASE_NONE,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_fsid,      { "Multicast address",      "axia_adv.src.fsid",           FT_IPv4,    BASE_NONE,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_bsid,      { "Backfeed address",       "axia_adv.src.bsid",           FT_IPv4,    BASE_NONE,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_psnm,      { "Name",                   "axia_adv.src.psnm",           FT_STRING,  BASE_NONE,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_lpid,      { "Logic Port ID",          "axia_adv.src.lpid",           FT_UINT32,  BASE_DEC,    NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_setup_frm, { "Setup Frame",            "axia_adv.src.setup-frame",    FT_FRAMENUM,BASE_NONE,   NULL,               0x0,    "First frame that advertised this source",   HFILL } },
        { &hf_lw_src_is_mm,     { "Is Backfeed",            "axia_adv.src.is-backfeed",    FT_BOOLEAN, BASE_NONE,   NULL,               0x0,    "Is this source a backfeed from a console?",   HFILL } },

        { &hf_lw_busy,          { "Source Allocation",      "axia_adv.busy",               FT_NONE,    BASE_NONE,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_busy_hwid,     { "Console HWID",           "axia_adv.busy.hwid",          FT_UINT16,  BASE_HEX,    NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_busy_fader,    { "Fader",                  "axia_adv.busy.fader",         FT_UINT8,   BASE_DEC,    NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_busy_ip,       { "Console IP Address",     "axia_adv.busy.ip",            FT_IPv4,    BASE_NONE,   NULL,    0xFFFF0000FFFF,    NULL,   HFILL } },
        { &hf_lw_busy_prefix,   { "Console IP Prefix",      "axia_adv.busy.prefix",        FT_UINT16,  BASE_HEX,    NULL,               0x0,    NULL,   HFILL } },

        { &hf_lw_gpio,          { "GPIO Message",           "axia_gpio",                    FT_NONE,    BASE_NONE,  NULL,                   0x00,   NULL,   HFILL } },
        { &hf_lw_gpio_lcid,     { "Logic Circuit ID",       "axia_gpio.lcid",               FT_UINT8,   BASE_DEC,   NULL,                   0x0F,   NULL,   HFILL } },
        { &hf_lw_gpio_state,    { "Logic Circuit State",    "axia_gpio.state",              FT_UINT8,   BASE_DEC,   NULL,                   0x40,   NULL,   HFILL } },
        { &hf_lw_gpio_state2,   { "Logic Circuit State",    "axia_gpio.state",              FT_UINT8,   BASE_DEC,   NULL,                   0x01,   NULL,   HFILL } },
        { &hf_lw_gpio_pmult,    { "Pulse length multipier", "axia_gpio.pulse_len_mult",     FT_UINT8,   BASE_DEC,   NULL,                   0x80,   NULL,   HFILL } },
        { &hf_lw_gpio_plen,     { "Pulse length",           "axia_gpio.pulse_len",          FT_UINT8,   BASE_DEC,   NULL,                   0x3E,   NULL,   HFILL } },

        { &hf_lw_clock_hwid,    { "Clock Hardware ID",      "axia_clock.hwid",              FT_UINT16,  BASE_HEX,   NULL,                   0x0,    NULL,   HFILL } },
        { &hf_lw_clock_prio,    { "Priority",               "axia_clock.priority",          FT_UINT8,   BASE_DEC,   NULL,                   0x0,    NULL,   HFILL } },
        { &hf_lw_clock_mac,     { "Clock MAC Address",      "axia_clock.mac",               FT_ETHER,   BASE_NONE,  NULL,                   0x0,    NULL,   HFILL } },
        { &hf_lw_clock_samp,    { "Timstamp in samples",    "axia_clock.timestamp",         FT_UINT32,  BASE_DEC,   NULL,                   0x0,    NULL,   HFILL } },
        { &hf_lw_clock_fast,    { "Timstamp in live packets","axia_clock.fast",             FT_UINT32,  BASE_DEC,   NULL,                   0x0,    NULL,   HFILL } },
        { &hf_lw_clock_seq,     { "Sequence",               "axia_clock.seq",               FT_UINT16,  BASE_DEC,   NULL,                   0x0,    NULL,   HFILL } },
        { &hf_lw_clock_rate,    { "Is Fast-Rate Clock",     "axia_clock.rate",              FT_BOOLEAN, BASE_NONE,  NULL,                   0x0,    NULL,   HFILL } },
        { &hf_lw_clock_type,    { "Clock message type",     "axia_clock.type",              FT_UINT8,   BASE_HEX,   VALS(clocktypenames),   0x0,    NULL,   HFILL } },
    };

    static int *ett[] = {
        &ett_lwadv
    };
    
    proto_lwadv = proto_register_protocol("Axia Livewire Source Advertisement", "AXIA Advertisement", "axia_adv");
    proto_lwgpio = proto_register_protocol("Axia Livewire Multicast GPIO", "AXIA GPIO", "axia_gpio");
    proto_lwclock = proto_register_protocol("Axia Livewire Clock", "AXIA Clock", "axia_clock");
    proto_register_field_array(proto_lwadv, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    lwadv_handle = register_dissector_with_description(
        "livewire-adv",
        "Axia Livewire Source Advertisement Protocol",
        dissect_lwadv,
        proto_lwadv
    );
    lwgpio_handle = register_dissector_with_description(
        "livewire-gpio",
        "Axia Livewire GPIO Protocol",
        dissect_lwgpio,
        proto_lwgpio
    );
    lwclock_handle = register_dissector_with_description(
        "livewire-clock",
        "Axia Livewire Clock",
        dissect_lwclock,
        proto_lwclock
    );
    lwadv_sources = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    lwadv_nodes = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    heur_dissector_add("udp", dissect_lwadv_heur_udp, "Axia Livewire Source Advertisement Heuristic Dissector", "axia_adv_heur", proto_lwadv, HEURISTIC_ENABLE);
    heur_dissector_add("udp", dissect_lwgpio_heur_udp, "Axia Livewire GPIO Heuristic Dissector", "axia_gpio_heur", proto_lwgpio, HEURISTIC_ENABLE);
    heur_dissector_add("udp", dissect_lwclock_heur_udp, "Axia Livewire Clock Heuristic Dissector", "axia_clock_heur", proto_lwclock, HEURISTIC_ENABLE);
    dissector_add_for_decode_as("udp.port", lwadv_handle);
    dissector_add_for_decode_as("udp.port", lwgpio_handle);
    dissector_add_for_decode_as("udp.port", lwclock_handle);
}
void proto_reg_handoff_lwadv(void)
{
    uint32_t ip4_addr;
    str_to_ip(FAST_CLOCK_ADDR, &ip4_addr);
    alloc_address_wmem(wmem_epan_scope(), &fast_clock_address, AT_IPv4, sizeof(uint32_t), &ip4_addr);
    str_to_ip(SLOW_CLOCK_ADDR, &ip4_addr);
    alloc_address_wmem(wmem_epan_scope(), &slow_clock_address, AT_IPv4, sizeof(uint32_t), &ip4_addr);
    str_to_ip(LWADV_ADDR, &ip4_addr);
    alloc_address_wmem(wmem_epan_scope(), &advertisement_address, AT_IPv4, sizeof(uint32_t), &ip4_addr);
    str_to_ip(LWGPIO_ADDR, &ip4_addr);
    alloc_address_wmem(wmem_epan_scope(), &gpio_address, AT_IPv4, sizeof(uint32_t), &ip4_addr);
    return;
}
void plugin_register(void)
{
    static proto_plugin plug;
    plug.register_protoinfo = proto_register_lwadv;
    plug.register_handoff = proto_reg_handoff_lwadv;
    proto_register_plugin(&plug);
}