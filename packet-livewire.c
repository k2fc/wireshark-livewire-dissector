#define WS_BUILD_DLL
#include <wireshark.h>
#include <epan/packet.h>
#include <math.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

#define LWADV_PORT 4001 
#define AXIA_MAGIC_NUMBER 0x03000207

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

static int proto_lwadv = -1;

static int hf_lw_seq;
static int hf_lw_opcode;
static int hf_lw_nest;
static int hf_lw_pver;
static int hf_lw_advt;
static int hf_lw_unk_u8;
static int hf_lw_unk_u16;
static int hf_lw_unk_u32;
static int hf_lw_unk_data;
static int hf_lw_unk_str;

static int hf_lw_term_inip;
static int hf_lw_term_advv;
static int hf_lw_term_hwid;
static int hf_lw_term_udpc;
static int hf_lw_term_nums;
static int hf_lw_term_atrn;
static int hf_lw_term_type;

static int hf_lw_src_psid;
static int hf_lw_src_shab;
static int hf_lw_src_fsid;
static int hf_lw_src_bsid;
static int hf_lw_src_psnm;
static int hf_lw_src_lpid;

static int hf_lw_busy;
static int hf_lw_busy_hwid;
static int hf_lw_busy_fader;
static int hf_lw_busy_ip;

static int ett_lwadv;

typedef enum {
    SECTION_BASE,
    SECTION_TERM,
    SECTION_SOURCE,
} adv_section_e;

static dissector_handle_t lwadv_handle;
static const value_string advtypenames[] = {
    { 0x1, "Livewire source advertisement" },
    { 0x2, "Livewire node advertisement" },
    { 0x3, "Livewire source allocation advertisment" },
    { 0, NULL }
};
static char* get_opcode_description(char* opcode)
{
    if (strcmp(opcode,"INDI") == 0)
        return "Value Indication";
    if (strcmp(opcode, "WNRI") == 0)
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
static bool validate_header(tvbuff_t* tvb)
{
    if (tvb_captured_length(tvb) < 16) {
        return false;
    }
    else if (tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN) != AXIA_MAGIC_NUMBER) {
        return false;
    }
    for (int i = 8; i < 16; i++) {
        if (tvb_get_uint8(tvb, i) != 0) {
            return false;
        }
    }
    return true;
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
static ws_in4_addr swap_endianness(ws_in4_addr value){
    return ((value & 0x000000FF) << 24) |
            ((value & 0x0000FF00) << 8) |
            ((value & 0x00FF0000) >> 8) |
            ((value & 0xFF000000) >> 24);
}
static int dissect_lwadv_msg(tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree, int offset, adv_section_e section) {
    char* msg_type = tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII|ENC_NA);
    offset += 4;
    if (get_opcode_description(msg_type)){
        int msg_count = tvb_get_uint8(tvb, offset + 1);
        proto_item *ti = proto_tree_add_item(tree, hf_lw_opcode, tvb, offset - 4, 4, ENC_ASCII | ENC_NA);
        //proto_tree *nest_tree = proto_item_add_subtree(ti, ett_lwadv);
        proto_item_append_text(ti, " (%s)", get_opcode_description(msg_type));
        offset += tree_add_value(tree, tvb, offset, hf_lw_nest);
        for (int i = 0; i < msg_count; i++) {
            increment_dissection_depth(pinfo);
            offset = dissect_lwadv_msg(tvb, pinfo, tree, offset, section);
            decrement_dissection_depth(pinfo);
        }
        return offset;
    }
    switch (section) {
        case SECTION_BASE:
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
                proto_item *ti = proto_tree_add_item(tree, proto_lwadv, tvb, offset - 4, len + 7, ENC_NA);
                proto_tree *term_tree = proto_item_add_subtree(ti, ett_lwadv);
                proto_item_set_text(ti, "Terminal Information");
                increment_dissection_depth(pinfo);
                dissect_lwadv_msg(tvb, pinfo, term_tree, offset + 3, SECTION_TERM);
                decrement_dissection_depth(pinfo);
                return offset + len + 3;
            }
            else if (msg_type[0] == 'S' &&
                msg_type[1] >= '0' && msg_type[1] <= '9' &&
                msg_type[2] >= '0' && msg_type[2] <= '9' &&
                msg_type[3] >= '0' && msg_type[3] <= '9' 
                ){
                int src_num = ((msg_type[1] - '0') * 100) + ((msg_type[2] - '0') * 10) + (msg_type[3] - '0');
                int len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                proto_item *ti = proto_tree_add_item(tree, proto_lwadv, tvb, offset - 4, len + 7, ENC_NA);
                proto_tree *source_tree = proto_item_add_subtree(ti, ett_lwadv);
                proto_item_set_text(ti, "Source %d", src_num);
                increment_dissection_depth(pinfo);
                dissect_lwadv_msg(tvb, pinfo, source_tree, offset + 3, SECTION_SOURCE);
                decrement_dissection_depth(pinfo);
                return offset + len + 3;
            }
            break;
        case SECTION_TERM:
            if (strcmp(msg_type,"INIP") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_inip);
            }
            else if (strcmp(msg_type,"HWID") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_hwid);
            }
            else if (strcmp(msg_type,"ADVV") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_advv);
            }
            else if (strcmp(msg_type,"UDPC") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_udpc);
            }
            else if (strcmp(msg_type,"NUMS") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_nums);
            }
            else if (strcmp(msg_type,"ATRN") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_atrn);
            }
            else if (strcmp(msg_type,"TYPE") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_term_type);
            }
            break;
        case SECTION_SOURCE:
            if (strcmp(msg_type,"PSID") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_src_psid);
            }
            else if (strcmp(msg_type,"PSNM") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_src_psnm);
            }
            else if (strcmp(msg_type,"FSID") == 0){
                return offset + tree_add_value(tree, tvb, offset, hf_lw_src_fsid);
            }
            else if (strcmp(msg_type,"BSID") == 0){
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
                    unsigned fader_num; 
                    char addr_str[15];
                    proto_tree *busy_tree = proto_item_add_subtree(ti, ett_lwadv);
                    proto_tree_add_item_ret_uint(busy_tree, hf_lw_busy_hwid, tvb, offset + 3, 2, ENC_BIG_ENDIAN, &console_ip);
                    //proto_tree_add_item(tree, hf_lw_busy_prefix, tvb, offset + 7, 2, ENC_BIG_ENDIAN);
                    console_ip += (tvb_get_uint16(tvb, offset + 7, ENC_BIG_ENDIAN) << 16);
                    console_ip = swap_endianness(console_ip);
                    ws_inet_ntop4(&console_ip, addr_str, sizeof(addr_str));
                    proto_tree_add_ipv4(busy_tree, hf_lw_busy_ip, tvb, offset + 7, 2, console_ip);
                    proto_item *fader = proto_tree_add_item_ret_uint(busy_tree, hf_lw_busy_fader, tvb, offset + 6, 1, ENC_BIG_ENDIAN, &fader_num);
                    proto_item_set_text(fader, "Fader: %d", fader_num + 1);
                    proto_item_append_text(ti, ": Console %s, Fader %d", addr_str, fader_num + 1);
                }
                return offset + 9;
            }
            break;
    }
    return offset + dissect_lwadv_unk(tvb, pinfo, tree, offset);
}
static int dissect_lwadv(tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (!validate_header(tvb)) /* This is not an Axia packet */ 
        return 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LW-ADV");
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_lwadv, tvb, 0, -1, ENC_NA);
    proto_tree *lwadv_tree = proto_item_add_subtree(ti, ett_lwadv);
    proto_tree_add_item(lwadv_tree, hf_lw_seq, tvb, 4, 4, ENC_BIG_ENDIAN);
    int offset = 16;
    dissect_lwadv_msg(tvb, pinfo, lwadv_tree, offset, SECTION_BASE);
    return offset;
}
void proto_register_lwadv(void)
{
    static hf_register_info hf[] = {
        { &hf_lw_seq,       { "Sequence",               "lwadv.seq",        FT_UINT32,  BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_nest,      { "Nested message count",   "lwadv.nest",       FT_UINT8,   BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_pver,      { "Protocol Version",       "lwadv.pver",       FT_UINT16,  BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_advt,      { "Advertisement type",     "lwadv.advt",       FT_UINT8,   BASE_HEX,   VALS(advtypenames), 0x0,    NULL,   HFILL } },
        { &hf_lw_unk_u8,    { "Unknown Byte",           "lwadv.unknown",    FT_UINT8,   BASE_HEX,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_unk_u16,   { "Unknown Int",            "lwadv.unknown",    FT_UINT16,  BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_unk_u32,   { "Unknown Int",            "lwadv.unknown",    FT_UINT32,  BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_unk_data,  { "Unknown Data",           "lwadv.unknown",    FT_BYTES,   SEP_COLON,  NULL,               0x0,    "",     HFILL } },
        { &hf_lw_unk_str,   { "Unknown String",         "lwadv.unknown",    FT_STRING,  BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_opcode,    { "Operation",              "lwadv.opcode",     FT_STRING,  BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },

        { &hf_lw_term_inip, { "IP Address",             "lwadv.term.inip",  FT_IPv4,    BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_term_hwid, { "Hardware ID",            "lwadv.term.hwid",  FT_UINT16,  BASE_HEX,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_term_advv, { "Advertisement Version",  "lwadv.term.advv",  FT_UINT32,  BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_term_udpc, { "UDP Port",               "lwadv.term.udpc",  FT_UINT16,  BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_term_nums, { "Number of Sources",      "lwadv.term.nums",  FT_UINT16,  BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_term_atrn, { "Terminal Name",          "lwadv.term.atrn",  FT_STRING,  BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_term_type, { "Type",                   "lwadv.term.type",  FT_STRING,  BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },

        { &hf_lw_src_psid,  { "Livewire Source ID",     "lwadv.src.psid",   FT_UINT32,  BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_shab,  { "Sharable",               "lwadv.src.shab",   FT_BOOLEAN, 0,          NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_fsid,  { "Multicast address",      "lwadv.src.fsid",   FT_IPv4,    BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_bsid,  { "Backfeed address",       "lwadv.src.bsid",   FT_IPv4,    BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_psnm,  { "Name",                   "lwadv.src.psnm",   FT_STRING,  BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_src_lpid,  { "Logic Port ID",          "lwadv.src.lpid",   FT_UINT32,  BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },

        { &hf_lw_busy,      { "Source Allocation",      "lwadv.busy",       FT_NONE,    BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_busy_hwid, { "Console HWID",           "lwadv.busy.hwid",  FT_UINT16,  BASE_HEX,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_busy_fader,{ "Fader",                  "lwadv.busy.fader", FT_UINT8,   BASE_DEC,   NULL,               0x0,    NULL,   HFILL } },
        { &hf_lw_busy_ip,   { "Console IP Address",     "lwadv.busy.fader", FT_IPv4,    BASE_NONE,  NULL,               0x0,    NULL,   HFILL } },
    };

    static int *ett[] = {
        &ett_lwadv
    };
    
    proto_lwadv = proto_register_protocol("Livewire Advertisement", "LW-ADV", "lwadv");
    proto_register_field_array(proto_lwadv, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    lwadv_handle = register_dissector_with_description(
        "livewire",
        "Axia Livewire Source Advertisement Protocol",
        dissect_lwadv,
        proto_lwadv
    );
}
void proto_reg_handoff_lwadv(void)
{
    dissector_add_uint("udp.port", 4000, lwadv_handle);
    dissector_add_uint("udp.port", 4001, lwadv_handle);
}
void plugin_register(void)
{
    static proto_plugin plug;
    plug.register_protoinfo = proto_register_lwadv;
    plug.register_handoff = proto_reg_handoff_lwadv;
    proto_register_plugin(&plug);
}