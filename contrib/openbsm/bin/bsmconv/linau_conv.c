/*
 * UPDATE: 2016.07.20 - The time of the most recent sync of the fields and
 * records lists with the audit-linux repositories on GitHub.
 */

#include <sys/types.h>

#include <sys/sbuf.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <bsm/libbsm.h>

#include "linau_common.h"
#include "linau_conv.h"
#include "linau_conv_impl.h"
#include "linau.h"
#include "pjdlog.h"

struct linau_conv_field {
	int	lcf_id;
	union {
		int (*lcf_validate)(const char *);
		nvlist_t *(*lcf_match)(const struct linau_record *);
	};
};

struct linau_conv_token {
	void (*lct_write)(int aurd, const struct linau_record *);
	const struct linau_conv_field *lct_fields[];
};

struct linau_conv_record_type {
	int				 lcrt_id;
	const char			*lcrt_str;
	const struct linau_conv_token	*lcrt_tokens[];
};

/*
 * Helper functions.
 */
static const char *field_name_from_field_name_id(int fieldnameid);
static bool process_id_field(const struct linau_record *record,
    const char *fieldname, const struct linau_conv_field *lcfield,
    uint32_t *idp, size_t *fieldscountp);
/*
 * STYLE: This function might belong to the token generating functions' section.
 */
static token_t *generate_proto_token_text_from_field(
    const struct linau_record *record, const char *fieldname);
static token_t *generate_proto_token_return(const struct linau_record *record,
    const char *fieldname);

/*
 * The lcf_validate validators for the linau_conv_field structure.
 */
/* The standard validators. */
static int linau_conv_is_alphanumeric(const char *field);
static int linau_conv_is_encoded(const char *field);
static int linau_conv_is_numeric(const char *field);
/* The field specific validators. */
static int linau_conv_is_valid_field_res(const char *field);
/* The validators of the whole groups of fields. */
static int linau_conv_is_valid_pid(const char *field);
static int linau_conv_is_valid_uid(const char *field);
/*
 * The lcf_match regex matchers for regex-defined fields like
 * "a[:digit:+](\[[:digit:]+\])?".
 */
static nvlist_t *linau_conv_match_a_execve_syscall(
    const struct linau_record *record);
/*
 * The lct_write functions for the linau_conv_token structure.
 */
static void write_token_path(int aurd, const struct linau_record *record);
static void write_token_process32(int aurd, const struct linau_record *record);
static void write_token_return_from_res(int aurd,
    const struct linau_record *record);

static void linau_conv_process_record(int aurd,
    const struct linau_record *record,
    const struct linau_conv_record_type *lcrectype);
static void linau_conv_write_unprocessed_fields(int aurd,
    const struct linau_record *record,
    const struct linau_conv_record_type *lcrectype);
static void linau_conv_write_token_text(int aurd,
    const struct linau_record *record, const char *name);

/*
 * Fields definitions.
 *
 * Only currently supported fields are not commented out.
 */
/* const static struct linau_conv_field lcfield_undefined = { */
/*         LINAU_FIELD_NAME_UNDEFINED, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_a0 = { */
/*         LINAU_FIELD_NAME_A0, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_a1 = { */
/*         LINAU_FIELD_NAME_A1, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_a2 = { */
/*         LINAU_FIELD_NAME_A2, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_a3 = { */
/*         LINAU_FIELD_NAME_A3, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_a_execve_syscall = {
	LINAU_FIELD_NAME_A_EXECVE_SYSCALL,
	.lcf_match = linau_conv_match_a_execve_syscall
};
/* const static struct linau_conv_field lcfield_acct = { */
/*         LINAU_FIELD_NAME_ACCT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_acl = { */
/*         LINAU_FIELD_NAME_ACL, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_action = { */
/*         LINAU_FIELD_NAME_ACTION, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_added = { */
/*         LINAU_FIELD_NAME_ADDED, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_addr = { */
/*         LINAU_FIELD_NAME_ADDR, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_apparmor = { */
/*         LINAU_FIELD_NAME_APPARMOR, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_arch = { */
/*         LINAU_FIELD_NAME_ARCH, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_argc = { */
/*         LINAU_FIELD_NAME_ARGC, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_audit_backlog_limit = { */
/*         LINAU_FIELD_NAME_AUDIT_BACKLOG_LIMIT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_audit_backlog_wait_time = { */
/*         LINAU_FIELD_NAME_AUDIT_BACKLOG_WAIT_TIME, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_audit_enabled = { */
/*         LINAU_FIELD_NAME_AUDIT_ENABLED, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_audit_failure = { */
/*         LINAU_FIELD_NAME_AUDIT_FAILURE, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_auid = {
	LINAU_FIELD_NAME_AUID,
	.lcf_validate = linau_conv_is_valid_uid
};
/* const static struct linau_conv_field lcfield_banners = { */
/*         LINAU_FIELD_NAME_BANNERS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_bool = { */
/*         LINAU_FIELD_NAME_BOOL, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_bus = { */
/*         LINAU_FIELD_NAME_BUS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_capability = { */
/*         LINAU_FIELD_NAME_CAPABILITY, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cap_fe = { */
/*         LINAU_FIELD_NAME_CAP_FE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cap_fi = { */
/*         LINAU_FIELD_NAME_CAP_FI, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cap_fp = { */
/*         LINAU_FIELD_NAME_CAP_FP, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cap_fver = { */
/*         LINAU_FIELD_NAME_CAP_FVER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cap_pe = { */
/*         LINAU_FIELD_NAME_CAP_PE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cap_pi = { */
/*         LINAU_FIELD_NAME_CAP_PI, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cap_pp = { */
/*         LINAU_FIELD_NAME_CAP_PP, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_category = { */
/*         LINAU_FIELD_NAME_CATEGORY, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cgroup = { */
/*         LINAU_FIELD_NAME_CGROUP, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_changed = { */
/*         LINAU_FIELD_NAME_CHANGED, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cipher = { */
/*         LINAU_FIELD_NAME_CIPHER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_class = { */
/*         LINAU_FIELD_NAME_CLASS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_cmd = { */
/*         LINAU_FIELD_NAME_CMD, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_code = { */
/*         LINAU_FIELD_NAME_CODE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_comm = { */
/*         LINAU_FIELD_NAME_COMM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_compat = { */
/*         LINAU_FIELD_NAME_COMPAT, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_cwd = {
	LINAU_FIELD_NAME_CWD,
	.lcf_validate = linau_conv_is_encoded
};
/* const static struct linau_conv_field lcfield_daddr = { */
/*         LINAU_FIELD_NAME_DADDR, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_data = { */
/*         LINAU_FIELD_NAME_DATA, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_default = { */
/*         LINAU_FIELD_NAME_DEFAULT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_dev = { */
/*         LINAU_FIELD_NAME_DEV, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_dev2 = { */
/*         LINAU_FIELD_NAME_DEV2, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_device = { */
/*         LINAU_FIELD_NAME_DEVICE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_dir = { */
/*         LINAU_FIELD_NAME_DIR, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_direction = { */
/*         LINAU_FIELD_NAME_DIRECTION, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_dmac = { */
/*         LINAU_FIELD_NAME_DMAC, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_dport = { */
/*         LINAU_FIELD_NAME_DPORT, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_egid = {
	LINAU_FIELD_NAME_EGID,
	.lcf_validate = linau_conv_is_valid_uid
};
/* const static struct linau_conv_field lcfield_enforcing = { */
/*         LINAU_FIELD_NAME_ENFORCING, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_entries = { */
/*         LINAU_FIELD_NAME_ENTRIES, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_euid = {
	LINAU_FIELD_NAME_EUID,
	.lcf_validate = linau_conv_is_valid_uid
};
/* const static struct linau_conv_field lcfield_exe = { */
/*         LINAU_FIELD_NAME_EXE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_exit = { */
/*         LINAU_FIELD_NAME_EXIT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_fam = { */
/*         LINAU_FIELD_NAME_FAM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_family = { */
/*         LINAU_FIELD_NAME_FAMILY, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_fd = { */
/*         LINAU_FIELD_NAME_FD, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_file = { */
/*         LINAU_FIELD_NAME_FILE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_flags = { */
/*         LINAU_FIELD_NAME_FLAGS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_fe = { */
/*         LINAU_FIELD_NAME_FE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_feature = { */
/*         LINAU_FIELD_NAME_FEATURE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_fi = { */
/*         LINAU_FIELD_NAME_FI, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_fp = { */
/*         LINAU_FIELD_NAME_FP, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_fp2 = { */
/*         LINAU_FIELD_NAME_FP2, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_format = { */
/*         LINAU_FIELD_NAME_FORMAT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_fsgid = { */
/*         LINAU_FIELD_NAME_FSGID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_fsuid = { */
/*         LINAU_FIELD_NAME_FSUID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_fver = { */
/*         LINAU_FIELD_NAME_FVER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_gid = { */
/*         LINAU_FIELD_NAME_GID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_grantors = { */
/*         LINAU_FIELD_NAME_GRANTORS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_grp = { */
/*         LINAU_FIELD_NAME_GRP, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_hook = { */
/*         LINAU_FIELD_NAME_HOOK, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_hostname = { */
/*         LINAU_FIELD_NAME_HOSTNAME, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_icmp_type = { */
/*         LINAU_FIELD_NAME_ICMP_TYPE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_id = { */
/*         LINAU_FIELD_NAME_ID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_igid = { */
/*         LINAU_FIELD_NAME_IGID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_img = { */
/*         LINAU_FIELD_NAME_IMG, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_inif = { */
/*         LINAU_FIELD_NAME_INIF, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ip = { */
/*         LINAU_FIELD_NAME_IP, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ipid = { */
/*         LINAU_FIELD_NAME_IPID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ino = { */
/*         LINAU_FIELD_NAME_INO, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_inode = { */
/*         LINAU_FIELD_NAME_INODE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_inode_gid = { */
/*         LINAU_FIELD_NAME_INODE_GID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_inode_uid = { */
/*         LINAU_FIELD_NAME_INODE_UID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_invalid_context = { */
/*         LINAU_FIELD_NAME_INVALID_CONTEXT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ioctlcmd = { */
/*         LINAU_FIELD_NAME_IOCTLCMD */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ipx = { */
/*         LINAU_FIELD_NAME_IPX, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_item = { */
/*         LINAU_FIELD_NAME_ITEM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_items = { */
/*         LINAU_FIELD_NAME_ITEMS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_iuid = { */
/*         LINAU_FIELD_NAME_IUID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_kernel = { */
/*         LINAU_FIELD_NAME_KERNEL, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_key = {
	LINAU_FIELD_NAME_KEY,
	.lcf_validate = linau_conv_is_encoded
};
/* const static struct linau_conv_field lcfield_kind = { */
/*         LINAU_FIELD_NAME_KIND, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ksize = { */
/*         LINAU_FIELD_NAME_KSIZE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_laddr = { */
/*         LINAU_FIELD_NAME_LADDR, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_len = { */
/*         LINAU_FIELD_NAME_LEN, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_lport = { */
/*         LINAU_FIELD_NAME_LPORT, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_list = {
	LINAU_FIELD_NAME_LIST,
	.lcf_validate = linau_conv_is_numeric
};
/* const static struct linau_conv_field lcfield_mac = { */
/*         LINAU_FIELD_NAME_MAC, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_macproto = { */
/*         LINAU_FIELD_NAME_MACPROTO, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_maj = { */
/*         LINAU_FIELD_NAME_MAJ, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_major = { */
/*         LINAU_FIELD_NAME_MAJOR, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_minor = { */
/*         LINAU_FIELD_NAME_MINOR, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_mode = { */
/*         LINAU_FIELD_NAME_MODE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_model = { */
/*         LINAU_FIELD_NAME_MODEL, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_msg = {
	LINAU_FIELD_NAME_MSG,
	.lcf_validate = linau_conv_is_alphanumeric
};
/* const static struct linau_conv_field lcfield_nargs = { */
/*         LINAU_FIELD_NAME_NARGS, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_name = {
	LINAU_FIELD_NAME_NAME,
	.lcf_validate = linau_conv_is_encoded
};
/* const static struct linau_conv_field lcfield_nametype = { */
/*         LINAU_FIELD_NAME_NAMETYPE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_net = { */
/*         LINAU_FIELD_NAME_NET, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new = { */
/*         LINAU_FIELD_NAME_NEW, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_chardev = { */
/*         LINAU_FIELD_NAME_NEW_CHARDEV, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_disk = { */
/*         LINAU_FIELD_NAME_NEW_DISK, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_enabled = { */
/*         LINAU_FIELD_NAME_NEW_ENABLED, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_fs = { */
/*         LINAU_FIELD_NAME_NEW_FS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_gid = { */
/*         LINAU_FIELD_NAME_NEW_GID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_level = { */
/*         LINAU_FIELD_NAME_NEW_LEVEL, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_lock = { */
/*         LINAU_FIELD_NAME_NEW_LOCK, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_log_passwd = { */
/*         LINAU_FIELD_NAME_NEW_LOG_PASSWD, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_mem = { */
/*         LINAU_FIELD_NAME_NEW_MEM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_net = { */
/*         LINAU_FIELD_NAME_NEW_NET, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_pe = { */
/*         LINAU_FIELD_NAME_NEW_PE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_pi = { */
/*         LINAU_FIELD_NAME_NEW_PI, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_pp = { */
/*         LINAU_FIELD_NAME_NEW_PP, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_range = { */
/*         LINAU_FIELD_NAME_NEW_RANGE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_rng = { */
/*         LINAU_FIELD_NAME_NEW_RNG, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_role = { */
/*         LINAU_FIELD_NAME_NEW_ROLE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_seuser = { */
/*         LINAU_FIELD_NAME_NEW_SEUSER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_new_vcpu = { */
/*         LINAU_FIELD_NAME_NEW_VCPU, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_nlnk_fam = { */
/*         LINAU_FIELD_NAME_NLNK_FAM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_nlnk_grp = { */
/*         LINAU_FIELD_NAME_NLNK_GRP, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_nlnk_pid = { */
/*         LINAU_FIELD_NAME_NLNK_PID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_oauid = { */
/*         LINAU_FIELD_NAME_OAUID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_obj = { */
/*         LINAU_FIELD_NAME_OBJ, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_obj_gid = { */
/*         LINAU_FIELD_NAME_OBJ_GID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_obj_uid = { */
/*         LINAU_FIELD_NAME_OBJ_UID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_oflag = { */
/*         LINAU_FIELD_NAME_OFLAG, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ogid = { */
/*         LINAU_FIELD_NAME_OGID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ocomm = { */
/*         LINAU_FIELD_NAME_OCOMM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old = { */
/*         LINAU_FIELD_NAME_OLD, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old2 = { */
/*         LINAU_FIELD_NAME_OLD2, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_auid = { */
/*         LINAU_FIELD_NAME_OLD_AUID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_chardev = { */
/*         LINAU_FIELD_NAME_OLD_CHARDEV, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_disk = { */
/*         LINAU_FIELD_NAME_OLD_DISK, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_enabled = { */
/*         LINAU_FIELD_NAME_OLD_ENABLED, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_enforcing = { */
/*         LINAU_FIELD_NAME_OLD_ENFORCING, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_fs = { */
/*         LINAU_FIELD_NAME_OLD_FS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_level = { */
/*         LINAU_FIELD_NAME_OLD_LEVEL, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_lock = { */
/*         LINAU_FIELD_NAME_OLD_LOCK, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_log_passwd = { */
/*         LINAU_FIELD_NAME_OLD_LOG_PASSWD, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_mem = { */
/*         LINAU_FIELD_NAME_OLD_MEM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_net = { */
/*         LINAU_FIELD_NAME_OLD_NET, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_pe = { */
/*         LINAU_FIELD_NAME_OLD_PE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_pi = { */
/*         LINAU_FIELD_NAME_OLD_PI, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_pp = { */
/*         LINAU_FIELD_NAME_OLD_PP, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_prom = { */
/*         LINAU_FIELD_NAME_OLD_PROM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_range = { */
/*         LINAU_FIELD_NAME_OLD_RANGE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_rng = { */
/*         LINAU_FIELD_NAME_OLD_RNG, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_role = { */
/*         LINAU_FIELD_NAME_OLD_ROLE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_ses = { */
/*         LINAU_FIELD_NAME_OLD_SES, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_seuser = { */
/*         LINAU_FIELD_NAME_OLD_SEUSER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_val = { */
/*         LINAU_FIELD_NAME_OLD_VAL, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_old_vcpu = { */
/*         LINAU_FIELD_NAME_OLD_VCPU, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_op = {
	LINAU_FIELD_NAME_OP,
	.lcf_validate = linau_conv_is_alphanumeric
};
/* const static struct linau_conv_field lcfield_opid = { */
/*         LINAU_FIELD_NAME_OPID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_oses = { */
/*         LINAU_FIELD_NAME_OSES, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ouid = { */
/*         LINAU_FIELD_NAME_OUID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_outif = { */
/*         LINAU_FIELD_NAME_OUTIF, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_parent = { */
/*         LINAU_FIELD_NAME_PARENT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_path = { */
/*         LINAU_FIELD_NAME_PATH, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_per = { */
/*         LINAU_FIELD_NAME_PER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_perm = { */
/*         LINAU_FIELD_NAME_PERM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_perm_mask = { */
/*         LINAU_FIELD_NAME_PERM_MASK, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_permissive = { */
/*         LINAU_FIELD_NAME_PERMISSIVE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_pfs = { */
/*         LINAU_FIELD_NAME_PFS, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_pid = {
	LINAU_FIELD_NAME_PID,
	.lcf_validate = linau_conv_is_valid_pid
};
/* const static struct linau_conv_field lcfield_ppid = { */
/*         LINAU_FIELD_NAME_PPID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_printer = { */
/*         LINAU_FIELD_NAME_PRINTER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_prom = { */
/*         LINAU_FIELD_NAME_PROM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_proctitle = { */
/*         LINAU_FIELD_NAME_PROCTITLE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_proto = { */
/*         LINAU_FIELD_NAME_PROTO, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_qbytes = { */
/*         LINAU_FIELD_NAME_QBYTES, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_range = { */
/*         LINAU_FIELD_NAME_RANGE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_rdev = { */
/*         LINAU_FIELD_NAME_RDEV, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_reason = { */
/*         LINAU_FIELD_NAME_REASON, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_removed = { */
/*         LINAU_FIELD_NAME_REMOVED, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_res = {
	LINAU_FIELD_NAME_RES,
	.lcf_validate = linau_conv_is_valid_field_res
};
/* const static struct linau_conv_field lcfield_resrc = { */
/*         LINAU_FIELD_NAME_RESRC, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_result = { */
/*         LINAU_FIELD_NAME_RESULT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_role = { */
/*         LINAU_FIELD_NAME_ROLE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_rport = { */
/*         LINAU_FIELD_NAME_RPORT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_saddr = { */
/*         LINAU_FIELD_NAME_SADDR, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_sauid = { */
/*         LINAU_FIELD_NAME_SAUID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_scontext = { */
/*         LINAU_FIELD_NAME_SCONTEXT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_selected = { */
/*         LINAU_FIELD_NAME_SELECTED, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_seperm = { */
/*         LINAU_FIELD_NAME_SEPERM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_seqno = { */
/*         LINAU_FIELD_NAME_SEQNO, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_seperms = { */
/*         LINAU_FIELD_NAME_SEPERMS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_seresult = { */
/*         LINAU_FIELD_NAME_SERESULT, */
/*         NULL */
/* }; */
const static struct linau_conv_field lcfield_ses = {
	LINAU_FIELD_NAME_SES,
	.lcf_validate = linau_conv_is_valid_pid
};
/* const static struct linau_conv_field lcfield_seuser = { */
/*         LINAU_FIELD_NAME_SEUSER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_sgid = { */
/*         LINAU_FIELD_NAME_SGID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_sig = { */
/*         LINAU_FIELD_NAME_SIG, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_sigev_signo = { */
/*         LINAU_FIELD_NAME_SIGEV_SIGNO, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_smac = { */
/*         LINAU_FIELD_NAME_SMAC, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_spid = { */
/*         LINAU_FIELD_NAME_SPID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_sport = { */
/*         LINAU_FIELD_NAME_SPORT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_state = { */
/*         LINAU_FIELD_NAME_STATE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_subj = { */
/*         LINAU_FIELD_NAME_SUBJ, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_success = { */
/*         LINAU_FIELD_NAME_SUCCESS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_suid = { */
/*         LINAU_FIELD_NAME_SUID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_syscall = { */
/*         LINAU_FIELD_NAME_SYSCALL, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_table = { */
/*         LINAU_FIELD_NAME_TABLE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_tclass = { */
/*         LINAU_FIELD_NAME_TCLASS, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_tcontext = { */
/*         LINAU_FIELD_NAME_TCONTEXT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_terminal = { */
/*         LINAU_FIELD_NAME_TERMINAL, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_tty = { */
/*         LINAU_FIELD_NAME_TTY, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_type = { */
/*         LINAU_FIELD_NAME_TYPE, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_uid = { */
/*         LINAU_FIELD_NAME_UID, */
/*         linau_conv_is_numeric */
/* }; */
/* const static struct linau_conv_field lcfield_unit = { */
/*         LINAU_FIELD_NAME_UNIT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_uri = { */
/*         LINAU_FIELD_NAME_URI, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_user = { */
/*         LINAU_FIELD_NAME_USER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_uuid = { */
/*         LINAU_FIELD_NAME_UUID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_val = { */
/*         LINAU_FIELD_NAME_VAL, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_ver = { */
/*         LINAU_FIELD_NAME_VER, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_virt = { */
/*         LINAU_FIELD_NAME_VIRT, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_vm = { */
/*         LINAU_FIELD_NAME_VM, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_vm_ctx = { */
/*         LINAU_FIELD_NAME_VM_CTX, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_vm_pid = { */
/*         LINAU_FIELD_NAME_VM_PID, */
/*         NULL */
/* }; */
/* const static struct linau_conv_field lcfield_watch = { */
/*         LINAU_FIELD_NAME_WATCH, */
/*         NULL */
/* }; */

/*
 * Tokens definitions.
 *
 * Rules for putting fields in linau_conv_token structures:
 * - Fields are required by the functions generating tokens, like au_to_text(3)
 *   (see au_token(3)).
 */
/*
 * This token is assuming that cwd and name fields does not come in one record.
 * See the write_token_path function to see which token is treated as the
 * primary source of the path in case there are both the cwd and the name
 * fields.
 */
const static struct linau_conv_token lctoken_path = {
	write_token_path,
	{
		&lcfield_cwd,
		&lcfield_name,
		NULL
	}
};
/*
 * XXX: I cannot distinguish when it is better to use the process token
 * and when the subject token.  I'll use the process token whenever I hesitate.
 */
const static struct linau_conv_token lctoken_process32 = {
	write_token_process32,
	{
		/*
		 * XXX: This field is not audit user id according to the
		 * documentation.
		 */
		/* &lcfield_auid, */
		&lcfield_egid,
		&lcfield_euid,
		&lcfield_pid,
		&lcfield_ses,
		NULL
	}
};
/*
 * This lctoken applies only to the res field. It does not cover the case
 * of the usage of a synonymous result field.
 */
const static struct linau_conv_token lctoken_return_from_res = {
	write_token_return_from_res,
	{
		&lcfield_res,
		NULL
	}
};

/*
 * Record types definitions.
 * STYLE: How about a define to add & before every object and a NULL at the end?
 */
const static struct linau_conv_record_type lcrectype_undefined = {
	LINAU_TYPE_UNDEFINED,
	LINAU_TYPE_UNDEFINED_STR,
	{ NULL }
};
/* const static struct linau_conv_record_type lcrectype_get = { */
/*         LINAU_TYPE_GET, */
/*         LINAU_TYPE_GET_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_set = { */
/*         LINAU_TYPE_SET, */
/*         LINAU_TYPE_SET_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_list = { */
/*         LINAU_TYPE_LIST, */
/*         LINAU_TYPE_LIST_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_add = { */
/*         LINAU_TYPE_ADD, */
/*         LINAU_TYPE_ADD_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_del = { */
/*         LINAU_TYPE_DEL, */
/*         LINAU_TYPE_DEL_STR, */
/*         { NULL } */
/* }; */
const static struct linau_conv_record_type lcrectype_user = {
	LINAU_TYPE_USER,
	LINAU_TYPE_USER_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_login = {
	LINAU_TYPE_LOGIN,
	LINAU_TYPE_LOGIN_STR,
	{
		&lctoken_process32,
		NULL
	}
};
/* const static struct linau_conv_record_type lcrectype_signal_info = { */
/*         LINAU_TYPE_SIGNAL_INFO, */
/*         LINAU_TYPE_SIGNAL_INFO_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_add_rule = { */
/*         LINAU_TYPE_ADD_RULE, */
/*         LINAU_TYPE_ADD_RULE_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_del_rule = { */
/*         LINAU_TYPE_DEL_RULE, */
/*         LINAU_TYPE_DEL_RULE_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_list_rules = { */
/*         LINAU_TYPE_LIST_RULES, */
/*         LINAU_TYPE_LIST_RULES_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_trim = { */
/*         LINAU_TYPE_TRIM, */
/*         LINAU_TYPE_TRIM_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_make_equiv = { */
/*         LINAU_TYPE_MAKE_EQUIV, */
/*         LINAU_TYPE_MAKE_EQUIV_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_tty_get = { */
/*         LINAU_TYPE_TTY_GET, */
/*         LINAU_TYPE_TTY_GET_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_tty_set = { */
/*         LINAU_TYPE_TTY_SET, */
/*         LINAU_TYPE_TTY_SET_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_set_feature = { */
/*         LINAU_TYPE_SET_FEATURE, */
/*         LINAU_TYPE_SET_FEATURE_STR, */
/*         { NULL } */
/* }; */
/* const static struct linau_conv_record_type lcrectype_get_feature = { */
/*         LINAU_TYPE_GET_FEATURE, */
/*         LINAU_TYPE_GET_FEATURE_STR, */
/*         { NULL } */
/* }; */
const static struct linau_conv_record_type lcrectype_user_auth = {
	LINAU_TYPE_USER_AUTH,
	LINAU_TYPE_USER_AUTH_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_user_acct = {
	LINAU_TYPE_USER_ACCT,
	LINAU_TYPE_USER_ACCT_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_user_mgmt = {
	LINAU_TYPE_USER_MGMT,
	LINAU_TYPE_USER_MGMT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_cred_acq = {
	LINAU_TYPE_CRED_ACQ,
	LINAU_TYPE_CRED_ACQ_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_cred_disp = {
	LINAU_TYPE_CRED_DISP,
	LINAU_TYPE_CRED_DISP_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_user_start = {
	LINAU_TYPE_USER_START,
	LINAU_TYPE_USER_START_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_user_end = {
	LINAU_TYPE_USER_END,
	LINAU_TYPE_USER_END_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_user_avc = {
	LINAU_TYPE_USER_AVC,
	LINAU_TYPE_USER_AVC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_chauthtok = {
	LINAU_TYPE_USER_CHAUTHTOK,
	LINAU_TYPE_USER_CHAUTHTOK_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_err = {
	LINAU_TYPE_USER_ERR,
	LINAU_TYPE_USER_ERR_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_cred_refr = {
	LINAU_TYPE_CRED_REFR,
	LINAU_TYPE_CRED_REFR_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_usys_config = {
	LINAU_TYPE_USYS_CONFIG,
	LINAU_TYPE_USYS_CONFIG_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_login = {
	LINAU_TYPE_USER_LOGIN,
	LINAU_TYPE_USER_LOGIN_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_user_logout = {
	LINAU_TYPE_USER_LOGOUT,
	LINAU_TYPE_USER_LOGOUT_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_add_user = {
	LINAU_TYPE_ADD_USER,
	LINAU_TYPE_ADD_USER_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_del_user = {
	LINAU_TYPE_DEL_USER,
	LINAU_TYPE_DEL_USER_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_add_group = {
	LINAU_TYPE_ADD_GROUP,
	LINAU_TYPE_ADD_GROUP_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_del_group = {
	LINAU_TYPE_DEL_GROUP,
	LINAU_TYPE_DEL_GROUP_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_dac_check = {
	LINAU_TYPE_DAC_CHECK,
	LINAU_TYPE_DAC_CHECK_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_chgrp_id = {
	LINAU_TYPE_CHGRP_ID,
	LINAU_TYPE_CHGRP_ID_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_test = {
	LINAU_TYPE_TEST,
	LINAU_TYPE_TEST_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_trusted_app = {
	LINAU_TYPE_TRUSTED_APP,
	LINAU_TYPE_TRUSTED_APP_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_selinux_err = {
	LINAU_TYPE_USER_SELINUX_ERR,
	LINAU_TYPE_USER_SELINUX_ERR_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_cmd = {
	LINAU_TYPE_USER_CMD,
	LINAU_TYPE_USER_CMD_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_user_tty = {
	LINAU_TYPE_USER_TTY,
	LINAU_TYPE_USER_TTY_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_chuser_id = {
	LINAU_TYPE_CHUSER_ID,
	LINAU_TYPE_CHUSER_ID_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_grp_auth = {
	LINAU_TYPE_GRP_AUTH,
	LINAU_TYPE_GRP_AUTH_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_check = {
	LINAU_TYPE_MAC_CHECK,
	LINAU_TYPE_MAC_CHECK_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_acct_lock = {
	LINAU_TYPE_ACCT_LOCK,
	LINAU_TYPE_ACCT_LOCK_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_acct_unlock = {
	LINAU_TYPE_ACCT_UNLOCK,
	LINAU_TYPE_ACCT_UNLOCK_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_system_boot = {
	LINAU_TYPE_SYSTEM_BOOT,
	LINAU_TYPE_SYSTEM_BOOT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_system_shutdown = {
	LINAU_TYPE_SYSTEM_SHUTDOWN,
	LINAU_TYPE_SYSTEM_SHUTDOWN_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_system_runlevel = {
	LINAU_TYPE_SYSTEM_RUNLEVEL,
	LINAU_TYPE_SYSTEM_RUNLEVEL_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_service_start = {
	LINAU_TYPE_SERVICE_START,
	LINAU_TYPE_SERVICE_START_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_service_stop = {
	LINAU_TYPE_SERVICE_STOP,
	LINAU_TYPE_SERVICE_STOP_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_grp_mgmt = {
	LINAU_TYPE_GRP_MGMT,
	LINAU_TYPE_GRP_MGMT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_grp_chauthtok = {
	LINAU_TYPE_GRP_CHAUTHTOK,
	LINAU_TYPE_GRP_CHAUTHTOK_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_daemon_start = {
	LINAU_TYPE_DAEMON_START,
	LINAU_TYPE_DAEMON_START_STR,
	{
		&lctoken_process32,
		&lctoken_return_from_res,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_daemon_end = {
	LINAU_TYPE_DAEMON_END,
	LINAU_TYPE_DAEMON_END_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_daemon_abort = {
	LINAU_TYPE_DAEMON_ABORT,
	LINAU_TYPE_DAEMON_ABORT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_daemon_config = {
	LINAU_TYPE_DAEMON_CONFIG,
	LINAU_TYPE_DAEMON_CONFIG_STR,
	{ NULL }
};
/* const static struct linau_conv_record_type lcrectype_daemon_reconfig = { */
/*         LINAU_TYPE_DAEMON_RECONFIG, */
/*         LINAU_TYPE_DAEMON_RECONFIG_STR, */
/*         { NULL } */
/* }; */
const static struct linau_conv_record_type lcrectype_daemon_rotate = {
	LINAU_TYPE_DAEMON_ROTATE,
	LINAU_TYPE_DAEMON_ROTATE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_daemon_resume = {
	LINAU_TYPE_DAEMON_RESUME,
	LINAU_TYPE_DAEMON_RESUME_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_daemon_accept = {
	LINAU_TYPE_DAEMON_ACCEPT,
	LINAU_TYPE_DAEMON_ACCEPT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_daemon_close = {
	LINAU_TYPE_DAEMON_CLOSE,
	LINAU_TYPE_DAEMON_CLOSE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_daemon_err = {
	LINAU_TYPE_DAEMON_ERR,
	LINAU_TYPE_DAEMON_ERR_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_syscall = {
	LINAU_TYPE_SYSCALL,
	LINAU_TYPE_SYSCALL_STR,
	{ NULL }
};
/* const static struct linau_conv_record_type lcrectype_fs_watch = { */
/*         LINAU_TYPE_FS_WATCH, */
/*         LINAU_TYPE_FS_WATCH_STR, */
/*         { NULL } */
/* }; */
const static struct linau_conv_record_type lcrectype_path = {
	LINAU_TYPE_PATH,
	LINAU_TYPE_PATH_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_ipc = {
	LINAU_TYPE_IPC,
	LINAU_TYPE_IPC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_socketcall = {
	LINAU_TYPE_SOCKETCALL,
	LINAU_TYPE_SOCKETCALL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_config_change = {
	LINAU_TYPE_CONFIG_CHANGE,
	LINAU_TYPE_CONFIG_CHANGE_STR,
	{
		&lctoken_process32,
		&lctoken_return_from_res,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_sockaddr = {
	LINAU_TYPE_SOCKADDR,
	LINAU_TYPE_SOCKADDR_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_cwd = {
	LINAU_TYPE_CWD,
	LINAU_TYPE_CWD_STR,
	{
		&lctoken_path,
		NULL
	}
};
/* const static struct linau_conv_record_type lcrectype_fs_inode = { */
/*         LINAU_TYPE_FS_INODE, */
/*         LINAU_TYPE_FS_INODE_STR, */
/*         { NULL } */
/* }; */
const static struct linau_conv_record_type lcrectype_execve = {
	LINAU_TYPE_EXECVE,
	LINAU_TYPE_EXECVE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_ipc_set_perm = {
	LINAU_TYPE_IPC_SET_PERM,
	LINAU_TYPE_IPC_SET_PERM_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mq_open = {
	LINAU_TYPE_MQ_OPEN,
	LINAU_TYPE_MQ_OPEN_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mq_sendrecv = {
	LINAU_TYPE_MQ_SENDRECV,
	LINAU_TYPE_MQ_SENDRECV_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mq_notify = {
	LINAU_TYPE_MQ_NOTIFY,
	LINAU_TYPE_MQ_NOTIFY_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mq_getsetattr = {
	LINAU_TYPE_MQ_GETSETATTR,
	LINAU_TYPE_MQ_GETSETATTR_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_kernel_other = {
	LINAU_TYPE_KERNEL_OTHER,
	LINAU_TYPE_KERNEL_OTHER_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_fd_pair = {
	LINAU_TYPE_FD_PAIR,
	LINAU_TYPE_FD_PAIR_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_obj_pid = {
	LINAU_TYPE_OBJ_PID,
	LINAU_TYPE_OBJ_PID_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_tty = {
	LINAU_TYPE_TTY,
	LINAU_TYPE_TTY_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_eoe = {
	LINAU_TYPE_EOE,
	LINAU_TYPE_EOE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_bprm_fcaps = {
	LINAU_TYPE_BPRM_FCAPS,
	LINAU_TYPE_BPRM_FCAPS_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_capset = {
	LINAU_TYPE_CAPSET,
	LINAU_TYPE_CAPSET_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mmap = {
	LINAU_TYPE_MMAP,
	LINAU_TYPE_MMAP_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_netfilter_pkt = {
	LINAU_TYPE_NETFILTER_PKT,
	LINAU_TYPE_NETFILTER_PKT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_netfilter_cfg = {
	LINAU_TYPE_NETFILTER_CFG,
	LINAU_TYPE_NETFILTER_CFG_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_seccomp = {
	LINAU_TYPE_SECCOMP,
	LINAU_TYPE_SECCOMP_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_proctitle = {
	LINAU_TYPE_PROCTITLE,
	LINAU_TYPE_PROCTITLE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_feature_change = {
	LINAU_TYPE_FEATURE_CHANGE,
	LINAU_TYPE_FEATURE_CHANGE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_avc = {
	LINAU_TYPE_AVC,
	LINAU_TYPE_AVC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_selinux_err = {
	LINAU_TYPE_SELINUX_ERR,
	LINAU_TYPE_SELINUX_ERR_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_avc_path = {
	LINAU_TYPE_AVC_PATH,
	LINAU_TYPE_AVC_PATH_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_policy_load = {
	LINAU_TYPE_MAC_POLICY_LOAD,
	LINAU_TYPE_MAC_POLICY_LOAD_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_status = {
	LINAU_TYPE_MAC_STATUS,
	LINAU_TYPE_MAC_STATUS_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_config_change = {
	LINAU_TYPE_MAC_CONFIG_CHANGE,
	LINAU_TYPE_MAC_CONFIG_CHANGE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_unlbl_allow = {
	LINAU_TYPE_MAC_UNLBL_ALLOW,
	LINAU_TYPE_MAC_UNLBL_ALLOW_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_cipsov4_add = {
	LINAU_TYPE_MAC_CIPSOV4_ADD,
	LINAU_TYPE_MAC_CIPSOV4_ADD_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_cipsov4_del = {
	LINAU_TYPE_MAC_CIPSOV4_DEL,
	LINAU_TYPE_MAC_CIPSOV4_DEL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_map_add = {
	LINAU_TYPE_MAC_MAP_ADD,
	LINAU_TYPE_MAC_MAP_ADD_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_map_del = {
	LINAU_TYPE_MAC_MAP_DEL,
	LINAU_TYPE_MAC_MAP_DEL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_ipsec_addsa = {
	LINAU_TYPE_MAC_IPSEC_ADDSA,
	LINAU_TYPE_MAC_IPSEC_ADDSA_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_ipsec_delsa = {
	LINAU_TYPE_MAC_IPSEC_DELSA,
	LINAU_TYPE_MAC_IPSEC_DELSA_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_ipsec_addspd = {
	LINAU_TYPE_MAC_IPSEC_ADDSPD,
	LINAU_TYPE_MAC_IPSEC_ADDSPD_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_ipsec_delspd = {
	LINAU_TYPE_MAC_IPSEC_DELSPD,
	LINAU_TYPE_MAC_IPSEC_DELSPD_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_ipsec_event = {
	LINAU_TYPE_MAC_IPSEC_EVENT,
	LINAU_TYPE_MAC_IPSEC_EVENT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_unlbl_stcadd = {
	LINAU_TYPE_MAC_UNLBL_STCADD,
	LINAU_TYPE_MAC_UNLBL_STCADD_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_mac_unlbl_stcdel = {
	LINAU_TYPE_MAC_UNLBL_STCDEL,
	LINAU_TYPE_MAC_UNLBL_STCDEL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_promiscuous = {
	LINAU_TYPE_ANOM_PROMISCUOUS,
	LINAU_TYPE_ANOM_PROMISCUOUS_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_abend = {
	LINAU_TYPE_ANOM_ABEND,
	LINAU_TYPE_ANOM_ABEND_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_link = {
	LINAU_TYPE_ANOM_LINK,
	LINAU_TYPE_ANOM_LINK_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_integrity_data = {
	LINAU_TYPE_INTEGRITY_DATA,
	LINAU_TYPE_INTEGRITY_DATA_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_integrity_metadata = {
	LINAU_TYPE_INTEGRITY_METADATA,
	LINAU_TYPE_INTEGRITY_METADATA_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_integrity_status = {
	LINAU_TYPE_INTEGRITY_STATUS,
	LINAU_TYPE_INTEGRITY_STATUS_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_integrity_hash = {
	LINAU_TYPE_INTEGRITY_HASH,
	LINAU_TYPE_INTEGRITY_HASH_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_integrity_pcr = {
	LINAU_TYPE_INTEGRITY_PCR,
	LINAU_TYPE_INTEGRITY_PCR_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_integrity_rule = {
	LINAU_TYPE_INTEGRITY_RULE,
	LINAU_TYPE_INTEGRITY_RULE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_aa = {
	LINAU_TYPE_AA,
	LINAU_TYPE_AA_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_apparmor_audit = {
	LINAU_TYPE_APPARMOR_AUDIT,
	LINAU_TYPE_APPARMOR_AUDIT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_apparmor_allowed = {
	LINAU_TYPE_APPARMOR_ALLOWED,
	LINAU_TYPE_APPARMOR_ALLOWED_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_apparmor_denied = {
	LINAU_TYPE_APPARMOR_DENIED,
	LINAU_TYPE_APPARMOR_DENIED_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_apparmor_hint = {
	LINAU_TYPE_APPARMOR_HINT,
	LINAU_TYPE_APPARMOR_HINT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_apparmor_status = {
	LINAU_TYPE_APPARMOR_STATUS,
	LINAU_TYPE_APPARMOR_STATUS_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_apparmor_error = {
	LINAU_TYPE_APPARMOR_ERROR,
	LINAU_TYPE_APPARMOR_ERROR_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_kernel = {
	LINAU_TYPE_KERNEL,
	LINAU_TYPE_KERNEL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_login_failures = {
	LINAU_TYPE_ANOM_LOGIN_FAILURES,
	LINAU_TYPE_ANOM_LOGIN_FAILURES_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_login_time = {
	LINAU_TYPE_ANOM_LOGIN_TIME,
	LINAU_TYPE_ANOM_LOGIN_TIME_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_login_sessions = {
	LINAU_TYPE_ANOM_LOGIN_SESSIONS,
	LINAU_TYPE_ANOM_LOGIN_SESSIONS_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_login_acct = {
	LINAU_TYPE_ANOM_LOGIN_ACCT,
	LINAU_TYPE_ANOM_LOGIN_ACCT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_login_location = {
	LINAU_TYPE_ANOM_LOGIN_LOCATION,
	LINAU_TYPE_ANOM_LOGIN_LOCATION_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_max_dac = {
	LINAU_TYPE_ANOM_MAX_DAC,
	LINAU_TYPE_ANOM_MAX_DAC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_max_mac = {
	LINAU_TYPE_ANOM_MAX_MAC,
	LINAU_TYPE_ANOM_MAX_MAC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_amtu_fail = {
	LINAU_TYPE_ANOM_AMTU_FAIL,
	LINAU_TYPE_ANOM_AMTU_FAIL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_rbac_fail = {
	LINAU_TYPE_ANOM_RBAC_FAIL,
	LINAU_TYPE_ANOM_RBAC_FAIL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_rbac_integrity_fail = {
	LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL,
	LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_crypto_fail = {
	LINAU_TYPE_ANOM_CRYPTO_FAIL,
	LINAU_TYPE_ANOM_CRYPTO_FAIL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_access_fs = {
	LINAU_TYPE_ANOM_ACCESS_FS,
	LINAU_TYPE_ANOM_ACCESS_FS_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_exec = {
	LINAU_TYPE_ANOM_EXEC,
	LINAU_TYPE_ANOM_EXEC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_mk_exec = {
	LINAU_TYPE_ANOM_MK_EXEC,
	LINAU_TYPE_ANOM_MK_EXEC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_add_acct = {
	LINAU_TYPE_ANOM_ADD_ACCT,
	LINAU_TYPE_ANOM_ADD_ACCT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_del_acct = {
	LINAU_TYPE_ANOM_DEL_ACCT,
	LINAU_TYPE_ANOM_DEL_ACCT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_mod_acct = {
	LINAU_TYPE_ANOM_MOD_ACCT,
	LINAU_TYPE_ANOM_MOD_ACCT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_anom_root_trans = {
	LINAU_TYPE_ANOM_ROOT_TRANS,
	LINAU_TYPE_ANOM_ROOT_TRANS_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_anomaly = {
	LINAU_TYPE_RESP_ANOMALY,
	LINAU_TYPE_RESP_ANOMALY_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_alert = {
	LINAU_TYPE_RESP_ALERT,
	LINAU_TYPE_RESP_ALERT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_kill_proc = {
	LINAU_TYPE_RESP_KILL_PROC,
	LINAU_TYPE_RESP_KILL_PROC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_term_access = {
	LINAU_TYPE_RESP_TERM_ACCESS,
	LINAU_TYPE_RESP_TERM_ACCESS_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_acct_remote = {
	LINAU_TYPE_RESP_ACCT_REMOTE,
	LINAU_TYPE_RESP_ACCT_REMOTE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_acct_lock_timed = {
	LINAU_TYPE_RESP_ACCT_LOCK_TIMED,
	LINAU_TYPE_RESP_ACCT_LOCK_TIMED_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_acct_unlock_timed = {
	LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED,
	LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_acct_lock = {
	LINAU_TYPE_RESP_ACCT_LOCK,
	LINAU_TYPE_RESP_ACCT_LOCK_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_term_lock = {
	LINAU_TYPE_RESP_TERM_LOCK,
	LINAU_TYPE_RESP_TERM_LOCK_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_sebool = {
	LINAU_TYPE_RESP_SEBOOL,
	LINAU_TYPE_RESP_SEBOOL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_exec = {
	LINAU_TYPE_RESP_EXEC,
	LINAU_TYPE_RESP_EXEC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_single = {
	LINAU_TYPE_RESP_SINGLE,
	LINAU_TYPE_RESP_SINGLE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_resp_halt = {
	LINAU_TYPE_RESP_HALT,
	LINAU_TYPE_RESP_HALT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_role_change = {
	LINAU_TYPE_USER_ROLE_CHANGE,
	LINAU_TYPE_USER_ROLE_CHANGE_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_role_assign = {
	LINAU_TYPE_ROLE_ASSIGN,
	LINAU_TYPE_ROLE_ASSIGN_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_role_remove = {
	LINAU_TYPE_ROLE_REMOVE,
	LINAU_TYPE_ROLE_REMOVE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_label_override = {
	LINAU_TYPE_LABEL_OVERRIDE,
	LINAU_TYPE_LABEL_OVERRIDE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_label_level_change = {
	LINAU_TYPE_LABEL_LEVEL_CHANGE,
	LINAU_TYPE_LABEL_LEVEL_CHANGE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_labeled_export = {
	LINAU_TYPE_USER_LABELED_EXPORT,
	LINAU_TYPE_USER_LABELED_EXPORT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_unlabeled_export = {
	LINAU_TYPE_USER_UNLABELED_EXPORT,
	LINAU_TYPE_USER_UNLABELED_EXPORT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_dev_alloc = {
	LINAU_TYPE_DEV_ALLOC,
	LINAU_TYPE_DEV_ALLOC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_dev_dealloc = {
	LINAU_TYPE_DEV_DEALLOC,
	LINAU_TYPE_DEV_DEALLOC_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_fs_relabel = {
	LINAU_TYPE_FS_RELABEL,
	LINAU_TYPE_FS_RELABEL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_mac_policy_load = {
	LINAU_TYPE_USER_MAC_POLICY_LOAD,
	LINAU_TYPE_USER_MAC_POLICY_LOAD_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_role_modify = {
	LINAU_TYPE_ROLE_MODIFY,
	LINAU_TYPE_ROLE_MODIFY_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_user_mac_config_change = {
	LINAU_TYPE_USER_MAC_CONFIG_CHANGE,
	LINAU_TYPE_USER_MAC_CONFIG_CHANGE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_crypto_test_user = {
	LINAU_TYPE_CRYPTO_TEST_USER,
	LINAU_TYPE_CRYPTO_TEST_USER_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_crypto_param_change_user = {
	LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER,
	LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_crypto_login = {
	LINAU_TYPE_CRYPTO_LOGIN,
	LINAU_TYPE_CRYPTO_LOGIN_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_crypto_logout = {
	LINAU_TYPE_CRYPTO_LOGOUT,
	LINAU_TYPE_CRYPTO_LOGOUT_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_crypto_key_user = {
	LINAU_TYPE_CRYPTO_KEY_USER,
	LINAU_TYPE_CRYPTO_KEY_USER_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_crypto_failure_user = {
	LINAU_TYPE_CRYPTO_FAILURE_USER,
	LINAU_TYPE_CRYPTO_FAILURE_USER_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_crypto_replay_user = {
	LINAU_TYPE_CRYPTO_REPLAY_USER,
	LINAU_TYPE_CRYPTO_REPLAY_USER_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_crypto_session = {
	LINAU_TYPE_CRYPTO_SESSION,
	LINAU_TYPE_CRYPTO_SESSION_STR,
	{
		&lctoken_process32,
		NULL
	}
};
const static struct linau_conv_record_type lcrectype_crypto_ike_sa = {
	LINAU_TYPE_CRYPTO_IKE_SA,
	LINAU_TYPE_CRYPTO_IKE_SA_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_crypto_ipsec_sa = {
	LINAU_TYPE_CRYPTO_IPSEC_SA,
	LINAU_TYPE_CRYPTO_IPSEC_SA_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_virt_control = {
	LINAU_TYPE_VIRT_CONTROL,
	LINAU_TYPE_VIRT_CONTROL_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_virt_resource = {
	LINAU_TYPE_VIRT_RESOURCE,
	LINAU_TYPE_VIRT_RESOURCE_STR,
	{ NULL }
};
const static struct linau_conv_record_type lcrectype_virt_machine_id = {
	LINAU_TYPE_VIRT_MACHINE_ID,
	LINAU_TYPE_VIRT_MACHINE_ID_STR,
	{ NULL }
};

static const char *
field_name_from_field_name_id(int fieldnameid)
{

	switch(fieldnameid) {
	case LINAU_FIELD_NAME_UNDEFINED:
		return (LINAU_FIELD_NAME_UNDEFINED_STR);
	case LINAU_FIELD_NAME_A0:
		return (LINAU_FIELD_NAME_A0_STR);
	case LINAU_FIELD_NAME_A1:
		return (LINAU_FIELD_NAME_A1_STR);
	case LINAU_FIELD_NAME_A2:
		return (LINAU_FIELD_NAME_A2_STR);
	case LINAU_FIELD_NAME_A3:
		return (LINAU_FIELD_NAME_A3_STR);
	case LINAU_FIELD_NAME_A_EXECVE_SYSCALL:
		PJDLOG_ABORT("Requesting the value of the "
		    "LINAU_FIELD_NAME_A_EXECVE_SYSCALL field is not allowed "
		    "because this is a regex field");
	case LINAU_FIELD_NAME_ACCT:
		return (LINAU_FIELD_NAME_ACCT_STR);
	case LINAU_FIELD_NAME_ACL:
		return (LINAU_FIELD_NAME_ACL_STR);
	case LINAU_FIELD_NAME_ACTION:
		return (LINAU_FIELD_NAME_ACTION_STR);
	case LINAU_FIELD_NAME_ADDED:
		return (LINAU_FIELD_NAME_ADDED_STR);
	case LINAU_FIELD_NAME_ADDR:
		return (LINAU_FIELD_NAME_ADDR_STR);
	case LINAU_FIELD_NAME_APPARMOR:
		return (LINAU_FIELD_NAME_APPARMOR_STR);
	case LINAU_FIELD_NAME_ARCH:
		return (LINAU_FIELD_NAME_ARCH_STR);
	case LINAU_FIELD_NAME_ARGC:
		return (LINAU_FIELD_NAME_ARGC_STR);
	case LINAU_FIELD_NAME_AUDIT_BACKLOG_LIMIT:
		return (LINAU_FIELD_NAME_AUDIT_BACKLOG_LIMIT_STR);
	case LINAU_FIELD_NAME_AUDIT_BACKLOG_WAIT_TIME:
		return (LINAU_FIELD_NAME_AUDIT_BACKLOG_WAIT_TIME_STR);
	case LINAU_FIELD_NAME_AUDIT_ENABLED:
		return (LINAU_FIELD_NAME_AUDIT_ENABLED_STR);
	case LINAU_FIELD_NAME_AUDIT_FAILURE:
		return (LINAU_FIELD_NAME_AUDIT_FAILURE_STR);
	case LINAU_FIELD_NAME_AUID:
		return (LINAU_FIELD_NAME_AUID_STR);
	case LINAU_FIELD_NAME_BANNERS:
		return (LINAU_FIELD_NAME_BANNERS_STR);
	case LINAU_FIELD_NAME_BOOL:
		return (LINAU_FIELD_NAME_BOOL_STR);
	case LINAU_FIELD_NAME_BUS:
		return (LINAU_FIELD_NAME_BUS_STR);
	case LINAU_FIELD_NAME_CAPABILITY:
		return (LINAU_FIELD_NAME_CAPABILITY_STR);
	case LINAU_FIELD_NAME_CAP_FE:
		return (LINAU_FIELD_NAME_CAP_FE_STR);
	case LINAU_FIELD_NAME_CAP_FI:
		return (LINAU_FIELD_NAME_CAP_FI_STR);
	case LINAU_FIELD_NAME_CAP_FP:
		return (LINAU_FIELD_NAME_CAP_FP_STR);
	case LINAU_FIELD_NAME_CAP_FVER:
		return (LINAU_FIELD_NAME_CAP_FVER_STR);
	case LINAU_FIELD_NAME_CAP_PE:
		return (LINAU_FIELD_NAME_CAP_PE_STR);
	case LINAU_FIELD_NAME_CAP_PI:
		return (LINAU_FIELD_NAME_CAP_PI_STR);
	case LINAU_FIELD_NAME_CAP_PP:
		return (LINAU_FIELD_NAME_CAP_PP_STR);
	case LINAU_FIELD_NAME_CATEGORY:
		return (LINAU_FIELD_NAME_CATEGORY_STR);
	case LINAU_FIELD_NAME_CGROUP:
		return (LINAU_FIELD_NAME_CGROUP_STR);
	case LINAU_FIELD_NAME_CHANGED:
		return (LINAU_FIELD_NAME_CHANGED_STR);
	case LINAU_FIELD_NAME_CIPHER:
		return (LINAU_FIELD_NAME_CIPHER_STR);
	case LINAU_FIELD_NAME_CLASS:
		return (LINAU_FIELD_NAME_CLASS_STR);
	case LINAU_FIELD_NAME_CMD:
		return (LINAU_FIELD_NAME_CMD_STR);
	case LINAU_FIELD_NAME_CODE:
		return (LINAU_FIELD_NAME_CODE_STR);
	case LINAU_FIELD_NAME_COMM:
		return (LINAU_FIELD_NAME_COMM_STR);
	case LINAU_FIELD_NAME_COMPAT:
		return (LINAU_FIELD_NAME_COMPAT_STR);
	case LINAU_FIELD_NAME_CWD:
		return (LINAU_FIELD_NAME_CWD_STR);
	case LINAU_FIELD_NAME_DADDR:
		return (LINAU_FIELD_NAME_DADDR_STR);
	case LINAU_FIELD_NAME_DATA:
		return (LINAU_FIELD_NAME_DATA_STR);
	case LINAU_FIELD_NAME_DEFAULT:
		return (LINAU_FIELD_NAME_DEFAULT_STR);
	case LINAU_FIELD_NAME_DEV:
		return (LINAU_FIELD_NAME_DEV_STR);
	/* case LINAU_FIELD_NAME2_DEV: */
	/*         return (LINAU_FIELD_NAME2_DEV_STR); */
	case LINAU_FIELD_NAME_DEVICE:
		return (LINAU_FIELD_NAME_DEVICE_STR);
	case LINAU_FIELD_NAME_DIR:
		return (LINAU_FIELD_NAME_DIR_STR);
	case LINAU_FIELD_NAME_DIRECTION:
		return (LINAU_FIELD_NAME_DIRECTION_STR);
	case LINAU_FIELD_NAME_DMAC:
		return (LINAU_FIELD_NAME_DMAC_STR);
	case LINAU_FIELD_NAME_DPORT:
		return (LINAU_FIELD_NAME_DPORT_STR);
	case LINAU_FIELD_NAME_EGID:
		return (LINAU_FIELD_NAME_EGID_STR);
	case LINAU_FIELD_NAME_ENFORCING:
		return (LINAU_FIELD_NAME_ENFORCING_STR);
	case LINAU_FIELD_NAME_ENTRIES:
		return (LINAU_FIELD_NAME_ENTRIES_STR);
	case LINAU_FIELD_NAME_EUID:
		return (LINAU_FIELD_NAME_EUID_STR);
	case LINAU_FIELD_NAME_EXE:
		return (LINAU_FIELD_NAME_EXE_STR);
	case LINAU_FIELD_NAME_EXIT:
		return (LINAU_FIELD_NAME_EXIT_STR);
	case LINAU_FIELD_NAME_FAM:
		return (LINAU_FIELD_NAME_FAM_STR);
	case LINAU_FIELD_NAME_FAMILY:
		return (LINAU_FIELD_NAME_FAMILY_STR);
	case LINAU_FIELD_NAME_FD:
		return (LINAU_FIELD_NAME_FD_STR);
	case LINAU_FIELD_NAME_FILE:
		return (LINAU_FIELD_NAME_FILE_STR);
	case LINAU_FIELD_NAME_FLAGS:
		return (LINAU_FIELD_NAME_FLAGS_STR);
	case LINAU_FIELD_NAME_FE:
		return (LINAU_FIELD_NAME_FE_STR);
	case LINAU_FIELD_NAME_FEATURE:
		return (LINAU_FIELD_NAME_FEATURE_STR);
	case LINAU_FIELD_NAME_FI:
		return (LINAU_FIELD_NAME_FI_STR);
	case LINAU_FIELD_NAME_FP:
		return (LINAU_FIELD_NAME_FP_STR);
	/* case LINAU_FIELD_NAME_FP2: */
	/*         return (LINAU_FIELD_NAME_FP2_STR); */
	case LINAU_FIELD_NAME_FORMAT:
		return (LINAU_FIELD_NAME_FORMAT_STR);
	case LINAU_FIELD_NAME_FSGID:
		return (LINAU_FIELD_NAME_FSGID_STR);
	case LINAU_FIELD_NAME_FSUID:
		return (LINAU_FIELD_NAME_FSUID_STR);
	case LINAU_FIELD_NAME_FVER:
		return (LINAU_FIELD_NAME_FVER_STR);
	case LINAU_FIELD_NAME_GID:
		return (LINAU_FIELD_NAME_GID_STR);
	case LINAU_FIELD_NAME_GRANTORS:
		return (LINAU_FIELD_NAME_GRANTORS_STR);
	case LINAU_FIELD_NAME_GRP:
		return (LINAU_FIELD_NAME_GRP_STR);
	case LINAU_FIELD_NAME_HOOK:
		return (LINAU_FIELD_NAME_HOOK_STR);
	case LINAU_FIELD_NAME_HOSTNAME:
		return (LINAU_FIELD_NAME_HOSTNAME_STR);
	case LINAU_FIELD_NAME_ICMP_TYPE:
		return (LINAU_FIELD_NAME_ICMP_TYPE_STR);
	case LINAU_FIELD_NAME_ID:
		return (LINAU_FIELD_NAME_ID_STR);
	case LINAU_FIELD_NAME_IGID:
		return (LINAU_FIELD_NAME_IGID_STR);
	case LINAU_FIELD_NAME_IMG:
		return (LINAU_FIELD_NAME_IMG_STR);
	case LINAU_FIELD_NAME_INIF:
		return (LINAU_FIELD_NAME_INIF_STR);
	case LINAU_FIELD_NAME_IP:
		return (LINAU_FIELD_NAME_IP_STR);
	case LINAU_FIELD_NAME_IPID:
		return (LINAU_FIELD_NAME_IPID_STR);
	case LINAU_FIELD_NAME_INO:
		return (LINAU_FIELD_NAME_INO_STR);
	case LINAU_FIELD_NAME_INODE:
		return (LINAU_FIELD_NAME_INODE_STR);
	case LINAU_FIELD_NAME_INODE_GID:
		return (LINAU_FIELD_NAME_INODE_GID_STR);
	case LINAU_FIELD_NAME_INODE_UID:
		return (LINAU_FIELD_NAME_INODE_UID_STR);
	case LINAU_FIELD_NAME_INVALID_CONTEXT:
		return (LINAU_FIELD_NAME_INVALID_CONTEXT_STR);
	case LINAU_FIELD_NAME_IOCTLCMD:
		return (LINAU_FIELD_NAME_IOCTLCMD_STR);
	case LINAU_FIELD_NAME_IPX:
		return (LINAU_FIELD_NAME_IPX_STR);
	case LINAU_FIELD_NAME_ITEM:
		return (LINAU_FIELD_NAME_ITEM_STR);
	case LINAU_FIELD_NAME_ITEMS:
		return (LINAU_FIELD_NAME_ITEMS_STR);
	case LINAU_FIELD_NAME_IUID:
		return (LINAU_FIELD_NAME_IUID_STR);
	case LINAU_FIELD_NAME_KERNEL:
		return (LINAU_FIELD_NAME_KERNEL_STR);
	case LINAU_FIELD_NAME_KEY:
		return (LINAU_FIELD_NAME_KEY_STR);
	case LINAU_FIELD_NAME_KIND:
		return (LINAU_FIELD_NAME_KIND_STR);
	case LINAU_FIELD_NAME_KSIZE:
		return (LINAU_FIELD_NAME_KSIZE_STR);
	case LINAU_FIELD_NAME_LADDR:
		return (LINAU_FIELD_NAME_LADDR_STR);
	case LINAU_FIELD_NAME_LEN:
		return (LINAU_FIELD_NAME_LEN_STR);
	case LINAU_FIELD_NAME_LPORT:
		return (LINAU_FIELD_NAME_LPORT_STR);
	case LINAU_FIELD_NAME_LIST:
		return (LINAU_FIELD_NAME_LIST_STR);
	case LINAU_FIELD_NAME_MAC:
		return (LINAU_FIELD_NAME_MAC_STR);
	case LINAU_FIELD_NAME_MACPROTO:
		return (LINAU_FIELD_NAME_MACPROTO_STR);
	case LINAU_FIELD_NAME_MAJ:
		return (LINAU_FIELD_NAME_MAJ_STR);
	case LINAU_FIELD_NAME_MAJOR:
		return (LINAU_FIELD_NAME_MAJOR_STR);
	case LINAU_FIELD_NAME_MINOR:
		return (LINAU_FIELD_NAME_MINOR_STR);
	case LINAU_FIELD_NAME_MODE:
		return (LINAU_FIELD_NAME_MODE_STR);
	case LINAU_FIELD_NAME_MODEL:
		return (LINAU_FIELD_NAME_MODEL_STR);
	case LINAU_FIELD_NAME_MSG:
		return (LINAU_FIELD_NAME_MSG_STR);
	case LINAU_FIELD_NAME_NARGS:
		return (LINAU_FIELD_NAME_NARGS_STR);
	case LINAU_FIELD_NAME_NAME:
		return (LINAU_FIELD_NAME_NAME_STR);
	case LINAU_FIELD_NAME_NAMETYPE:
		return (LINAU_FIELD_NAME_NAMETYPE_STR);
	case LINAU_FIELD_NAME_NET:
		return (LINAU_FIELD_NAME_NET_STR);
	case LINAU_FIELD_NAME_NEW:
		return (LINAU_FIELD_NAME_NEW_STR);
	case LINAU_FIELD_NAME_NEW_CHARDEV:
		return (LINAU_FIELD_NAME_NEW_CHARDEV_STR);
	case LINAU_FIELD_NAME_NEW_DISK:
		return (LINAU_FIELD_NAME_NEW_DISK_STR);
	case LINAU_FIELD_NAME_NEW_ENABLED:
		return (LINAU_FIELD_NAME_NEW_ENABLED_STR);
	case LINAU_FIELD_NAME_NEW_FS:
		return (LINAU_FIELD_NAME_NEW_FS_STR);
	case LINAU_FIELD_NAME_NEW_GID:
		return (LINAU_FIELD_NAME_NEW_GID_STR);
	case LINAU_FIELD_NAME_NEW_LEVEL:
		return (LINAU_FIELD_NAME_NEW_LEVEL_STR);
	case LINAU_FIELD_NAME_NEW_LOCK:
		return (LINAU_FIELD_NAME_NEW_LOCK_STR);
	case LINAU_FIELD_NAME_NEW_LOG_PASSWD:
		return (LINAU_FIELD_NAME_NEW_LOG_PASSWD_STR);
	case LINAU_FIELD_NAME_NEW_MEM:
		return (LINAU_FIELD_NAME_NEW_MEM_STR);
	case LINAU_FIELD_NAME_NEW_NET:
		return (LINAU_FIELD_NAME_NEW_NET_STR);
	case LINAU_FIELD_NAME_NEW_PE:
		return (LINAU_FIELD_NAME_NEW_PE_STR);
	case LINAU_FIELD_NAME_NEW_PI:
		return (LINAU_FIELD_NAME_NEW_PI_STR);
	case LINAU_FIELD_NAME_NEW_PP:
		return (LINAU_FIELD_NAME_NEW_PP_STR);
	case LINAU_FIELD_NAME_NEW_RANGE:
		return (LINAU_FIELD_NAME_NEW_RANGE_STR);
	case LINAU_FIELD_NAME_NEW_RNG:
		return (LINAU_FIELD_NAME_NEW_RNG_STR);
	case LINAU_FIELD_NAME_NEW_ROLE:
		return (LINAU_FIELD_NAME_NEW_ROLE_STR);
	case LINAU_FIELD_NAME_NEW_SEUSER:
		return (LINAU_FIELD_NAME_NEW_SEUSER_STR);
	case LINAU_FIELD_NAME_NEW_VCPU:
		return (LINAU_FIELD_NAME_NEW_VCPU_STR);
	case LINAU_FIELD_NAME_NLNK_FAM:
		return (LINAU_FIELD_NAME_NLNK_FAM_STR);
	case LINAU_FIELD_NAME_NLNK_GRP:
		return (LINAU_FIELD_NAME_NLNK_GRP_STR);
	case LINAU_FIELD_NAME_NLNK_PID:
		return (LINAU_FIELD_NAME_NLNK_PID_STR);
	case LINAU_FIELD_NAME_OAUID:
		return (LINAU_FIELD_NAME_OAUID_STR);
	case LINAU_FIELD_NAME_OBJ:
		return (LINAU_FIELD_NAME_OBJ_STR);
	case LINAU_FIELD_NAME_OBJ_GID:
		return (LINAU_FIELD_NAME_OBJ_GID_STR);
	case LINAU_FIELD_NAME_OBJ_UID:
		return (LINAU_FIELD_NAME_OBJ_UID_STR);
	case LINAU_FIELD_NAME_OFLAG:
		return (LINAU_FIELD_NAME_OFLAG_STR);
	case LINAU_FIELD_NAME_OGID:
		return (LINAU_FIELD_NAME_OGID_STR);
	case LINAU_FIELD_NAME_OCOMM:
		return (LINAU_FIELD_NAME_OCOMM_STR);
	case LINAU_FIELD_NAME_OLD:
		return (LINAU_FIELD_NAME_OLD_STR);
	/* case LINAU_FIELD_NAME2_OLD: */
	/*         return (LINAU_FIELD_NAME2_OLD_STR); */
	case LINAU_FIELD_NAME_OLD_AUID:
		return (LINAU_FIELD_NAME_OLD_AUID_STR);
	case LINAU_FIELD_NAME_OLD_CHARDEV:
		return (LINAU_FIELD_NAME_OLD_CHARDEV_STR);
	case LINAU_FIELD_NAME_OLD_DISK:
		return (LINAU_FIELD_NAME_OLD_DISK_STR);
	case LINAU_FIELD_NAME_OLD_ENABLED:
		return (LINAU_FIELD_NAME_OLD_ENABLED_STR);
	case LINAU_FIELD_NAME_OLD_ENFORCING:
		return (LINAU_FIELD_NAME_OLD_ENFORCING_STR);
	case LINAU_FIELD_NAME_OLD_FS:
		return (LINAU_FIELD_NAME_OLD_FS_STR);
	case LINAU_FIELD_NAME_OLD_LEVEL:
		return (LINAU_FIELD_NAME_OLD_LEVEL_STR);
	case LINAU_FIELD_NAME_OLD_LOCK:
		return (LINAU_FIELD_NAME_OLD_LOCK_STR);
	case LINAU_FIELD_NAME_OLD_LOG_PASSWD:
		return (LINAU_FIELD_NAME_OLD_LOG_PASSWD_STR);
	case LINAU_FIELD_NAME_OLD_MEM:
		return (LINAU_FIELD_NAME_OLD_MEM_STR);
	case LINAU_FIELD_NAME_OLD_NET:
		return (LINAU_FIELD_NAME_OLD_NET_STR);
	case LINAU_FIELD_NAME_OLD_PE:
		return (LINAU_FIELD_NAME_OLD_PE_STR);
	case LINAU_FIELD_NAME_OLD_PI:
		return (LINAU_FIELD_NAME_OLD_PI_STR);
	case LINAU_FIELD_NAME_OLD_PP:
		return (LINAU_FIELD_NAME_OLD_PP_STR);
	case LINAU_FIELD_NAME_OLD_PROM:
		return (LINAU_FIELD_NAME_OLD_PROM_STR);
	case LINAU_FIELD_NAME_OLD_RANGE:
		return (LINAU_FIELD_NAME_OLD_RANGE_STR);
	case LINAU_FIELD_NAME_OLD_RNG:
		return (LINAU_FIELD_NAME_OLD_RNG_STR);
	case LINAU_FIELD_NAME_OLD_ROLE:
		return (LINAU_FIELD_NAME_OLD_ROLE_STR);
	case LINAU_FIELD_NAME_OLD_SES:
		return (LINAU_FIELD_NAME_OLD_SES_STR);
	case LINAU_FIELD_NAME_OLD_SEUSER:
		return (LINAU_FIELD_NAME_OLD_SEUSER_STR);
	case LINAU_FIELD_NAME_OLD_VAL:
		return (LINAU_FIELD_NAME_OLD_VAL_STR);
	case LINAU_FIELD_NAME_OLD_VCPU:
		return (LINAU_FIELD_NAME_OLD_VCPU_STR);
	case LINAU_FIELD_NAME_OP:
		return (LINAU_FIELD_NAME_OP_STR);
	case LINAU_FIELD_NAME_OPID:
		return (LINAU_FIELD_NAME_OPID_STR);
	case LINAU_FIELD_NAME_OSES:
		return (LINAU_FIELD_NAME_OSES_STR);
	case LINAU_FIELD_NAME_OUID:
		return (LINAU_FIELD_NAME_OUID_STR);
	case LINAU_FIELD_NAME_OUTIF:
		return (LINAU_FIELD_NAME_OUTIF_STR);
	case LINAU_FIELD_NAME_PARENT:
		return (LINAU_FIELD_NAME_PARENT_STR);
	case LINAU_FIELD_NAME_PATH:
		return (LINAU_FIELD_NAME_PATH_STR);
	case LINAU_FIELD_NAME_PER:
		return (LINAU_FIELD_NAME_PER_STR);
	case LINAU_FIELD_NAME_PERM:
		return (LINAU_FIELD_NAME_PERM_STR);
	case LINAU_FIELD_NAME_PERM_MASK:
		return (LINAU_FIELD_NAME_PERM_MASK_STR);
	case LINAU_FIELD_NAME_PERMISSIVE:
		return (LINAU_FIELD_NAME_PERMISSIVE_STR);
	case LINAU_FIELD_NAME_PFS:
		return (LINAU_FIELD_NAME_PFS_STR);
	case LINAU_FIELD_NAME_PID:
		return (LINAU_FIELD_NAME_PID_STR);
	case LINAU_FIELD_NAME_PPID:
		return (LINAU_FIELD_NAME_PPID_STR);
	case LINAU_FIELD_NAME_PRINTER:
		return (LINAU_FIELD_NAME_PRINTER_STR);
	case LINAU_FIELD_NAME_PROM:
		return (LINAU_FIELD_NAME_PROM_STR);
	case LINAU_FIELD_NAME_PROCTITLE:
		return (LINAU_FIELD_NAME_PROCTITLE_STR);
	case LINAU_FIELD_NAME_PROTO:
		return (LINAU_FIELD_NAME_PROTO_STR);
	case LINAU_FIELD_NAME_QBYTES:
		return (LINAU_FIELD_NAME_QBYTES_STR);
	case LINAU_FIELD_NAME_RANGE:
		return (LINAU_FIELD_NAME_RANGE_STR);
	case LINAU_FIELD_NAME_RDEV:
		return (LINAU_FIELD_NAME_RDEV_STR);
	case LINAU_FIELD_NAME_REASON:
		return (LINAU_FIELD_NAME_REASON_STR);
	case LINAU_FIELD_NAME_REMOVED:
		return (LINAU_FIELD_NAME_REMOVED_STR);
	case LINAU_FIELD_NAME_RES:
		return (LINAU_FIELD_NAME_RES_STR);
	case LINAU_FIELD_NAME_RESRC:
		return (LINAU_FIELD_NAME_RESRC_STR);
	case LINAU_FIELD_NAME_RESULT:
		return (LINAU_FIELD_NAME_RESULT_STR);
	case LINAU_FIELD_NAME_ROLE:
		return (LINAU_FIELD_NAME_ROLE_STR);
	case LINAU_FIELD_NAME_RPORT:
		return (LINAU_FIELD_NAME_RPORT_STR);
	case LINAU_FIELD_NAME_SADDR:
		return (LINAU_FIELD_NAME_SADDR_STR);
	case LINAU_FIELD_NAME_SAUID:
		return (LINAU_FIELD_NAME_SAUID_STR);
	case LINAU_FIELD_NAME_SCONTEXT:
		return (LINAU_FIELD_NAME_SCONTEXT_STR);
	case LINAU_FIELD_NAME_SELECTED:
		return (LINAU_FIELD_NAME_SELECTED_STR);
	case LINAU_FIELD_NAME_SEPERM:
		return (LINAU_FIELD_NAME_SEPERM_STR);
	case LINAU_FIELD_NAME_SEQNO:
		return (LINAU_FIELD_NAME_SEQNO_STR);
	case LINAU_FIELD_NAME_SEPERMS:
		return (LINAU_FIELD_NAME_SEPERMS_STR);
	case LINAU_FIELD_NAME_SERESULT:
		return (LINAU_FIELD_NAME_SERESULT_STR);
	case LINAU_FIELD_NAME_SES:
		return (LINAU_FIELD_NAME_SES_STR);
	case LINAU_FIELD_NAME_SEUSER:
		return (LINAU_FIELD_NAME_SEUSER_STR);
	case LINAU_FIELD_NAME_SGID:
		return (LINAU_FIELD_NAME_SGID_STR);
	case LINAU_FIELD_NAME_SIG:
		return (LINAU_FIELD_NAME_SIG_STR);
	case LINAU_FIELD_NAME_SIGEV_SIGNO:
		return (LINAU_FIELD_NAME_SIGEV_SIGNO_STR);
	case LINAU_FIELD_NAME_SMAC:
		return (LINAU_FIELD_NAME_SMAC_STR);
	case LINAU_FIELD_NAME_SPID:
		return (LINAU_FIELD_NAME_SPID_STR);
	case LINAU_FIELD_NAME_SPORT:
		return (LINAU_FIELD_NAME_SPORT_STR);
	case LINAU_FIELD_NAME_STATE:
		return (LINAU_FIELD_NAME_STATE_STR);
	case LINAU_FIELD_NAME_SUBJ:
		return (LINAU_FIELD_NAME_SUBJ_STR);
	case LINAU_FIELD_NAME_SUCCESS:
		return (LINAU_FIELD_NAME_SUCCESS_STR);
	case LINAU_FIELD_NAME_SUID:
		return (LINAU_FIELD_NAME_SUID_STR);
	case LINAU_FIELD_NAME_SYSCALL:
		return (LINAU_FIELD_NAME_SYSCALL_STR);
	case LINAU_FIELD_NAME_TABLE:
		return (LINAU_FIELD_NAME_TABLE_STR);
	case LINAU_FIELD_NAME_TCLASS:
		return (LINAU_FIELD_NAME_TCLASS_STR);
	case LINAU_FIELD_NAME_TCONTEXT:
		return (LINAU_FIELD_NAME_TCONTEXT_STR);
	case LINAU_FIELD_NAME_TERMINAL:
		return (LINAU_FIELD_NAME_TERMINAL_STR);
	case LINAU_FIELD_NAME_TTY:
		return (LINAU_FIELD_NAME_TTY_STR);
	case LINAU_FIELD_NAME_TYPE:
		return (LINAU_FIELD_NAME_TYPE_STR);
	case LINAU_FIELD_NAME_UID:
		return (LINAU_FIELD_NAME_UID_STR);
	case LINAU_FIELD_NAME_UNIT:
		return (LINAU_FIELD_NAME_UNIT_STR);
	case LINAU_FIELD_NAME_URI:
		return (LINAU_FIELD_NAME_URI_STR);
	case LINAU_FIELD_NAME_USER:
		return (LINAU_FIELD_NAME_USER_STR);
	case LINAU_FIELD_NAME_UUID:
		return (LINAU_FIELD_NAME_UUID_STR);
	case LINAU_FIELD_NAME_VAL:
		return (LINAU_FIELD_NAME_VAL_STR);
	case LINAU_FIELD_NAME_VER:
		return (LINAU_FIELD_NAME_VER_STR);
	case LINAU_FIELD_NAME_VIRT:
		return (LINAU_FIELD_NAME_VIRT_STR);
	case LINAU_FIELD_NAME_VM:
		return (LINAU_FIELD_NAME_VM_STR);
	case LINAU_FIELD_NAME_VM_CTX:
		return (LINAU_FIELD_NAME_VM_CTX_STR);
	case LINAU_FIELD_NAME_VM_PID:
		return (LINAU_FIELD_NAME_VM_PID_STR);
	case LINAU_FIELD_NAME_WATCH:
		return (LINAU_FIELD_NAME_WATCH_STR);
	default:
		/* NOTREACHED */
		PJDLOG_ABORT("Field name should be marked as "
		    "LINAU_FIELD_NAME_UNDEFINED if it is not a standard name");
	}
}

static int
field_type_from_field_name_id(int fieldnameid)
{

	switch(fieldnameid) {
	case LINAU_FIELD_NAME_UNDEFINED:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_A0:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_A1:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_A2:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_A3:
		return (LINAU_CONV_FIELD_TYPE_STANDARD);
	case LINAU_FIELD_NAME_A_EXECVE_SYSCALL:
		return (LINAU_CONV_FIELD_TYPE_REGEX);
	case LINAU_FIELD_NAME_ACCT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ACL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ACTION:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ADDED:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ADDR:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_APPARMOR:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ARCH:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ARGC:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_AUDIT_BACKLOG_LIMIT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_AUDIT_BACKLOG_WAIT_TIME:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_AUDIT_ENABLED:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_AUDIT_FAILURE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_AUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_BANNERS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_BOOL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_BUS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CAPABILITY:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CAP_FE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CAP_FI:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CAP_FP:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CAP_FVER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CAP_PE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CAP_PI:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CAP_PP:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CATEGORY:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CGROUP:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CHANGED:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CIPHER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CLASS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CMD:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CODE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_COMM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_COMPAT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_CWD:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_DADDR:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_DATA:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_DEFAULT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_DEV:
		/* FALLTHROUGH */
	/* case LINAU_FIELD_NAME2_DEV: */
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_DEVICE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_DIR:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_DIRECTION:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_DMAC:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_DPORT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_EGID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ENFORCING:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ENTRIES:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_EUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_EXE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_EXIT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FAM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FAMILY:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FD:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FILE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FLAGS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FEATURE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FI:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FP:
		/* FALLTHROUGH */
	/* case LINAU_FIELD_NAME_FP2: */
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FORMAT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FSGID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FSUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_FVER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_GID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_GRANTORS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_GRP:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_HOOK:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_HOSTNAME:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ICMP_TYPE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_IGID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_IMG:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_INIF:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_IP:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_IPID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_INO:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_INODE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_INODE_GID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_INODE_UID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_INVALID_CONTEXT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_IOCTLCMD:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_IPX:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ITEM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ITEMS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_IUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_KERNEL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_KEY:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_KIND:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_KSIZE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_LADDR:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_LEN:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_LPORT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_LIST:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_MAC:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_MACPROTO:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_MAJ:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_MAJOR:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_MINOR:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_MODE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_MODEL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_MSG:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NARGS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NAME:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NAMETYPE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NET:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_CHARDEV:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_DISK:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_ENABLED:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_FS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_GID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_LEVEL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_LOCK:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_LOG_PASSWD:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_MEM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_NET:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_PE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_PI:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_PP:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_RANGE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_RNG:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_ROLE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_SEUSER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NEW_VCPU:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NLNK_FAM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NLNK_GRP:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_NLNK_PID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OAUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OBJ:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OBJ_GID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OBJ_UID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OFLAG:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OGID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OCOMM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD:
		/* FALLTHROUGH */
	/* case LINAU_FIELD_NAME2_OLD: */
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_AUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_CHARDEV:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_DISK:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_ENABLED:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_ENFORCING:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_FS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_LEVEL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_LOCK:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_LOG_PASSWD:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_MEM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_NET:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_PE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_PI:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_PP:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_PROM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_RANGE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_RNG:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_ROLE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_SES:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_SEUSER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_VAL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OLD_VCPU:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OP:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OPID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OSES:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_OUTIF:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PARENT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PATH:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PERM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PERM_MASK:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PERMISSIVE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PFS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PPID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PRINTER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PROM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PROCTITLE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_PROTO:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_QBYTES:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_RANGE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_RDEV:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_REASON:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_REMOVED:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_RES:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_RESRC:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_RESULT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_ROLE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_RPORT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SADDR:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SAUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SCONTEXT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SELECTED:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SEPERM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SEQNO:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SEPERMS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SERESULT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SES:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SEUSER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SGID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SIG:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SIGEV_SIGNO:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SMAC:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SPID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SPORT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_STATE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SUBJ:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SUCCESS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_SYSCALL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_TABLE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_TCLASS:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_TCONTEXT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_TERMINAL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_TTY:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_TYPE:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_UID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_UNIT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_URI:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_USER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_UUID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_VAL:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_VER:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_VIRT:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_VM:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_VM_CTX:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_VM_PID:
		/* FALLTHROUGH */
	case LINAU_FIELD_NAME_WATCH:
		return (LINAU_CONV_FIELD_TYPE_STANDARD);
	default:
		/* NOTREACHED */
		PJDLOG_ABORT("Field name should be marked as "
		    "LINAU_FIELD_NAME_UNDEFINED if it is not a standard name; "
		    "otherwise it is impossible to determine the type of "
		    "its linau_conv_field structure");
	}
}

/*
 * This is an abstraction for processing the *id fields from both
 * pid_t (int32_t) and uid_t (uint32_t) families.
 *
 * Returns:
 * - true if the field is valid and was processed;
 * - false if there is no field like this in the record or it is invalid.
 */
static bool
process_id_field(const struct linau_record *record, const char *fieldname,
    const struct linau_conv_field *lcfield, uint32_t *idp, size_t *fieldscountp)
{
	const char *fieldvalue;

	PJDLOG_ASSERT(lcfield != NULL);
	PJDLOG_ASSERT(fieldscountp != NULL);

	if (!linau_record_exists_field(record, fieldname))
		return (false);

	fieldvalue = linau_record_get_field(record, fieldname);

	if (lcfield->lcf_validate(fieldvalue)) {
		PJDLOG_VERIFY(string_to_uint32(idp, fieldvalue));
		*fieldscountp += 1;
		return (true);
	} else {
		return (false);
	}
}

/*
 * TODO: The errno code of the return token is always set to 0 (undefined) for
 * the time being.
 *
 * fieldname is expected to be either "res" or "result".
 *
 * Returns:
 * - NULL if:
 *  - There is no field called fieldname in the record;
 *  - The value of the field is neither success nor failed.
 */
static token_t *
generate_proto_token_return(const struct linau_record *record,
    const char *fieldname)
{
	const char *fieldvalue;
	token_t *tok;
	int retvalue;

	if (!linau_record_exists_field(record, fieldname))
		return (NULL);

	fieldvalue = linau_record_get_field(record, fieldname);
	PJDLOG_ASSERT(strchr(fieldvalue, '\0') != NULL);

	if (strncmp(fieldvalue, "success", sizeof("success")) == 0)
		retvalue = 0;
	else if (strncmp(fieldvalue, "failed", sizeof("failed")) == 0)
		retvalue = 1;
	else
		return (NULL);

	tok = au_to_return32(0, retvalue);
	PJDLOG_ASSERT(tok != NULL);

	return (tok);
}

/*
 * Returns NULL if there is no field fieldname in record.
 */
static token_t *
generate_proto_token_text_from_field(const struct linau_record *record,
    const char *fieldname)
{
	struct sbuf *buf;
	const char *msg;
	token_t *tok;

	PJDLOG_ASSERT(fieldname != NULL);

	if (!linau_record_exists_field(record, fieldname))
		return (NULL);

	buf = sbuf_new_auto();
	PJDLOG_ASSERT(buf != NULL);

	msg = linau_record_get_field(record, fieldname);
	sbuf_printf(buf, "%s=%s", fieldname, msg);

	PJDLOG_VERIFY(sbuf_finish(buf) == 0);

	tok = au_to_text(sbuf_data(buf));
	PJDLOG_ASSERT(tok != NULL);

	sbuf_delete(buf);

	return (tok);
}

/*
 * TODO: Implement it.
 *
 * XXX: This function should probably check if the value is in the form of a
 * text in a string like 'pid=320 cwd="/usr"' or "pid=320 cwd='/usr'".  I am
 * not sure though.
 */
static int
linau_conv_is_alphanumeric(const char *field)
{

	PJDLOG_ASSERT(field != NULL);

	return (1);
}

static int
linau_conv_is_encoded(const char *field)
{

	PJDLOG_ASSERT(field != NULL);

	return (1);
}

/*
 * Check if the field is made of digits only.
 *
 * STYLE: This function might go to linau_field.c
 * and be added to the interface in linau.h.
 *
 * Parameters:
 * field	The null-terminated string.
 */
static int
linau_conv_is_numeric(const char *field)
{
	size_t ii;

	PJDLOG_ASSERT(field != NULL);
	PJDLOG_ASSERT(strchr(field, '\0') != NULL);

	for (ii = 0; field[ii] != '\0'; ii++)
		if (!isdigit(field[ii]))
			return (0);

	return (1);
}

/*
 * An example of a valid mode is 0100644. Assume that the length of this
 * field is always 7.
 *
 * STYLE: I don't know how to initialize the len variable after the declaration.
 */
static int
linau_conv_is_valid_field_mode(const char *field)
{
	const size_t len = 7;
	size_t ii;

	PJDLOG_ASSERT(field != NULL);
	PJDLOG_ASSERT(strchr(field, '\0') != NULL);

	if (strlen(field) != len)
		return (0);

	for (ii = 0; ii < len; ii++)
		if (!isdigit(field[ii]))
			return (0);

	return (1);
}

static int
linau_conv_is_valid_field_res(const char *field)
{

	PJDLOG_ASSERT(field != NULL);
	PJDLOG_ASSERT(strchr(field, '\0') != NULL);

	if (strncmp(field, "success", sizeof("success")) == 0)
		return (1);
	else if (strncmp(field, "failed", sizeof("failed")) == 0)
		return (1);
	else
		return (0);
}

/*
 * Validates whether a field is a a legal pid_t typedef (uint32_t).
 *
 * pid_t is an alias of int32_t; this is why this function differs from
 * linau_conv_is_valid_uid.
 */
static int
linau_conv_is_valid_pid(const char *field)
{
	uint32_t num;

	if (string_to_uint32(&num, field) && 0 <= (int32_t)num &&
	    (int32_t)num <= INT32_MAX)
		return (1);
	else
		return (0);
}

/*
 * Validates whether a field is a a legal uid_t typedef (uint32_t).
 */
static int
linau_conv_is_valid_uid(const char *field)
{
	uint32_t num;

	if (string_to_uint32(&num, field))
		return (1);
	else
		return (0);
}

/*
 * Returns all the fields which match "a[[:digit:]+](\[[:digit:]+\])?" as
 * an nvlist. Returns an empty nvlist if there are no such fields.
 */
static nvlist_t *
linau_conv_match_a_execve_syscall(const struct linau_record *record)
{
	void *cookie;
	nvlist_t *fields;
	const char *name;
	size_t ii;
	int type;

	pjdlog_debug(5, "%s", __func__);

	fields = linau_record_clone_fields(record);

	cookie = NULL;
	while ((name = nvlist_next(fields, &type, &cookie)) != NULL) {
		PJDLOG_ASSERT(type == NV_TYPE_STRING);
		pjdlog_debug(5, "Inside the loop with name (%s)", name);
		if (name[0] == 'a') {
			ii = 1;
			while (isdigit(name[ii]))
				ii++;
			if (name[ii] == '\0') {
				continue;
			} else if (ii != 1 && name[ii] == '[') {
				while (isdigit(name[ii]))
					ii++;
				if (name[ii] == ']' && strlen(name) == ii)
					continue;
			}
		}
		pjdlog_debug(5, "Fail name (%s) ", name);
		/* nvlist_free_string(fields, name); */
	}
	pjdlog_debug(5, "After the loop", __func__);

	name = LINAU_FIELD_NAME_A0_STR;
	if (nvlist_exists_string(fields, name))
		nvlist_free_string(fields, name);
	name = LINAU_FIELD_NAME_A1_STR;
	if (nvlist_exists_string(fields, name))
		nvlist_free_string(fields, name);
	name = LINAU_FIELD_NAME_A2_STR;
	if (nvlist_exists_string(fields, name))
		nvlist_free_string(fields, name);
	name = LINAU_FIELD_NAME_A3_STR;
	if (nvlist_exists_string(fields, name))
		nvlist_free_string(fields, name);

	pjdlog_debug(5, "End %s", __func__);

	return (fields);
}

/*
 * Current fields: mode, ouid, ogid.
 */
static void
write_token_attribute(int aurd, const struct linau_record *record)
{
	(void)aurd;
	(void)record;
	/* const char *fieldval; */
	/* const char *fieldname; */
	/* token_t *tok; */
	/* struct vnode_au_info *vni; */
	/* token_t *tok; */
	/* size_t fieldscount; */
	/* uint32_t num; */

	/* PJDLOG_ASSERT(aurd >= 0); */

	/* pjdlog_debug(3, "%s", __func__); */

	/* vni = calloc(1, sizeof(*vni)); */
	/* PJDLOG_ASSERT(vni != NULL); */
	/* fieldscount = 0; */

	/* fieldname = LINAU_FIELD_NAME_MODE_STR; */
	/* if (linau_record_exists_field(record, fieldname)) { */
	/*         fieldval = linau_record_get_field(record, fieldname); */
	/*         if (lcfield_mode.lcf_validate(fieldval)) { */
	/*                 PJDLOG_VERIFY(string_to_uint32(&num, fieldval[3])); */
	/*                 vni->vn_mode = (mode_t)num; */
	/*                 pjdlog_debug(3, "vn_mode (%u)", vni->vn_mode); */
	/*                 fieldscount++; */
	/*         } */
	/* } */

	/* if (fieldscount > 0) { */
	/*         tok = au_to_attr32(vni); */
	/*         PJDLOG_ASSERT(tok != NULL); */
	/*         PJDLOG_VERIFY(au_write(aurd, tok) == 0); */
	/* } */

	/* pjdlog_debug(3, "End %s", __func__); */
}

static void
write_token_exec_args(int aurd, const struct linau_record *record)
{
	/* token_t *tok; */

	PJDLOG_ASSERT(aurd >= 0);
	(void)record;

	/* If there is no argc field then something must be broken. */
	if (!linau_record_exists_field(record, LINAU_FIELD_NAME_ARGC_STR)) {
		return;
	}
}

/*
 * STYLE: It is worth reconsidering if the name of this function should be
 * write_token_path. That is because it does not write a path token only but
 * a text token as well in some cases.
 */
static void
write_token_path(int aurd, const struct linau_record *record)
{
	const char *cwdfieldval;
	const char *namefieldval;
	token_t *tok;

	PJDLOG_ASSERT(aurd >= 0);

	if (linau_record_exists_field(record, LINAU_FIELD_NAME_CWD_STR)) {
		cwdfieldval = linau_record_get_field(record,
		    LINAU_FIELD_NAME_CWD_STR);
	} else {
		cwdfieldval = NULL;
	}
	if (linau_record_exists_field(record, LINAU_FIELD_NAME_NAME_STR)) {
		namefieldval = linau_record_get_field(record,
		    LINAU_FIELD_NAME_NAME_STR);
	} else {
		namefieldval = NULL;
	}

	if (cwdfieldval != NULL && lcfield_cwd.lcf_validate(cwdfieldval)) {
		tok = au_to_path(cwdfieldval);
		PJDLOG_ASSERT(tok != NULL);
		PJDLOG_VERIFY(au_write(aurd, tok) == 0);

		if (namefieldval != NULL) {
			tok = generate_proto_token_text_from_field(record,
			    LINAU_FIELD_NAME_NAME_STR);
			PJDLOG_VERIFY(au_write(aurd, tok) == 0);
		}
	} else if (namefieldval != NULL &&
	    lcfield_name.lcf_validate(namefieldval)) {
		tok = au_to_path(namefieldval);
		PJDLOG_ASSERT(tok != NULL);
		PJDLOG_VERIFY(au_write(aurd, tok) == 0);

		if (cwdfieldval != NULL) {
			tok = generate_proto_token_text_from_field(record,
					LINAU_FIELD_NAME_CWD_STR);
			PJDLOG_VERIFY(au_write(aurd, tok) == 0);
		}
	}
}

/*
 * Returns:
 * - NULL if the token would be written without any fields.  It might happen
 * if all the expected fields are missing (for example no there is no uid)
 * or invalid (for example pid=NONE);
 * - a process token otherwise.
 */
static void
write_token_process32(int aurd, const struct linau_record *record)
{
	token_t *tok;
	au_tid_t *tid;
	size_t fieldscount;
	au_id_t auid;
	gid_t egid;
	uid_t euid;
	pid_t pid;
	gid_t rgid;
	uid_t ruid;
	au_asid_t sid;

	PJDLOG_ASSERT(aurd >= 0);

	pjdlog_debug(3, "%s", __func__);

	fieldscount = 0;

	/* Audit ID.
	 * XXX: It is NOT lcfield_auid. See auid definition in the Linux Audit
	 * field dictionary.
	 */
	/* if (!process_id_field(record,  */
	/*     LINAU_FIELD_NAME_AUID_STR, &lcfield_auid, &auid,  */
	/*     &fieldscount)) */
	auid = 0;

	/* Effective User ID. */
	if (!process_id_field(record, LINAU_FIELD_NAME_EUID_STR,
	    &lcfield_euid, &euid, &fieldscount))
		euid = 0;

	/* Effective Group ID. */
	if (!process_id_field(record, LINAU_FIELD_NAME_EGID_STR,
	    &lcfield_egid, &egid, &fieldscount))
		egid = 0;

	/*
	 * Real User ID.
	 *
	 * XXX: Unavailable AFAIK.
	 */
	ruid = -1;

	/*
	 * Real Group ID.
	 *
	 * XXX: Unavailable AFAIK.
	 */
	rgid = -1;

	/* Process ID. */
	if (!process_id_field(record, LINAU_FIELD_NAME_PID_STR,
	    &lcfield_pid, &pid, &fieldscount))
		pid = -1;

	/*
	 * Session ID.
	 *
	 * XXX: Map to a field which represents login session id in the
	 * Linux Audit format.
	 */
	if (!process_id_field(record, LINAU_FIELD_NAME_SES_STR,
	    &lcfield_ses, &sid, &fieldscount))
		sid = -1;

	/*
	 * Terminal Port ID.
	 *
	 * This is simply a port number.
	 *
	 * XXX: Unavailable AFAIK.
	 */
	sid = -1;

	/*
	 * Terminal Machine Address.
	 *
	 * This is an IP address assosiated with sid, the terminal port id.
	 *
	 * XXX: Unavailable AFAIK.
	 */
	tid = calloc(1, sizeof(*tid));

	if (fieldscount != 0) {
		tok = au_to_process32(auid, euid, egid, ruid, rgid, pid, sid,
		    tid);
		PJDLOG_ASSERT(tok != NULL);
		PJDLOG_VERIFY(au_write(aurd, tok) == 0);
	}

	free(tid);

	pjdlog_debug(3, "End %s", __func__);
}

static void
write_token_return_from_res(int aurd, const struct linau_record *record)
{
	token_t *tok;

	PJDLOG_ASSERT(aurd >= 0);

	tok = generate_proto_token_return(record, LINAU_FIELD_NAME_RES_STR);

	if (tok != NULL)
		PJDLOG_VERIFY(au_write(aurd, tok) == 0);
}

static void
linau_conv_write_unprocessed_fields(int aurd, const struct linau_record *record,
    const struct linau_conv_record_type *lcrectype)
{
	void *cookie;
	const char *fieldname;
	nvlist_t *fields;
	const char *fieldval;
	const struct linau_conv_field *lcfield;
	const struct linau_conv_token *lctoken;
	const char *name;
	nvlist_t *regexfields;
	size_t fi, ti;
	int fieldid;
	int type;

	PJDLOG_ASSERT(lcrectype != NULL);
	PJDLOG_ASSERT(lcrectype->lcrt_tokens != NULL);

	pjdlog_debug(4, "%s", __func__);

	/* Get a copy of fields. */
	fields = linau_record_clone_fields(record);

	/*
	 * Remove all the fields declared by tokens which have a valid value.
	 * This way it is possible to extract all the unprocessed fields.
	 */
	for (ti = 0; lcrectype->lcrt_tokens[ti] != NULL; ti++) {
		lctoken = lcrectype->lcrt_tokens[ti];
		for (fi = 0; lctoken->lct_fields[fi] != NULL; fi++) {
			lcfield = lctoken->lct_fields[fi];
			fieldid = lcfield->lcf_id;
			switch (field_type_from_field_name_id(fieldid)) {
			case LINAU_CONV_FIELD_TYPE_STANDARD:
				fieldname = field_name_from_field_name_id(
				    fieldid);
				if (!nvlist_exists_string(fields, fieldname))
					continue;
				fieldval = nvlist_get_string(fields, fieldname);
				if (lcfield->lcf_validate(fieldval))
					nvlist_free_string(fields, fieldname);
				break;
			case LINAU_CONV_FIELD_TYPE_REGEX:
				pjdlog_debug(4, "Processing a regex field");
				regexfields = lcfield->lcf_match(record);
				/*
				 * XXX: There is no validation of the values
				 * of the regex fields.
				 */
				cookie = NULL;
				while ((name = nvlist_next(regexfields, &type,
				    &cookie)) != NULL) {
					PJDLOG_ASSERT(type == NV_TYPE_STRING);
					/*
					 * TODO: Free this string.
					 * 0mphere
					 */
					/* nvlist_free_string(regexfields, name); */
				}
				break;
			}
		}
	}

	/* Iterate over the unprocessed fields and write them as text tokens. */
	cookie = NULL;
	while ((name = nvlist_next(fields, &type, &cookie)) != NULL) {
		PJDLOG_ASSERT(type == NV_TYPE_STRING);
		pjdlog_debug(4, "name (%s)", name);
		linau_conv_write_token_text(aurd, record, name);
	}

	nvlist_destroy(fields);

	pjdlog_debug(4, "End %s", __func__);
}

static void
linau_conv_write_token_text(int aurd, const struct linau_record *record,
    const char *name)
{
	token_t *tok;

	PJDLOG_ASSERT(aurd >= 0);

	tok = generate_proto_token_text_from_field(record, name);

	if (tok != NULL)
		PJDLOG_VERIFY(au_write(aurd, tok) == 0);
}

static void
linau_conv_process_record(int aurd, const struct linau_record *record,
    const struct linau_conv_record_type *lcrectype)
{
	size_t ti;

	PJDLOG_ASSERT(lcrectype != NULL);
	PJDLOG_ASSERT(lcrectype->lcrt_tokens != NULL);

	pjdlog_debug(3, "%s", __func__);

	for (ti = 0; lcrectype->lcrt_tokens[ti] != NULL; ti++)
		lcrectype->lcrt_tokens[ti]->lct_write(aurd, record);

	linau_conv_write_unprocessed_fields(aurd, record, lcrectype);

	pjdlog_debug(3, "End %s", __func__);
}

/*
 * It does make sense to require passing typenum here.  It allows the
 * interpretation based on typenum which is more flexible than an
 * interpretation based on a record type.  This is because the user might
 * want to interpret the record in a non-standard way.  They can achieve
 * it by modifying the library and passing a custom typenum.
 */
void
linau_conv_to_au(int aurd, const struct linau_record *record, int typenum)
{

	switch (typenum) {
	case LINAU_TYPE_UNDEFINED:
		linau_conv_process_record(aurd, record,
		    &lcrectype_undefined);
		break;
	/* case LINAU_TYPE_GET: */
	/* case LINAU_TYPE_SET: */
	/* case LINAU_TYPE_LIST: */
	/* case LINAU_TYPE_ADD: */
	/* case LINAU_TYPE_DEL: */
	case LINAU_TYPE_USER:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user);
		break;
	case LINAU_TYPE_LOGIN:
		linau_conv_process_record(aurd, record,
		    &lcrectype_login);
		break;
	/* case LINAU_TYPE_SIGNAL_INFO: */
	/* case LINAU_TYPE_ADD_RULE: */
	/* case LINAU_TYPE_DEL_RULE: */
	/* case LINAU_TYPE_LIST_RULES: */
	/* case LINAU_TYPE_TRIM: */
	/* case LINAU_TYPE_MAKE_EQUIV: */
	/* case LINAU_TYPE_TTY_GET: */
	/* case LINAU_TYPE_TTY_SET: */
	/* case LINAU_TYPE_SET_FEATURE: */
	/* case LINAU_TYPE_GET_FEATURE: */
	case LINAU_TYPE_USER_AUTH:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_auth);
		break;
	case LINAU_TYPE_USER_ACCT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_acct);
		break;
	case LINAU_TYPE_USER_MGMT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_mgmt);
		break;
	case LINAU_TYPE_CRED_ACQ:
		linau_conv_process_record(aurd, record,
		    &lcrectype_cred_acq);
		break;
	case LINAU_TYPE_CRED_DISP:
		linau_conv_process_record(aurd, record,
		    &lcrectype_cred_disp);
		break;
	case LINAU_TYPE_USER_START:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_start);
		break;
	case LINAU_TYPE_USER_END:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_end);
		break;
	case LINAU_TYPE_USER_AVC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_avc);
		break;
	case LINAU_TYPE_USER_CHAUTHTOK:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_chauthtok);
		break;
	case LINAU_TYPE_USER_ERR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_err);
		break;
	case LINAU_TYPE_CRED_REFR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_cred_refr);
		break;
	case LINAU_TYPE_USYS_CONFIG:
		linau_conv_process_record(aurd, record,
		    &lcrectype_usys_config);
		break;
	case LINAU_TYPE_USER_LOGIN:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_login);
		break;
	case LINAU_TYPE_USER_LOGOUT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_logout);
		break;
	case LINAU_TYPE_ADD_USER:
		linau_conv_process_record(aurd, record,
		    &lcrectype_add_user);
		break;
	case LINAU_TYPE_DEL_USER:
		linau_conv_process_record(aurd, record,
		    &lcrectype_del_user);
		break;
	case LINAU_TYPE_ADD_GROUP:
		linau_conv_process_record(aurd, record,
		    &lcrectype_add_group);
		break;
	case LINAU_TYPE_DEL_GROUP:
		linau_conv_process_record(aurd, record,
		    &lcrectype_del_group);
		break;
	case LINAU_TYPE_DAC_CHECK:
		linau_conv_process_record(aurd, record,
		    &lcrectype_dac_check);
		break;
	case LINAU_TYPE_CHGRP_ID:
		linau_conv_process_record(aurd, record,
		    &lcrectype_chgrp_id);
		break;
	case LINAU_TYPE_TEST:
		linau_conv_process_record(aurd, record,
		    &lcrectype_test);
		break;
	case LINAU_TYPE_TRUSTED_APP:
		linau_conv_process_record(aurd, record,
		    &lcrectype_trusted_app);
		break;
	case LINAU_TYPE_USER_SELINUX_ERR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_selinux_err);
		break;
	case LINAU_TYPE_USER_CMD:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_cmd);
		break;
	case LINAU_TYPE_USER_TTY:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_tty);
		break;
	case LINAU_TYPE_CHUSER_ID:
		linau_conv_process_record(aurd, record,
		    &lcrectype_chuser_id);
		break;
	case LINAU_TYPE_GRP_AUTH:
		linau_conv_process_record(aurd, record,
		    &lcrectype_grp_auth);
		break;
	case LINAU_TYPE_MAC_CHECK:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_check);
		break;
	case LINAU_TYPE_ACCT_LOCK:
		linau_conv_process_record(aurd, record,
		    &lcrectype_acct_lock);
		break;
	case LINAU_TYPE_ACCT_UNLOCK:
		linau_conv_process_record(aurd, record,
		    &lcrectype_acct_unlock);
		break;
	case LINAU_TYPE_SYSTEM_BOOT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_system_boot);
		break;
	case LINAU_TYPE_SYSTEM_SHUTDOWN:
		linau_conv_process_record(aurd, record,
		    &lcrectype_system_shutdown);
		break;
	case LINAU_TYPE_SYSTEM_RUNLEVEL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_system_runlevel);
		break;
	case LINAU_TYPE_SERVICE_START:
		linau_conv_process_record(aurd, record,
		    &lcrectype_service_start);
		break;
	case LINAU_TYPE_SERVICE_STOP:
		linau_conv_process_record(aurd, record,
		    &lcrectype_service_stop);
		break;
	case LINAU_TYPE_GRP_MGMT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_grp_mgmt);
		break;
	case LINAU_TYPE_GRP_CHAUTHTOK:
		linau_conv_process_record(aurd, record,
		    &lcrectype_grp_chauthtok);
		break;
	case LINAU_TYPE_DAEMON_START:
		linau_conv_process_record(aurd, record,
		    &lcrectype_daemon_start);
		break;
	case LINAU_TYPE_DAEMON_END:
		linau_conv_process_record(aurd, record,
		    &lcrectype_daemon_end);
		break;
	case LINAU_TYPE_DAEMON_ABORT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_daemon_abort);
		break;
	case LINAU_TYPE_DAEMON_CONFIG:
		linau_conv_process_record(aurd, record,
		    &lcrectype_daemon_config);
		break;
	/* case LINAU_TYPE_DAEMON_RECONFIG: */
	case LINAU_TYPE_DAEMON_ROTATE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_daemon_rotate);
		break;
	case LINAU_TYPE_DAEMON_RESUME:
		linau_conv_process_record(aurd, record,
		    &lcrectype_daemon_resume);
		break;
	case LINAU_TYPE_DAEMON_ACCEPT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_daemon_accept);
		break;
	case LINAU_TYPE_DAEMON_CLOSE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_daemon_close);
		break;
	case LINAU_TYPE_DAEMON_ERR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_daemon_err);
		break;
	case LINAU_TYPE_SYSCALL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_syscall);
		break;
	/* case LINAU_TYPE_FS_WATCH: */
	case LINAU_TYPE_PATH:
		linau_conv_process_record(aurd, record,
		    &lcrectype_path);
		break;
	case LINAU_TYPE_IPC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_ipc);
		break;
	case LINAU_TYPE_SOCKETCALL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_socketcall);
		break;
	case LINAU_TYPE_CONFIG_CHANGE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_config_change);
		break;
	case LINAU_TYPE_SOCKADDR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_sockaddr);
		break;
	case LINAU_TYPE_CWD:
		linau_conv_process_record(aurd, record,
		    &lcrectype_cwd);
		break;
	/* case LINAU_TYPE_FS_INODE: */
	case LINAU_TYPE_EXECVE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_execve);
		break;
	case LINAU_TYPE_IPC_SET_PERM:
		linau_conv_process_record(aurd, record,
		    &lcrectype_ipc_set_perm);
		break;
	case LINAU_TYPE_MQ_OPEN:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mq_open);
		break;
	case LINAU_TYPE_MQ_SENDRECV:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mq_sendrecv);
		break;
	case LINAU_TYPE_MQ_NOTIFY:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mq_notify);
		break;
	case LINAU_TYPE_MQ_GETSETATTR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mq_getsetattr);
		break;
	case LINAU_TYPE_KERNEL_OTHER:
		linau_conv_process_record(aurd, record,
		    &lcrectype_kernel_other);
		break;
	case LINAU_TYPE_FD_PAIR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_fd_pair);
		break;
	case LINAU_TYPE_OBJ_PID:
		linau_conv_process_record(aurd, record,
		    &lcrectype_obj_pid);
		break;
	case LINAU_TYPE_TTY:
		linau_conv_process_record(aurd, record,
		    &lcrectype_tty);
		break;
	case LINAU_TYPE_EOE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_eoe);
		break;
	case LINAU_TYPE_BPRM_FCAPS:
		linau_conv_process_record(aurd, record,
		    &lcrectype_bprm_fcaps);
		break;
	case LINAU_TYPE_CAPSET:
		linau_conv_process_record(aurd, record,
		    &lcrectype_capset);
		break;
	case LINAU_TYPE_MMAP:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mmap);
		break;
	case LINAU_TYPE_NETFILTER_PKT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_netfilter_pkt);
		break;
	case LINAU_TYPE_NETFILTER_CFG:
		linau_conv_process_record(aurd, record,
		    &lcrectype_netfilter_cfg);
		break;
	case LINAU_TYPE_SECCOMP:
		linau_conv_process_record(aurd, record,
		    &lcrectype_seccomp);
		break;
	case LINAU_TYPE_PROCTITLE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_proctitle);
		break;
	case LINAU_TYPE_FEATURE_CHANGE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_feature_change);
		break;
	case LINAU_TYPE_AVC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_avc);
		break;
	case LINAU_TYPE_SELINUX_ERR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_selinux_err);
		break;
	case LINAU_TYPE_AVC_PATH:
		linau_conv_process_record(aurd, record,
		    &lcrectype_avc_path);
		break;
	case LINAU_TYPE_MAC_POLICY_LOAD:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_policy_load);
		break;
	case LINAU_TYPE_MAC_STATUS:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_status);
		break;
	case LINAU_TYPE_MAC_CONFIG_CHANGE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_config_change);
		break;
	case LINAU_TYPE_MAC_UNLBL_ALLOW:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_unlbl_allow);
		break;
	case LINAU_TYPE_MAC_CIPSOV4_ADD:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_cipsov4_add);
		break;
	case LINAU_TYPE_MAC_CIPSOV4_DEL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_cipsov4_del);
		break;
	case LINAU_TYPE_MAC_MAP_ADD:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_map_add);
		break;
	case LINAU_TYPE_MAC_MAP_DEL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_map_del);
		break;
	case LINAU_TYPE_MAC_IPSEC_ADDSA:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_ipsec_addsa);
		break;
	case LINAU_TYPE_MAC_IPSEC_DELSA:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_ipsec_delsa);
		break;
	case LINAU_TYPE_MAC_IPSEC_ADDSPD:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_ipsec_addspd);
		break;
	case LINAU_TYPE_MAC_IPSEC_DELSPD:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_ipsec_delspd);
		break;
	case LINAU_TYPE_MAC_IPSEC_EVENT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_ipsec_event);
		break;
	case LINAU_TYPE_MAC_UNLBL_STCADD:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_unlbl_stcadd);
		break;
	case LINAU_TYPE_MAC_UNLBL_STCDEL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_mac_unlbl_stcdel);
		break;
	case LINAU_TYPE_ANOM_PROMISCUOUS:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_promiscuous);
		break;
	case LINAU_TYPE_ANOM_ABEND:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_abend);
		break;
	case LINAU_TYPE_ANOM_LINK:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_link);
		break;
	case LINAU_TYPE_INTEGRITY_DATA:
		linau_conv_process_record(aurd, record,
		    &lcrectype_integrity_data);
		break;
	case LINAU_TYPE_INTEGRITY_METADATA:
		linau_conv_process_record(aurd, record,
		    &lcrectype_integrity_metadata);
		break;
	case LINAU_TYPE_INTEGRITY_STATUS:
		linau_conv_process_record(aurd, record,
		    &lcrectype_integrity_status);
		break;
	case LINAU_TYPE_INTEGRITY_HASH:
		linau_conv_process_record(aurd, record,
		    &lcrectype_integrity_hash);
		break;
	case LINAU_TYPE_INTEGRITY_PCR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_integrity_pcr);
		break;
	case LINAU_TYPE_INTEGRITY_RULE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_integrity_rule);
		break;
	case LINAU_TYPE_AA:
		linau_conv_process_record(aurd, record,
		    &lcrectype_aa);
		break;
	case LINAU_TYPE_APPARMOR_AUDIT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_apparmor_audit);
		break;
	case LINAU_TYPE_APPARMOR_ALLOWED:
		linau_conv_process_record(aurd, record,
		    &lcrectype_apparmor_allowed);
		break;
	case LINAU_TYPE_APPARMOR_DENIED:
		linau_conv_process_record(aurd, record,
		    &lcrectype_apparmor_denied);
		break;
	case LINAU_TYPE_APPARMOR_HINT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_apparmor_hint);
		break;
		/* FALLTHROUGH */
	case LINAU_TYPE_APPARMOR_STATUS:
		linau_conv_process_record(aurd, record,
		    &lcrectype_apparmor_status);
		break;
	case LINAU_TYPE_APPARMOR_ERROR:
		linau_conv_process_record(aurd, record,
		    &lcrectype_apparmor_error);
		break;
	case LINAU_TYPE_KERNEL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_kernel);
		break;
	case LINAU_TYPE_ANOM_LOGIN_FAILURES:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_login_failures);
		break;
	case LINAU_TYPE_ANOM_LOGIN_TIME:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_login_time);
		break;
	case LINAU_TYPE_ANOM_LOGIN_SESSIONS:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_login_sessions);
		break;
	case LINAU_TYPE_ANOM_LOGIN_ACCT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_login_acct);
		break;
	case LINAU_TYPE_ANOM_LOGIN_LOCATION:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_login_location);
		break;
	case LINAU_TYPE_ANOM_MAX_DAC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_max_dac);
		break;
	case LINAU_TYPE_ANOM_MAX_MAC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_max_mac);
		break;
	case LINAU_TYPE_ANOM_AMTU_FAIL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_amtu_fail);
		break;
	case LINAU_TYPE_ANOM_RBAC_FAIL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_rbac_fail);
		break;
	case LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_rbac_integrity_fail);
		break;
	case LINAU_TYPE_ANOM_CRYPTO_FAIL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_crypto_fail);
		break;
	case LINAU_TYPE_ANOM_ACCESS_FS:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_access_fs);
		break;
	case LINAU_TYPE_ANOM_EXEC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_exec);
		break;
	case LINAU_TYPE_ANOM_MK_EXEC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_mk_exec);
		break;
	case LINAU_TYPE_ANOM_ADD_ACCT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_add_acct);
		break;
	case LINAU_TYPE_ANOM_DEL_ACCT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_del_acct);
		break;
	case LINAU_TYPE_ANOM_MOD_ACCT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_mod_acct);
		break;
	case LINAU_TYPE_ANOM_ROOT_TRANS:
		linau_conv_process_record(aurd, record,
		    &lcrectype_anom_root_trans);
		break;
	case LINAU_TYPE_RESP_ANOMALY:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_anomaly);
		break;
	case LINAU_TYPE_RESP_ALERT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_alert);
		break;
	case LINAU_TYPE_RESP_KILL_PROC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_kill_proc);
		break;
	case LINAU_TYPE_RESP_TERM_ACCESS:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_term_access);
		break;
	case LINAU_TYPE_RESP_ACCT_REMOTE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_acct_remote);
		break;
	case LINAU_TYPE_RESP_ACCT_LOCK_TIMED:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_acct_lock_timed);
		break;
	case LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_acct_unlock_timed);
		break;
	case LINAU_TYPE_RESP_ACCT_LOCK:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_acct_lock);
		break;
	case LINAU_TYPE_RESP_TERM_LOCK:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_term_lock);
		break;
	case LINAU_TYPE_RESP_SEBOOL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_sebool);
		break;
	case LINAU_TYPE_RESP_EXEC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_exec);
		break;
	case LINAU_TYPE_RESP_SINGLE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_single);
		break;
	case LINAU_TYPE_RESP_HALT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_resp_halt);
		break;
	case LINAU_TYPE_USER_ROLE_CHANGE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_role_change);
		break;
	case LINAU_TYPE_ROLE_ASSIGN:
		linau_conv_process_record(aurd, record,
		    &lcrectype_role_assign);
		break;
	case LINAU_TYPE_ROLE_REMOVE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_role_remove);
		break;
	case LINAU_TYPE_LABEL_OVERRIDE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_label_override);
		break;
	case LINAU_TYPE_LABEL_LEVEL_CHANGE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_label_level_change);
		break;
	case LINAU_TYPE_USER_LABELED_EXPORT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_labeled_export);
		break;
	case LINAU_TYPE_USER_UNLABELED_EXPORT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_unlabeled_export);
		break;
	case LINAU_TYPE_DEV_ALLOC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_dev_alloc);
		break;
	case LINAU_TYPE_DEV_DEALLOC:
		linau_conv_process_record(aurd, record,
		    &lcrectype_dev_dealloc);
		break;
	case LINAU_TYPE_FS_RELABEL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_fs_relabel);
		break;
	case LINAU_TYPE_USER_MAC_POLICY_LOAD:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_mac_policy_load);
		break;
	case LINAU_TYPE_ROLE_MODIFY:
		linau_conv_process_record(aurd, record,
		    &lcrectype_role_modify);
		break;
	case LINAU_TYPE_USER_MAC_CONFIG_CHANGE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_user_mac_config_change);
		break;
	case LINAU_TYPE_CRYPTO_TEST_USER:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_test_user);
		break;
	case LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_param_change_user);
		break;
	case LINAU_TYPE_CRYPTO_LOGIN:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_login);
		break;
	case LINAU_TYPE_CRYPTO_LOGOUT:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_logout);
		break;
	case LINAU_TYPE_CRYPTO_KEY_USER:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_key_user);
		break;
	case LINAU_TYPE_CRYPTO_FAILURE_USER:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_failure_user);
		break;
	case LINAU_TYPE_CRYPTO_REPLAY_USER:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_replay_user);
		break;
	case LINAU_TYPE_CRYPTO_SESSION:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_session);
		break;
	case LINAU_TYPE_CRYPTO_IKE_SA:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_ike_sa);
		break;
	case LINAU_TYPE_CRYPTO_IPSEC_SA:
		linau_conv_process_record(aurd, record,
		    &lcrectype_crypto_ipsec_sa);
		break;
	case LINAU_TYPE_VIRT_CONTROL:
		linau_conv_process_record(aurd, record,
		    &lcrectype_virt_control);
		break;
	case LINAU_TYPE_VIRT_RESOURCE:
		linau_conv_process_record(aurd, record,
		    &lcrectype_virt_resource);
		break;
	case LINAU_TYPE_VIRT_MACHINE_ID:
		linau_conv_process_record(aurd, record,
		    &lcrectype_virt_machine_id);
		break;
	default:
		PJDLOG_ABORT("The type of the record is set neither to "
		    "a type from the Linux Audit standard nor to an undefined "
		    "type. If the type is not standard then "
		    "LINAU_TYPE_UNDEFINED must be used");
	}
}

/*
 * STYLE: Should I change those if's to else if's?
 *
 * STYLE: And how about using this macro instead:
 * #define	RETURN_IF_EQUAL(str1, str2, retval) do {		\
 *         if (strcmp((str1), (str2)) == 0)				\
 *                 return ((retval));					\
 * } while(0);								\
 *
 * Mariusz says that I should use else if's but I am not fully convinced yet.
 * else if's would damage the readability due to the presence of the commented
 * out deprecated defines like LINAU_TYPE_GET_STR.
 */
int
linau_conv_get_type_number(const char *type)
{

	PJDLOG_ASSERT(type != NULL);

	pjdlog_debug(3, "%s", __func__);
	pjdlog_debug(3, "%s", type);

	/* if (strcmp(type, LINAU_TYPE_GET_STR) == 0) */
	/*         return (LINAU_TYPE_GET); */
	/* if (strcmp(type, LINAU_TYPE_SET_STR) == 0) */
	/*         return (LINAU_TYPE_SET); */
	/* if (strcmp(type, LINAU_TYPE_LIST_STR) == 0) */
	/*         return (LINAU_TYPE_LIST); */
	/* if (strcmp(type, LINAU_TYPE_ADD_STR) == 0) */
	/*         return (LINAU_TYPE_ADD); */
	/* if (strcmp(type, LINAU_TYPE_DEL_STR) == 0) */
	/*         return (LINAU_TYPE_DEL); */
	if (strcmp(type, LINAU_TYPE_USER_STR) == 0)
		return (LINAU_TYPE_USER);
	if (strcmp(type, LINAU_TYPE_LOGIN_STR) == 0)
		return (LINAU_TYPE_LOGIN);
	/* if (strcmp(type, LINAU_TYPE_SIGNAL_INFO_STR) == 0) */
	/*         return (LINAU_TYPE_SIGNAL_INFO); */
	/* if (strcmp(type, LINAU_TYPE_ADD_RULE_STR) == 0) */
	/*         return (LINAU_TYPE_ADD_RULE); */
	/* if (strcmp(type, LINAU_TYPE_DEL_RULE_STR) == 0) */
	/*         return (LINAU_TYPE_DEL_RULE); */
	/* if (strcmp(type, LINAU_TYPE_LIST_RULES_STR) == 0) */
	/*         return (LINAU_TYPE_LIST_RULES); */
	/* if (strcmp(type, LINAU_TYPE_TRIM_STR) == 0) */
	/*         return (LINAU_TYPE_TRIM); */
	/* if (strcmp(type, LINAU_TYPE_MAKE_EQUIV_STR) == 0) */
	/*         return (LINAU_TYPE_MAKE_EQUIV); */
	/* if (strcmp(type, LINAU_TYPE_TTY_GET_STR) == 0) */
	/*         return (LINAU_TYPE_TTY_GET); */
	/* if (strcmp(type, LINAU_TYPE_TTY_SET_STR) == 0) */
	/*         return (LINAU_TYPE_TTY_SET); */
	/* if (strcmp(type, LINAU_TYPE_SET_FEATURE_STR) == 0) */
	/*         return (LINAU_TYPE_SET_FEATURE); */
	/* if (strcmp(type, LINAU_TYPE_GET_FEATURE_STR) == 0) */
	/*         return (LINAU_TYPE_GET_FEATURE); */
	if (strcmp(type, LINAU_TYPE_USER_AUTH_STR) == 0)
		return (LINAU_TYPE_USER_AUTH);
	if (strcmp(type, LINAU_TYPE_USER_ACCT_STR) == 0)
		return (LINAU_TYPE_USER_ACCT);
	if (strcmp(type, LINAU_TYPE_USER_MGMT_STR) == 0)
		return (LINAU_TYPE_USER_MGMT);
	if (strcmp(type, LINAU_TYPE_CRED_ACQ_STR) == 0)
		return (LINAU_TYPE_CRED_ACQ);
	if (strcmp(type, LINAU_TYPE_CRED_DISP_STR) == 0)
		return (LINAU_TYPE_CRED_DISP);
	if (strcmp(type, LINAU_TYPE_USER_START_STR) == 0)
		return (LINAU_TYPE_USER_START);
	if (strcmp(type, LINAU_TYPE_USER_END_STR) == 0)
		return (LINAU_TYPE_USER_END);
	if (strcmp(type, LINAU_TYPE_USER_AVC_STR) == 0)
		return (LINAU_TYPE_USER_AVC);
	if (strcmp(type, LINAU_TYPE_USER_CHAUTHTOK_STR) == 0)
		return (LINAU_TYPE_USER_CHAUTHTOK);
	if (strcmp(type, LINAU_TYPE_USER_ERR_STR) == 0)
		return (LINAU_TYPE_USER_ERR);
	if (strcmp(type, LINAU_TYPE_CRED_REFR_STR) == 0)
		return (LINAU_TYPE_CRED_REFR);
	if (strcmp(type, LINAU_TYPE_USYS_CONFIG_STR) == 0)
		return (LINAU_TYPE_USYS_CONFIG);
	if (strcmp(type, LINAU_TYPE_USER_LOGIN_STR) == 0)
		return (LINAU_TYPE_USER_LOGIN);
	if (strcmp(type, LINAU_TYPE_USER_LOGOUT_STR) == 0)
		return (LINAU_TYPE_USER_LOGOUT);
	if (strcmp(type, LINAU_TYPE_ADD_USER_STR) == 0)
		return (LINAU_TYPE_ADD_USER);
	if (strcmp(type, LINAU_TYPE_DEL_USER_STR) == 0)
		return (LINAU_TYPE_DEL_USER);
	if (strcmp(type, LINAU_TYPE_ADD_GROUP_STR) == 0)
		return (LINAU_TYPE_ADD_GROUP);
	if (strcmp(type, LINAU_TYPE_DEL_GROUP_STR) == 0)
		return (LINAU_TYPE_DEL_GROUP);
	if (strcmp(type, LINAU_TYPE_DAC_CHECK_STR) == 0)
		return (LINAU_TYPE_DAC_CHECK);
	if (strcmp(type, LINAU_TYPE_CHGRP_ID_STR) == 0)
		return (LINAU_TYPE_CHGRP_ID);
	if (strcmp(type, LINAU_TYPE_TEST_STR) == 0)
		return (LINAU_TYPE_TEST);
	if (strcmp(type, LINAU_TYPE_TRUSTED_APP_STR) == 0)
		return (LINAU_TYPE_TRUSTED_APP);
	if (strcmp(type, LINAU_TYPE_USER_SELINUX_ERR_STR) == 0)
		return (LINAU_TYPE_USER_SELINUX_ERR);
	if (strcmp(type, LINAU_TYPE_USER_CMD_STR) == 0)
		return (LINAU_TYPE_USER_CMD);
	if (strcmp(type, LINAU_TYPE_USER_TTY_STR) == 0)
		return (LINAU_TYPE_USER_TTY);
	if (strcmp(type, LINAU_TYPE_CHUSER_ID_STR) == 0)
		return (LINAU_TYPE_CHUSER_ID);
	if (strcmp(type, LINAU_TYPE_GRP_AUTH_STR) == 0)
		return (LINAU_TYPE_GRP_AUTH);
	if (strcmp(type, LINAU_TYPE_MAC_CHECK_STR) == 0)
		return (LINAU_TYPE_MAC_CHECK);
	if (strcmp(type, LINAU_TYPE_ACCT_LOCK_STR) == 0)
		return (LINAU_TYPE_ACCT_LOCK);
	if (strcmp(type, LINAU_TYPE_ACCT_UNLOCK_STR) == 0)
		return (LINAU_TYPE_ACCT_UNLOCK);
	if (strcmp(type, LINAU_TYPE_SYSTEM_BOOT_STR) == 0)
		return (LINAU_TYPE_SYSTEM_BOOT);
	if (strcmp(type, LINAU_TYPE_SYSTEM_SHUTDOWN_STR) == 0)
		return (LINAU_TYPE_SYSTEM_SHUTDOWN);
	if (strcmp(type, LINAU_TYPE_SYSTEM_RUNLEVEL_STR) == 0)
		return (LINAU_TYPE_SYSTEM_RUNLEVEL);
	if (strcmp(type, LINAU_TYPE_SERVICE_START_STR) == 0)
		return (LINAU_TYPE_SERVICE_START);
	if (strcmp(type, LINAU_TYPE_SERVICE_STOP_STR) == 0)
		return (LINAU_TYPE_SERVICE_STOP);
	if (strcmp(type, LINAU_TYPE_GRP_MGMT_STR) == 0)
		return (LINAU_TYPE_GRP_MGMT);
	if (strcmp(type, LINAU_TYPE_GRP_CHAUTHTOK_STR) == 0)
		return (LINAU_TYPE_GRP_CHAUTHTOK);
	if (strcmp(type, LINAU_TYPE_DAEMON_START_STR) == 0)
		return (LINAU_TYPE_DAEMON_START);
	if (strcmp(type, LINAU_TYPE_DAEMON_END_STR) == 0)
		return (LINAU_TYPE_DAEMON_END);
	if (strcmp(type, LINAU_TYPE_DAEMON_ABORT_STR) == 0)
		return (LINAU_TYPE_DAEMON_ABORT);
	if (strcmp(type, LINAU_TYPE_DAEMON_CONFIG_STR) == 0)
		return (LINAU_TYPE_DAEMON_CONFIG);
	/* if (strcmp(type, LINAU_TYPE_DAEMON_RECONFIG_STR) == 0) */
	/*         return (LINAU_TYPE_DAEMON_RECONFIG); */
	if (strcmp(type, LINAU_TYPE_DAEMON_ROTATE_STR) == 0)
		return (LINAU_TYPE_DAEMON_ROTATE);
	if (strcmp(type, LINAU_TYPE_DAEMON_RESUME_STR) == 0)
		return (LINAU_TYPE_DAEMON_RESUME);
	if (strcmp(type, LINAU_TYPE_DAEMON_ACCEPT_STR) == 0)
		return (LINAU_TYPE_DAEMON_ACCEPT);
	if (strcmp(type, LINAU_TYPE_DAEMON_CLOSE_STR) == 0)
		return (LINAU_TYPE_DAEMON_CLOSE);
	if (strcmp(type, LINAU_TYPE_DAEMON_ERR_STR) == 0)
		return (LINAU_TYPE_DAEMON_ERR);
	if (strcmp(type, LINAU_TYPE_SYSCALL_STR) == 0)
		return (LINAU_TYPE_SYSCALL);
	/* if (strcmp(type, LINAU_TYPE_FS_WATCH_STR) == 0) */
	/*         return (LINAU_TYPE_FS_WATCH); */
	if (strcmp(type, LINAU_TYPE_PATH_STR) == 0)
		return (LINAU_TYPE_PATH);
	if (strcmp(type, LINAU_TYPE_IPC_STR) == 0)
		return (LINAU_TYPE_IPC);
	if (strcmp(type, LINAU_TYPE_SOCKETCALL_STR) == 0)
		return (LINAU_TYPE_SOCKETCALL);
	if (strcmp(type, LINAU_TYPE_CONFIG_CHANGE_STR) == 0)
		return (LINAU_TYPE_CONFIG_CHANGE);
	if (strcmp(type, LINAU_TYPE_SOCKADDR_STR) == 0)
		return (LINAU_TYPE_SOCKADDR);
	if (strcmp(type, LINAU_TYPE_CWD_STR) == 0)
		return (LINAU_TYPE_CWD);
	/* if (strcmp(type, LINAU_TYPE_FS_INODE_STR) == 0) */
	/*         return (LINAU_TYPE_FS_INODE); */
	if (strcmp(type, LINAU_TYPE_EXECVE_STR) == 0)
		return (LINAU_TYPE_EXECVE);
	if (strcmp(type, LINAU_TYPE_IPC_SET_PERM_STR) == 0)
		return (LINAU_TYPE_IPC_SET_PERM);
	if (strcmp(type, LINAU_TYPE_MQ_OPEN_STR) == 0)
		return (LINAU_TYPE_MQ_OPEN);
	if (strcmp(type, LINAU_TYPE_MQ_SENDRECV_STR) == 0)
		return (LINAU_TYPE_MQ_SENDRECV);
	if (strcmp(type, LINAU_TYPE_MQ_NOTIFY_STR) == 0)
		return (LINAU_TYPE_MQ_NOTIFY);
	if (strcmp(type, LINAU_TYPE_MQ_GETSETATTR_STR) == 0)
		return (LINAU_TYPE_MQ_GETSETATTR);
	if (strcmp(type, LINAU_TYPE_KERNEL_OTHER_STR) == 0)
		return (LINAU_TYPE_KERNEL_OTHER);
	if (strcmp(type, LINAU_TYPE_FD_PAIR_STR) == 0)
		return (LINAU_TYPE_FD_PAIR);
	if (strcmp(type, LINAU_TYPE_OBJ_PID_STR) == 0)
		return (LINAU_TYPE_OBJ_PID);
	if (strcmp(type, LINAU_TYPE_TTY_STR) == 0)
		return (LINAU_TYPE_TTY);
	if (strcmp(type, LINAU_TYPE_EOE_STR) == 0)
		return (LINAU_TYPE_EOE);
	if (strcmp(type, LINAU_TYPE_BPRM_FCAPS_STR) == 0)
		return (LINAU_TYPE_BPRM_FCAPS);
	if (strcmp(type, LINAU_TYPE_CAPSET_STR) == 0)
		return (LINAU_TYPE_CAPSET);
	if (strcmp(type, LINAU_TYPE_MMAP_STR) == 0)
		return (LINAU_TYPE_MMAP);
	if (strcmp(type, LINAU_TYPE_NETFILTER_PKT_STR) == 0)
		return (LINAU_TYPE_NETFILTER_PKT);
	if (strcmp(type, LINAU_TYPE_NETFILTER_CFG_STR) == 0)
		return (LINAU_TYPE_NETFILTER_CFG);
	if (strcmp(type, LINAU_TYPE_SECCOMP_STR) == 0)
		return (LINAU_TYPE_SECCOMP);
	if (strcmp(type, LINAU_TYPE_PROCTITLE_STR) == 0)
		return (LINAU_TYPE_PROCTITLE);
	if (strcmp(type, LINAU_TYPE_FEATURE_CHANGE_STR) == 0)
		return (LINAU_TYPE_FEATURE_CHANGE);
	if (strcmp(type, LINAU_TYPE_AVC_STR) == 0)
		return (LINAU_TYPE_AVC);
	if (strcmp(type, LINAU_TYPE_SELINUX_ERR_STR) == 0)
		return (LINAU_TYPE_SELINUX_ERR);
	if (strcmp(type, LINAU_TYPE_AVC_PATH_STR) == 0)
		return (LINAU_TYPE_AVC_PATH);
	if (strcmp(type, LINAU_TYPE_MAC_POLICY_LOAD_STR) == 0)
		return (LINAU_TYPE_MAC_POLICY_LOAD);
	if (strcmp(type, LINAU_TYPE_MAC_STATUS_STR) == 0)
		return (LINAU_TYPE_MAC_STATUS);
	if (strcmp(type, LINAU_TYPE_MAC_CONFIG_CHANGE_STR) == 0)
		return (LINAU_TYPE_MAC_CONFIG_CHANGE);
	if (strcmp(type, LINAU_TYPE_MAC_UNLBL_ALLOW_STR) == 0)
		return (LINAU_TYPE_MAC_UNLBL_ALLOW);
	if (strcmp(type, LINAU_TYPE_MAC_CIPSOV4_ADD_STR) == 0)
		return (LINAU_TYPE_MAC_CIPSOV4_ADD);
	if (strcmp(type, LINAU_TYPE_MAC_CIPSOV4_DEL_STR) == 0)
		return (LINAU_TYPE_MAC_CIPSOV4_DEL);
	if (strcmp(type, LINAU_TYPE_MAC_MAP_ADD_STR) == 0)
		return (LINAU_TYPE_MAC_MAP_ADD);
	if (strcmp(type, LINAU_TYPE_MAC_MAP_DEL_STR) == 0)
		return (LINAU_TYPE_MAC_MAP_DEL);
	if (strcmp(type, LINAU_TYPE_MAC_IPSEC_ADDSA_STR) == 0)
		return (LINAU_TYPE_MAC_IPSEC_ADDSA);
	if (strcmp(type, LINAU_TYPE_MAC_IPSEC_DELSA_STR) == 0)
		return (LINAU_TYPE_MAC_IPSEC_DELSA);
	if (strcmp(type, LINAU_TYPE_MAC_IPSEC_ADDSPD_STR) == 0)
		return (LINAU_TYPE_MAC_IPSEC_ADDSPD);
	if (strcmp(type, LINAU_TYPE_MAC_IPSEC_DELSPD_STR) == 0)
		return (LINAU_TYPE_MAC_IPSEC_DELSPD);
	if (strcmp(type, LINAU_TYPE_MAC_IPSEC_EVENT_STR) == 0)
		return (LINAU_TYPE_MAC_IPSEC_EVENT);
	if (strcmp(type, LINAU_TYPE_MAC_UNLBL_STCADD_STR) == 0)
		return (LINAU_TYPE_MAC_UNLBL_STCADD);
	if (strcmp(type, LINAU_TYPE_MAC_UNLBL_STCDEL_STR) == 0)
		return (LINAU_TYPE_MAC_UNLBL_STCDEL);
	if (strcmp(type, LINAU_TYPE_ANOM_PROMISCUOUS_STR) == 0)
		return (LINAU_TYPE_ANOM_PROMISCUOUS);
	if (strcmp(type, LINAU_TYPE_ANOM_ABEND_STR) == 0)
		return (LINAU_TYPE_ANOM_ABEND);
	if (strcmp(type, LINAU_TYPE_ANOM_LINK_STR) == 0)
		return (LINAU_TYPE_ANOM_LINK);
	if (strcmp(type, LINAU_TYPE_INTEGRITY_DATA_STR) == 0)
		return (LINAU_TYPE_INTEGRITY_DATA);
	if (strcmp(type, LINAU_TYPE_INTEGRITY_METADATA_STR) == 0)
		return (LINAU_TYPE_INTEGRITY_METADATA);
	if (strcmp(type, LINAU_TYPE_INTEGRITY_STATUS_STR) == 0)
		return (LINAU_TYPE_INTEGRITY_STATUS);
	if (strcmp(type, LINAU_TYPE_INTEGRITY_HASH_STR) == 0)
		return (LINAU_TYPE_INTEGRITY_HASH);
	if (strcmp(type, LINAU_TYPE_INTEGRITY_PCR_STR) == 0)
		return (LINAU_TYPE_INTEGRITY_PCR);
	if (strcmp(type, LINAU_TYPE_INTEGRITY_RULE_STR) == 0)
		return (LINAU_TYPE_INTEGRITY_RULE);
	if (strcmp(type, LINAU_TYPE_AA_STR) == 0)
		return (LINAU_TYPE_AA);
	if (strcmp(type, LINAU_TYPE_APPARMOR_AUDIT_STR) == 0)
		return (LINAU_TYPE_APPARMOR_AUDIT);
	if (strcmp(type, LINAU_TYPE_APPARMOR_ALLOWED_STR) == 0)
		return (LINAU_TYPE_APPARMOR_ALLOWED);
	if (strcmp(type, LINAU_TYPE_APPARMOR_DENIED_STR) == 0)
		return (LINAU_TYPE_APPARMOR_DENIED);
	if (strcmp(type, LINAU_TYPE_APPARMOR_HINT_STR) == 0)
		return (LINAU_TYPE_APPARMOR_HINT);
	if (strcmp(type, LINAU_TYPE_APPARMOR_STATUS_STR) == 0)
		return (LINAU_TYPE_APPARMOR_STATUS);
	if (strcmp(type, LINAU_TYPE_APPARMOR_ERROR_STR) == 0)
		return (LINAU_TYPE_APPARMOR_ERROR);
	if (strcmp(type, LINAU_TYPE_KERNEL_STR) == 0)
		return (LINAU_TYPE_KERNEL);
	if (strcmp(type, LINAU_TYPE_ANOM_LOGIN_FAILURES_STR) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_FAILURES);
	if (strcmp(type, LINAU_TYPE_ANOM_LOGIN_TIME_STR) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_TIME);
	if (strcmp(type, LINAU_TYPE_ANOM_LOGIN_SESSIONS_STR) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_SESSIONS);
	if (strcmp(type, LINAU_TYPE_ANOM_LOGIN_ACCT_STR) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_ACCT);
	if (strcmp(type, LINAU_TYPE_ANOM_LOGIN_LOCATION_STR) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_LOCATION);
	if (strcmp(type, LINAU_TYPE_ANOM_MAX_DAC_STR) == 0)
		return (LINAU_TYPE_ANOM_MAX_DAC);
	if (strcmp(type, LINAU_TYPE_ANOM_MAX_MAC_STR) == 0)
		return (LINAU_TYPE_ANOM_MAX_MAC);
	if (strcmp(type, LINAU_TYPE_ANOM_AMTU_FAIL_STR) == 0)
		return (LINAU_TYPE_ANOM_AMTU_FAIL);
	if (strcmp(type, LINAU_TYPE_ANOM_RBAC_FAIL_STR) == 0)
		return (LINAU_TYPE_ANOM_RBAC_FAIL);
	if (strcmp(type, LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL_STR) == 0)
		return (LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL);
	if (strcmp(type, LINAU_TYPE_ANOM_CRYPTO_FAIL_STR) == 0)
		return (LINAU_TYPE_ANOM_CRYPTO_FAIL);
	if (strcmp(type, LINAU_TYPE_ANOM_ACCESS_FS_STR) == 0)
		return (LINAU_TYPE_ANOM_ACCESS_FS);
	if (strcmp(type, LINAU_TYPE_ANOM_EXEC_STR) == 0)
		return (LINAU_TYPE_ANOM_EXEC);
	if (strcmp(type, LINAU_TYPE_ANOM_MK_EXEC_STR) == 0)
		return (LINAU_TYPE_ANOM_MK_EXEC);
	if (strcmp(type, LINAU_TYPE_ANOM_ADD_ACCT_STR) == 0)
		return (LINAU_TYPE_ANOM_ADD_ACCT);
	if (strcmp(type, LINAU_TYPE_ANOM_DEL_ACCT_STR) == 0)
		return (LINAU_TYPE_ANOM_DEL_ACCT);
	if (strcmp(type, LINAU_TYPE_ANOM_MOD_ACCT_STR) == 0)
		return (LINAU_TYPE_ANOM_MOD_ACCT);
	if (strcmp(type, LINAU_TYPE_ANOM_ROOT_TRANS_STR) == 0)
		return (LINAU_TYPE_ANOM_ROOT_TRANS);
	if (strcmp(type, LINAU_TYPE_RESP_ANOMALY_STR) == 0)
		return (LINAU_TYPE_RESP_ANOMALY);
	if (strcmp(type, LINAU_TYPE_RESP_ALERT_STR) == 0)
		return (LINAU_TYPE_RESP_ALERT);
	if (strcmp(type, LINAU_TYPE_RESP_KILL_PROC_STR) == 0)
		return (LINAU_TYPE_RESP_KILL_PROC);
	if (strcmp(type, LINAU_TYPE_RESP_TERM_ACCESS_STR) == 0)
		return (LINAU_TYPE_RESP_TERM_ACCESS);
	if (strcmp(type, LINAU_TYPE_RESP_ACCT_REMOTE_STR) == 0)
		return (LINAU_TYPE_RESP_ACCT_REMOTE);
	if (strcmp(type, LINAU_TYPE_RESP_ACCT_LOCK_TIMED_STR) == 0)
		return (LINAU_TYPE_RESP_ACCT_LOCK_TIMED);
	if (strcmp(type, LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED_STR) == 0)
		return (LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED);
	if (strcmp(type, LINAU_TYPE_RESP_ACCT_LOCK_STR) == 0)
		return (LINAU_TYPE_RESP_ACCT_LOCK);
	if (strcmp(type, LINAU_TYPE_RESP_TERM_LOCK_STR) == 0)
		return (LINAU_TYPE_RESP_TERM_LOCK);
	if (strcmp(type, LINAU_TYPE_RESP_SEBOOL_STR) == 0)
		return (LINAU_TYPE_RESP_SEBOOL);
	if (strcmp(type, LINAU_TYPE_RESP_EXEC_STR) == 0)
		return (LINAU_TYPE_RESP_EXEC);
	if (strcmp(type, LINAU_TYPE_RESP_SINGLE_STR) == 0)
		return (LINAU_TYPE_RESP_SINGLE);
	if (strcmp(type, LINAU_TYPE_RESP_HALT_STR) == 0)
		return (LINAU_TYPE_RESP_HALT);
	if (strcmp(type, LINAU_TYPE_USER_ROLE_CHANGE_STR) == 0)
		return (LINAU_TYPE_USER_ROLE_CHANGE);
	if (strcmp(type, LINAU_TYPE_ROLE_ASSIGN_STR) == 0)
		return (LINAU_TYPE_ROLE_ASSIGN);
	if (strcmp(type, LINAU_TYPE_ROLE_REMOVE_STR) == 0)
		return (LINAU_TYPE_ROLE_REMOVE);
	if (strcmp(type, LINAU_TYPE_LABEL_OVERRIDE_STR) == 0)
		return (LINAU_TYPE_LABEL_OVERRIDE);
	if (strcmp(type, LINAU_TYPE_LABEL_LEVEL_CHANGE_STR) == 0)
		return (LINAU_TYPE_LABEL_LEVEL_CHANGE);
	if (strcmp(type, LINAU_TYPE_USER_LABELED_EXPORT_STR) == 0)
		return (LINAU_TYPE_USER_LABELED_EXPORT);
	if (strcmp(type, LINAU_TYPE_USER_UNLABELED_EXPORT_STR) == 0)
		return (LINAU_TYPE_USER_UNLABELED_EXPORT);
	if (strcmp(type, LINAU_TYPE_DEV_ALLOC_STR) == 0)
		return (LINAU_TYPE_DEV_ALLOC);
	if (strcmp(type, LINAU_TYPE_DEV_DEALLOC_STR) == 0)
		return (LINAU_TYPE_DEV_DEALLOC);
	if (strcmp(type, LINAU_TYPE_FS_RELABEL_STR) == 0)
		return (LINAU_TYPE_FS_RELABEL);
	if (strcmp(type, LINAU_TYPE_USER_MAC_POLICY_LOAD_STR) == 0)
		return (LINAU_TYPE_USER_MAC_POLICY_LOAD);
	if (strcmp(type, LINAU_TYPE_ROLE_MODIFY_STR) == 0)
		return (LINAU_TYPE_ROLE_MODIFY);
	if (strcmp(type, LINAU_TYPE_USER_MAC_CONFIG_CHANGE_STR) == 0)
		return (LINAU_TYPE_USER_MAC_CONFIG_CHANGE);
	if (strcmp(type, LINAU_TYPE_CRYPTO_TEST_USER_STR) == 0)
		return (LINAU_TYPE_CRYPTO_TEST_USER);
	if (strcmp(type, LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER_STR) == 0)
		return (LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER);
	if (strcmp(type, LINAU_TYPE_CRYPTO_LOGIN_STR) == 0)
		return (LINAU_TYPE_CRYPTO_LOGIN);
	if (strcmp(type, LINAU_TYPE_CRYPTO_LOGOUT_STR) == 0)
		return (LINAU_TYPE_CRYPTO_LOGOUT);
	if (strcmp(type, LINAU_TYPE_CRYPTO_KEY_USER_STR) == 0)
		return (LINAU_TYPE_CRYPTO_KEY_USER);
	if (strcmp(type, LINAU_TYPE_CRYPTO_FAILURE_USER_STR) == 0)
		return (LINAU_TYPE_CRYPTO_FAILURE_USER);
	if (strcmp(type, LINAU_TYPE_CRYPTO_REPLAY_USER_STR) == 0)
		return (LINAU_TYPE_CRYPTO_REPLAY_USER);
	if (strcmp(type, LINAU_TYPE_CRYPTO_SESSION_STR) == 0)
		return (LINAU_TYPE_CRYPTO_SESSION);
	if (strcmp(type, LINAU_TYPE_CRYPTO_IKE_SA_STR) == 0)
		return (LINAU_TYPE_CRYPTO_IKE_SA);
	if (strcmp(type, LINAU_TYPE_CRYPTO_IPSEC_SA_STR) == 0)
		return (LINAU_TYPE_CRYPTO_IPSEC_SA);
	if (strcmp(type, LINAU_TYPE_VIRT_CONTROL_STR) == 0)
		return (LINAU_TYPE_VIRT_CONTROL);
	if (strcmp(type, LINAU_TYPE_VIRT_RESOURCE_STR) == 0)
		return (LINAU_TYPE_VIRT_RESOURCE);
	if (strcmp(type, LINAU_TYPE_VIRT_MACHINE_ID_STR) == 0)
		return (LINAU_TYPE_VIRT_MACHINE_ID);

	pjdlog_debug(3, "End %s", __func__);

	return (LINAU_TYPE_UNDEFINED);
}
