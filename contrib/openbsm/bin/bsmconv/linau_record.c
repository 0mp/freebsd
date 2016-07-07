#include <sys/types.h>
#include <sys/sbuf.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bsm/libbsm.h>

#include "linau.h"
#include "linau_impl.h"
#include "pjdlog.h"


#define	BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE	16
#define	BSMCONV_LINAU_RECORD_UINT_BUFFER_SIZE	32

#define	LINAU_TYPE_GET_STR			"GET"
#define	LINAU_TYPE_SET_STR			"SET" /* Beging of a deprecated types section. */
#define	LINAU_TYPE_LIST_STR			"LIST"
#define	LINAU_TYPE_ADD_STR			"ADD"
#define	LINAU_TYPE_DEL_STR			"DEL" /* End of a deprecated types section. */
#define	LINAU_TYPE_USER_STR			"USER"
#define	AUDILINAU_TYPE_SIGNAL_INFO_STR	"SIGNAL_INFO"
#define	LINAU_TYPE_ADD_RULE_STR			"ADD_RULE" /* Beging of a deprecated types section. */
#define	LINAU_TYPE_DEL_RULE_STR			"DEL_RULE"
#define	LINAU_TYPE_LIST_RULES_STR		"LIST_RULES"
#define	LINAU_TYPE_TRIM_STR			"TRIM"
#define	LINAU_TYPE_MAKE_EQUIV_STR		"MAKE_EQUIV"
#define	LINAU_TYPE_TTY_GET_STR			"TTY_GET"
#define	LINAU_TYPE_TTY_SET_STR			"TTY_SET"
#define	LINAU_TYPE_SET_FEATURE_STR		"SET_FEATURE"
#define	LINAU_TYPE_GET_FEATURE_STR		"GET_FEATURE" /* End of a deprecated types section. */
#define	AUDILINAU_TYPE_USER_ACCT_STR		"USER_ACCT"
#define	AUDILINAU_TYPE_CRED_ACQ_STR		"CRED_ACQ"
#define	AUDILINAU_TYPE_USER_START_STR		"USER_START"
#define	AUDILINAU_TYPE_USER_AVC_STR		"USER_AVC"
#define	AUDILINAU_TYPE_USER_ERR_STR		"USER_ERR"
#define	AUDILINAU_TYPE_USYS_CONFIG_STR		"USYS_CONFIG"
#define	LINAU_TYPE_USER_LOGIN_STR		"USER_LOGIN"
#define	LINAU_TYPE_USER_LOGOUT_STR		"USER_LOGOUT"
#define	LINAU_TYPE_ADD_USER_STR			"ADD_USER"
#define	LINAU_TYPE_DEL_USER_STR			"DEL_USER"
#define	LINAU_TYPE_ADD_GROUP_STR			"ADD_GROUP"
#define	LINAU_TYPE_DEL_GROUP_STR			"DEL_GROUP"
#define	LINAU_TYPE_DAC_CHECK_STR			"DAC_CHECK"
#define	LINAU_TYPE_CHGRP_ID_STR			"CHGRP_ID"
#define	LINAU_TYPE_TEST_STR			"TEST"
#define	LINAU_TYPE_TRUSTED_APP_STR		"TRUSTED_APP"
#define	LINAU_TYPE_USER_SELINUX_ERR_STR		"USER_SELINUX_ERR"
#define	LINAU_TYPE_USER_CMD_STR			"USER_CMD"
#define	LINAU_TYPE_USER_TTY_STR			"USER_TTY"
#define	LINAU_TYPE_CHUSER_ID_STR			"CHUSER_ID"
#define	LINAU_TYPE_GRP_AUTH_STR			"GRP_AUTH"
#define	LINAU_TYPE_MAC_CHECK_STR			"MAC_CHECK"
#define	LINAU_TYPE_ACCT_LOCK_STR			"ACCT_LOCK"
#define	LINAU_TYPE_ACCT_UNLOCK_STR		"ACCT_UNLOCK"
#define	LINAU_TYPE_SYSTEM_BOOT_STR		"SYSTEM_BOOT"
#define	LINAU_TYPE_SYSTEM_SHUTDOWN_STR		"SYSTEM_SHUTDOWN"
#define	LINAU_TYPE_SYSTEM_RUNLEVEL_STR		"SYSTEM_RUNLEVEL"
#define	LINAU_TYPE_SERVICE_START_STR		"SERVICE_START"
#define	LINAU_TYPE_SERVICE_STOP_STR		"SERVICE_STOP"
#define	LINAU_TYPE_GRP_MGMT_STR			"GRP_MGMT"
#define	LINAU_TYPE_GRP_CHAUTHTOK_STR		"GRP_CHAUTHTOK"
#define	LINAU_TYPE_DAEMON_START_STR		"DAEMON_START"
#define	LINAU_TYPE_DAEMON_END_STR		"DAEMON_END"
#define	LINAU_TYPE_DAEMON_ABORT_STR		"DAEMON_ABORT"
#define	LINAU_TYPE_DAEMON_CONFIG_STR		"DAEMON_CONFIG"
#define	LINAU_TYPE_DAEMON_RECONFIG_STR		"DAEMON_RECONFIG" /* Deprecated. */
#define	LINAU_TYPE_DAEMON_ROTATE_STR		"DAEMON_ROTATE"
#define	LINAU_TYPE_DAEMON_RESUME_STR		"DAEMON_RESUME"
#define	LINAU_TYPE_DAEMON_ACCEPT_STR		"DAEMON_ACCEPT"
#define	LINAU_TYPE_DAEMON_CLOSE_STR		"DAEMON_CLOSE"
#define	LINAU_TYPE_DAEMON_ERR_STR		"DAEMON_ERR"
#define	LINAU_TYPE_SYSCALL_STR			"SYSCALL"
#define	LINAU_TYPE_FS_WATCH_STR			"FS_WATCH" /* Deprecated. */
#define	LINAU_TYPE_PATH_STR			"PATH"
#define	LINAU_TYPE_IPC_STR			"IPC"
#define	LINAU_TYPE_SOCKETCALL_STR		"SOCKETCALL"
#define	LINAU_TYPE_CONFIG_CHANGE_STR		"CONFIG_CHANGE"
#define	LINAU_TYPE_SOCKADDR_STR			"SOCKADDR"
#define	LINAU_TYPE_CWD_STR			"CWD"
#define	LINAU_TYPE_FS_INODE_STR			"FS_INODE" /* Deprecated. */
#define	LINAU_TYPE_EXECVE_STR			"EXECVE"
#define	LINAU_TYPE_IPC_SET_PERM_STR		"IPC_SET_PERM"
#define	LINAU_TYPE_MQ_OPEN_STR			"MQ_OPEN"
#define	LINAU_TYPE_MQ_SENDRECV_STR		"MQ_SENDRECV"
#define	LINAU_TYPE_MQ_NOTIFY_STR			"MQ_NOTIFY"
#define	LINAU_TYPE_MQ_GETSETATTR_STR		"MQ_GETSETATTR"
#define	LINAU_TYPE_KERNEL_OTHER_STR		"KERNEL_OTHER"
#define	LINAU_TYPE_FD_PAIR_STR			"FD_PAIR"
#define	LINAU_TYPE_OBJ_PID_STR			"OBJ_PID"
#define	LINAU_TYPE_TTY_STR			"TTY"
#define	LINAU_TYPE_EOE_STR			"EOE"
#define	LINAU_TYPE_BPRM_FCAPS_STR		"BPRM_FCAPS"
#define	LINAU_TYPE_CAPSET_STR			"CAPSET"
#define	LINAU_TYPE_MMAP_STR			"MMAP"
#define	LINAU_TYPE_NETFILTER_PKT_STR		"NETFILTER_PKT"
#define	LINAU_TYPE_NETFILTER_CFG_STR		"NETFILTER_CFG"
#define	LINAU_TYPE_SECCOMP_STR			"SECCOMP"
#define	LINAU_TYPE_PROCTITLE_STR			"PROCTITLE"
#define	LINAU_TYPE_FEATURE_CHANGE_STR		"FEATURE_CHANGE"
#define	LINAU_TYPE_AVC_STR			"AVC"
#define	LINAU_TYPE_SELINUX_ERR_STR		"SELINUX_ERR"
#define	LINAU_TYPE_AVC_PATH_STR			"AVC_PATH"
#define	LINAU_TYPE_MAC_POLICY_LOAD_STR		"MAC_POLICY_LOAD"
#define	LINAU_TYPE_MAC_STATUS_STR		"MAC_STATUS"
#define	LINAU_TYPE_MAC_CONFIG_CHANGE_STR		"MAC_CONFIG_CHANGE"
#define	LINAU_TYPE_MAC_UNLBL_ALLOW_STR		"MAC_UNLBL_ALLOW"
#define	LINAU_TYPE_MAC_CIPSOV4_ADD_STR		"MAC_CIPSOV4_ADD"
#define	LINAU_TYPE_MAC_CIPSOV4_DEL_STR		"MAC_CIPSOV4_DEL"
#define	LINAU_TYPE_MAC_MAP_ADD_STR		"MAC_MAP_ADD"
#define	LINAU_TYPE_MAC_MAP_DEL_STR		"MAC_MAP_DEL"
#define	LINAU_TYPE_MAC_IPSEC_ADDSA_STR		"MAC_IPSEC_ADDSA"
#define	LINAU_TYPE_MAC_IPSEC_DELSA_STR		"MAC_IPSEC_DELSA"
#define	LINAU_TYPE_MAC_IPSEC_ADDSPD_STR		"MAC_IPSEC_ADDSPD"
#define	LINAU_TYPE_MAC_IPSEC_DELSPD_STR		"MAC_IPSEC_DELSPD"
#define	LINAU_TYPE_MAC_IPSEC_EVENT_STR		"MAC_IPSEC_EVENT"
#define	LINAU_TYPE_MAC_UNLBL_STCADD_STR		"MAC_UNLBL_STCADD"
#define	LINAU_TYPE_MAC_UNLBL_STCDEL_STR		"MAC_UNLBL_STCDEL"
#define	LINAU_TYPE_ANOM_PROMISCUOUS_STR		"ANOM_PROMISCUOUS"
#define	LINAU_TYPE_ANOM_ABEND_STR		"ANOM_ABEND"
#define	LINAU_TYPE_ANOM_LINK_STR			"ANOM_LINK"
#define	LINAU_TYPE_INTEGRITY_DATA_STR		"INTEGRITY_DATA"
#define	LINAU_TYPE_INTEGRITY_STATUS_STR		"INTEGRITY_STATUS"
#define	LINAU_TYPE_INTEGRITY_HASH_STR		"INTEGRITY_HASH"
#define	LINAU_TYPE_INTEGRITY_PCR_STR		"INTEGRITY_PCR"
#define	LINAU_TYPE_INTEGRITY_RULE_STR		"INTEGRITY_RULE"

//#ifdef WITH_APPARMOR /* XXX What is this? */
#define	LINAU_TYPE_AA_STR			"APPARMOR"
#define	LINAU_TYPE_APPARMOR_AUDIT_STR		"APPARMOR_AUDIT"
#define	LINAU_TYPE_APPARMOR_ALLOWED_STR		"APPARMOR_ALLOWED"
#define	LINAU_TYPE_APPARMOR_DENIED_STR		"APPARMOR_DENIED"
#define	LINAU_TYPE_APPARMOR_HINT_STR		"APPARMOR_HINT"
#define	LINAU_TYPE_APPARMOR_STATUS_STR		"APPARMOR_STATUS"
#define	LINAU_TYPE_APPARMOR_ERROR_STR		"APPARMOR_ERROR"
//#endif /* End of XXX What is this? */

#define	LINAU_TYPE_KERNEL_STR			"KERNEL"
#define	LINAU_TYPE_ANOM_LOGIN_FAILURES_STR	"ANOM_LOGIN_FAILURES"
#define	LINAU_TYPE_ANOM_LOGIN_TIME_STR		"ANOM_LOGIN_TIME"
#define	LINAU_TYPE_ANOM_LOGIN_SESSIONS_STR	"ANOM_LOGIN_SESSIONS"
#define	LINAU_TYPE_ANOM_LOGIN_ACCT_STR		"ANOM_LOGIN_ACCT"
#define	LINAU_TYPE_ANOM_LOGIN_LOCATION_STR	"ANOM_LOGIN_LOCATION"
#define	LINAU_TYPE_ANOM_MAX_DAC_STR		"ANOM_MAX_DAC"
#define	LINAU_TYPE_ANOM_MAX_MAC_STR		"ANOM_MAX_MAC"
#define	LINAU_TYPE_ANOM_AMTU_FAIL_STR		"ANOM_AMTU_FAIL"
#define	LINAU_TYPE_ANOM_RBAC_FAIL_STR		"ANOM_RBAC_FAIL"
#define	LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL_STR	"ANOM_RBAC_INTEGRITY_FAIL"
#define	LINAU_TYPE_ANOM_CRYPTO_FAIL_STR		"ANOM_CRYPTO_FAIL"
#define	LINAU_TYPE_ANOM_ACCESS_FS_STR		"ANOM_ACCESS_FS"
#define	LINAU_TYPE_ANOM_EXEC_STR			"ANOM_EXEC"
#define	LINAU_TYPE_ANOM_MK_EXEC_STR		"ANOM_MK_EXEC"
#define	LINAU_TYPE_ANOM_ADD_ACCT_STR		"ANOM_ADD_ACCT"
#define	LINAU_TYPE_ANOM_DEL_ACCT_STR		"ANOM_DEL_ACCT"
#define	LINAU_TYPE_ANOM_MOD_ACCT_STR		"ANOM_MOD_ACCT"
#define	LINAU_TYPE_ANOM_ROOT_TRANS_STR		"ANOM_ROOT_TRANS"
#define	LINAU_TYPE_RESP_ANOMALY_STR		"RESP_ANOMALY"
#define	LINAU_TYPE_RESP_ALERT_STR		"RESP_ALERT"
#define	LINAU_TYPE_RESP_KILL_PROC_STR		"RESP_KILL_PROC"
#define	LINAU_TYPE_RESP_TERM_ACCESS_STR		"RESP_TERM_ACCESS"
#define	LINAU_TYPE_RESP_ACCT_REMOTE_STR		"RESP_ACCT_REMOTE"
#define	LINAU_TYPE_RESP_ACCT_LOCK_TIMED_STR	"RESP_ACCT_LOCK_TIMED"
#define	LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED_STR	"RESP_ACCT_UNLOCK_TIMED"
#define	LINAU_TYPE_RESP_ACCT_LOCK_STR		"RESP_ACCT_LOCK"
#define	LINAU_TYPE_RESP_TERM_LOCK_STR		"RESP_TERM_LOCK"
#define	LINAU_TYPE_RESP_SEBOOL_STR		"RESP_SEBOOL"
#define	LINAU_TYPE_RESP_EXEC_STR			"RESP_EXEC"
#define	LINAU_TYPE_RESP_SINGLE_STR		"RESP_SINGLE"
#define	LINAU_TYPE_RESP_HALT_STR			"RESP_HALT"
#define	LINAU_TYPE_USER_ROLE_CHANGE_STR		"USER_ROLE_CHANGE"
#define	LINAU_TYPE_ROLE_ASSIGN_STR		"ROLE_ASSIGN"
#define	LINAU_TYPE_ROLE_REMOVE_STR		"ROLE_REMOVE"
#define	LINAU_TYPE_LABEL_OVERRIDE_STR		"LABEL_OVERRIDE"
#define	LINAU_TYPE_LABEL_LEVEL_CHANGE_STR	"LABEL_LEVEL_CHANGE"
#define	LINAU_TYPE_USER_LABELED_EXPORT_STR	"USER_LABELED_EXPORT"
#define	LINAU_TYPE_USER_UNLABELED_EXPORT_STR	"USER_UNLABELED_EXPORT"
#define	LINAU_TYPE_DEV_ALLOC_STR			"DEV_ALLOC"
#define	LINAU_TYPE_DEV_DEALLOC_STR		"DEV_DEALLOC"
#define	LINAU_TYPE_FS_RELABEL_STR		"FS_RELABEL"
#define	LINAU_TYPE_USER_MAC_POLICY_LOAD_STR	"USER_MAC_POLICY_LOAD"
#define	LINAU_TYPE_ROLE_MODIFY_STR		"ROLE_MODIFY"
#define	LINAU_TYPE_USER_MAC_CONFIG_CHANGE_STR	"USER_MAC_CONFIG_CHANGE"
#define	LINAU_TYPE_CRYPTO_TEST_USER_STR		"CRYPTO_TEST_USER"
#define	LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER_STR	"CRYPTO_PARAM_CHANGE_USER"
#define	LINAU_TYPE_CRYPTO_LOGIN_STR		"CRYPTO_LOGIN"
#define	LINAU_TYPE_CRYPTO_LOGOUT_STR		"CRYPTO_LOGOUT"
#define	LINAU_TYPE_CRYPTO_KEY_USER_STR		"CRYPTO_KEY_USER"
#define	LINAU_TYPE_CRYPTO_FAILURE_USER_STR	"CRYPTO_FAILURE_USER"
#define	LINAU_TYPE_CRYPTO_REPLAY_USER_STR	"CRYPTO_REPLAY_USER"
#define	LINAU_TYPE_CRYPTO_SESSION_STR		"CRYPTO_SESSION"
#define	LINAU_TYPE_CRYPTO_IKE_SA_STR		"CRYPTO_IKE_SA"
#define	LINAU_TYPE_CRYPTO_IPSEC_SA_STR		"CRYPTO_IPSEC_SA"
#define	LINAU_TYPE_VIRT_CONTROL_STR		"VIRT_CONTROL"
#define	LINAU_TYPE_VIRT_RESOURCE_STR		"VIRT_RESOURCE"
#define	LINAU_TYPE_VIRT_MACHINE_ID_STR		"VIRT_MACHINE_ID"


#define LINAU_TYPE_UNDEFINED			-1
#define	LINAU_TYPE_GET		1
#define	LINAU_TYPE_SET		2
#define	LINAU_TYPE_LIST		3
#define	LINAU_TYPE_ADD		4
#define	LINAU_TYPE_DEL		5
#define	LINAU_TYPE_USER		6
#define	AUDILINAU_TYPE_SIGNAL_INFO	7
#define	LINAU_TYPE_ADD_RULE		8
#define	LINAU_TYPE_DEL_RULE		9
#define	LINAU_TYPE_LIST_RULES		10
#define	LINAU_TYPE_TRIM		11
#define	LINAU_TYPE_MAKE_EQUIV		12
#define	LINAU_TYPE_TTY_GET		13
#define	LINAU_TYPE_TTY_SET		14
#define	LINAU_TYPE_SET_FEATURE		15
#define	LINAU_TYPE_GET_FEATURE		16
#define	AUDILINAU_TYPE_USER_ACCT		17
#define	AUDILINAU_TYPE_CRED_ACQ		18
#define	AUDILINAU_TYPE_USER_START		19
#define	AUDILINAU_TYPE_USER_AVC		20
#define	AUDILINAU_TYPE_USER_ERR		21
#define	AUDILINAU_TYPE_USYS_CONFIG		22
#define	LINAU_TYPE_USER_LOGIN		23
#define	LINAU_TYPE_USER_LOGOUT		24
#define	LINAU_TYPE_ADD_USER		25
#define	LINAU_TYPE_DEL_USER		26
#define	LINAU_TYPE_ADD_GROUP		27
#define	LINAU_TYPE_DEL_GROUP		28
#define	LINAU_TYPE_DAC_CHECK		29
#define	LINAU_TYPE_CHGRP_ID		30
#define	LINAU_TYPE_TEST		31
#define	LINAU_TYPE_TRUSTED_APP		32
#define	LINAU_TYPE_USER_SELINUX_ERR		33
#define	LINAU_TYPE_USER_CMD		34
#define	LINAU_TYPE_USER_TTY		35
#define	LINAU_TYPE_CHUSER_ID		36
#define	LINAU_TYPE_GRP_AUTH		37
#define	LINAU_TYPE_MAC_CHECK		38
#define	LINAU_TYPE_ACCT_LOCK		39
#define	LINAU_TYPE_ACCT_UNLOCK		40
#define	LINAU_TYPE_SYSTEM_BOOT		41
#define	LINAU_TYPE_SYSTEM_SHUTDOWN		42
#define	LINAU_TYPE_SYSTEM_RUNLEVEL		43
#define	LINAU_TYPE_SERVICE_START		44
#define	LINAU_TYPE_SERVICE_STOP		45
#define	LINAU_TYPE_GRP_MGMT		46
#define	LINAU_TYPE_GRP_CHAUTHTOK		47
#define	LINAU_TYPE_DAEMON_START		48
#define	LINAU_TYPE_DAEMON_END		49
#define	LINAU_TYPE_DAEMON_ABORT		50
#define	LINAU_TYPE_DAEMON_CONFIG		51
#define	LINAU_TYPE_DAEMON_RECONFIG		52
#define	LINAU_TYPE_DAEMON_ROTATE		53
#define	LINAU_TYPE_DAEMON_RESUME		54
#define	LINAU_TYPE_DAEMON_ACCEPT		55
#define	LINAU_TYPE_DAEMON_CLOSE		56
#define	LINAU_TYPE_DAEMON_ERR		57
#define	LINAU_TYPE_SYSCALL		58
#define	LINAU_TYPE_FS_WATCH		59
#define	LINAU_TYPE_PATH		60
#define	LINAU_TYPE_IPC		61
#define	LINAU_TYPE_SOCKETCALL		62
#define	LINAU_TYPE_CONFIG_CHANGE		63
#define	LINAU_TYPE_SOCKADDR		64
#define	LINAU_TYPE_CWD		65
#define	LINAU_TYPE_FS_INODE		66
#define	LINAU_TYPE_EXECVE		67
#define	LINAU_TYPE_IPC_SET_PERM		68
#define	LINAU_TYPE_MQ_OPEN		69
#define	LINAU_TYPE_MQ_SENDRECV		70
#define	LINAU_TYPE_MQ_NOTIFY		71
#define	LINAU_TYPE_MQ_GETSETATTR		72
#define	LINAU_TYPE_KERNEL_OTHER		73
#define	LINAU_TYPE_FD_PAIR		74
#define	LINAU_TYPE_OBJ_PID		75
#define	LINAU_TYPE_TTY		76
#define	LINAU_TYPE_EOE		77
#define	LINAU_TYPE_BPRM_FCAPS		78
#define	LINAU_TYPE_CAPSET		79
#define	LINAU_TYPE_MMAP		80
#define	LINAU_TYPE_NETFILTER_PKT		81
#define	LINAU_TYPE_NETFILTER_CFG		82
#define	LINAU_TYPE_SECCOMP		83
#define	LINAU_TYPE_PROCTITLE		84
#define	LINAU_TYPE_FEATURE_CHANGE		85
#define	LINAU_TYPE_AVC		86
#define	LINAU_TYPE_SELINUX_ERR		87
#define	LINAU_TYPE_AVC_PATH		88
#define	LINAU_TYPE_MAC_POLICY_LOAD		89
#define	LINAU_TYPE_MAC_STATUS		90
#define	LINAU_TYPE_MAC_CONFIG_CHANGE		91
#define	LINAU_TYPE_MAC_UNLBL_ALLOW		92
#define	LINAU_TYPE_MAC_CIPSOV4_ADD		93
#define	LINAU_TYPE_MAC_CIPSOV4_DEL		94
#define	LINAU_TYPE_MAC_MAP_ADD		95
#define	LINAU_TYPE_MAC_MAP_DEL		96
#define	LINAU_TYPE_MAC_IPSEC_ADDSA		97
#define	LINAU_TYPE_MAC_IPSEC_DELSA		98
#define	LINAU_TYPE_MAC_IPSEC_ADDSPD		99
#define	LINAU_TYPE_MAC_IPSEC_DELSPD		100
#define	LINAU_TYPE_MAC_IPSEC_EVENT		101
#define	LINAU_TYPE_MAC_UNLBL_STCADD		102
#define	LINAU_TYPE_MAC_UNLBL_STCDEL		103
#define	LINAU_TYPE_ANOM_PROMISCUOUS		104
#define	LINAU_TYPE_ANOM_ABEND		105
#define	LINAU_TYPE_ANOM_LINK		106
#define	LINAU_TYPE_INTEGRITY_DATA		107
#define	LINAU_TYPE_INTEGRITY_STATUS		108
#define	LINAU_TYPE_INTEGRITY_HASH		109
#define	LINAU_TYPE_INTEGRITY_PCR		110
#define	LINAU_TYPE_INTEGRITY_RULE		111
#define	LINAU_TYPE_AA		112
#define	LINAU_TYPE_APPARMOR_AUDIT		113
#define	LINAU_TYPE_APPARMOR_ALLOWED		114
#define	LINAU_TYPE_APPARMOR_DENIED		115
#define	LINAU_TYPE_APPARMOR_HINT		116
#define	LINAU_TYPE_APPARMOR_STATUS		117
#define	LINAU_TYPE_APPARMOR_ERROR		118
#define	LINAU_TYPE_KERNEL		119
#define	LINAU_TYPE_ANOM_LOGIN_FAILURES		120
#define	LINAU_TYPE_ANOM_LOGIN_TIME		121
#define	LINAU_TYPE_ANOM_LOGIN_SESSIONS		122
#define	LINAU_TYPE_ANOM_LOGIN_ACCT		123
#define	LINAU_TYPE_ANOM_LOGIN_LOCATION		124
#define	LINAU_TYPE_ANOM_MAX_DAC		125
#define	LINAU_TYPE_ANOM_MAX_MAC		126
#define	LINAU_TYPE_ANOM_AMTU_FAIL		127
#define	LINAU_TYPE_ANOM_RBAC_FAIL		128
#define	LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL		129
#define	LINAU_TYPE_ANOM_CRYPTO_FAIL		130
#define	LINAU_TYPE_ANOM_ACCESS_FS		131
#define	LINAU_TYPE_ANOM_EXEC		132
#define	LINAU_TYPE_ANOM_MK_EXEC		133
#define	LINAU_TYPE_ANOM_ADD_ACCT		134
#define	LINAU_TYPE_ANOM_DEL_ACCT		135
#define	LINAU_TYPE_ANOM_MOD_ACCT		136
#define	LINAU_TYPE_ANOM_ROOT_TRANS		137
#define	LINAU_TYPE_RESP_ANOMALY		138
#define	LINAU_TYPE_RESP_ALERT		139
#define	LINAU_TYPE_RESP_KILL_PROC		140
#define	LINAU_TYPE_RESP_TERM_ACCESS		141
#define	LINAU_TYPE_RESP_ACCT_REMOTE		142
#define	LINAU_TYPE_RESP_ACCT_LOCK_TIMED		143
#define	LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED		144
#define	LINAU_TYPE_RESP_ACCT_LOCK		145
#define	LINAU_TYPE_RESP_TERM_LOCK		146
#define	LINAU_TYPE_RESP_SEBOOL		147
#define	LINAU_TYPE_RESP_EXEC		148
#define	LINAU_TYPE_RESP_SINGLE		149
#define	LINAU_TYPE_RESP_HALT		150
#define	LINAU_TYPE_USER_ROLE_CHANGE		151
#define	LINAU_TYPE_ROLE_ASSIGN		152
#define	LINAU_TYPE_ROLE_REMOVE		153
#define	LINAU_TYPE_LABEL_OVERRIDE		154
#define	LINAU_TYPE_LABEL_LEVEL_CHANGE		155
#define	LINAU_TYPE_USER_LABELED_EXPORT		156
#define	LINAU_TYPE_USER_UNLABELED_EXPORT		157
#define	LINAU_TYPE_DEV_ALLOC		158
#define	LINAU_TYPE_DEV_DEALLOC		159
#define	LINAU_TYPE_FS_RELABEL		160
#define	LINAU_TYPE_USER_MAC_POLICY_LOAD		161
#define	LINAU_TYPE_ROLE_MODIFY		162
#define	LINAU_TYPE_USER_MAC_CONFIG_CHANGE		163
#define	LINAU_TYPE_CRYPTO_TEST_USER		164
#define	LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER		165
#define	LINAU_TYPE_CRYPTO_LOGIN		166
#define	LINAU_TYPE_CRYPTO_LOGOUT		167
#define	LINAU_TYPE_CRYPTO_KEY_USER		168
#define	LINAU_TYPE_CRYPTO_FAILURE_USER		169
#define	LINAU_TYPE_CRYPTO_REPLAY_USER		170
#define	LINAU_TYPE_CRYPTO_SESSION		171
#define	LINAU_TYPE_CRYPTO_IKE_SA		172
#define	LINAU_TYPE_CRYPTO_IPSEC_SA		173
#define	LINAU_TYPE_VIRT_CONTROL		174
#define	LINAU_TYPE_VIRT_RESOURCE		175
#define	LINAU_TYPE_VIRT_MACHINE_ID		176


static int	 get_linau_type_num(const char *type);
static void	 convert_to_au(int aurecordd,
		    const struct linau_record *record, int typenum);

static uint32_t	 extract_uint32(const char *buf, size_t start, size_t end);
static uint32_t	 string_to_uint32(const char *str);


static uint32_t
extract_uint32(const char *buf, size_t start, size_t end)
{
	size_t len;
	char *numstr;
	uint32_t num;

	PJDLOG_ASSERT(isdigit(buf[start]) != 0);
	PJDLOG_ASSERT(isdigit(buf[end]) != 0);

	len = end - start + 1;
	numstr = extract_substring(buf, start, len);
	num = string_to_uint32(numstr);

	return (num);
}

static uint32_t
string_to_uint32(const char *str)
{
	char *endp;
	uint32_t num;

	pjdlog_debug(6, " . . >> string_to_uint32");

	errno = 0;
	num = (uint32_t)strtoul(str, &endp, 10);

	PJDLOG_VERIFY(str != endp);
	PJDLOG_VERIFY(*endp == '\0');
	PJDLOG_VERIFY(num != 0 || errno == 0);

	return (num);
}


struct linau_record *
linau_record_create(void)
{
	struct linau_record *record;

	record = calloc(1, sizeof(*record));
	PJDLOG_VERIFY(record != NULL);

	return (record);
}

void
linau_record_destroy(struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	free(record->lr_type);

	free(record->lr_text);

	nvlist_destroy(record->lr_fields);

	free(record);
}

bool
linau_record_exists_field(const struct linau_record *record, const char *name)
{
	nvlist_t *fields;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(record->lr_fields != NULL);
	PJDLOG_ASSERT(name != NULL);

	fields = linau_record_get_fields(record);

	return (nvlist_exists_string(fields, name));
}

const char *
linau_record_get_field(const struct linau_record *record, const char *name)
{
	nvlist_t *fields;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(name != NULL);
	PJDLOG_ASSERT(record->lr_fields != NULL);

	/* XXX Return NULL or exit? */
	/* if (!linau_record_exists_field(record, name)) */
	/*         return (NULL); */
	PJDLOG_VERIFY(linau_record_exists_field(record, name));


	fields = linau_record_get_fields(record);

	return (nvlist_get_string(fields, name));
}

nvlist_t *
linau_record_get_fields(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_fields);
}

uint32_t
linau_record_get_id(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_id);
}

const char *
linau_record_get_text(const struct linau_record *record)
{
	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(record->lr_text != NULL);

	return (record->lr_text);
}

uint64_t
linau_record_get_time(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_time);
}

const char *
linau_record_get_type(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_type);
}

void
linau_record_move_fields(struct linau_record *record, nvlist_t *fields)
{

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(fields != NULL);

	record->lr_fields = fields;
}

void
linau_record_set_id(struct linau_record *record, uint32_t id)
{

	PJDLOG_ASSERT(record != NULL);

	record->lr_id = id;
}

void
linau_record_set_text(struct linau_record *record, const char *text)
{
	size_t len;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(text != NULL);
	PJDLOG_ASSERT(strchr(text, '\0') != NULL);

	len = strlen(text);

	record->lr_text = malloc(sizeof(*record->lr_text) * (len + 1));
	PJDLOG_VERIFY(record->lr_text != NULL);

	PJDLOG_VERIFY(strlcpy(record->lr_text, text, len + 1) == len);
}

void
linau_record_set_time(struct linau_record *record, uint64_t time)
{

	PJDLOG_ASSERT(record != NULL);

	record->lr_time = time;
}

void
linau_record_move_type(struct linau_record *record, char *type)
{

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(type != NULL);

	record->lr_type = type;
}

/*
 * data must be a null-terminated string.
 * The function doesn't require data to have/not have a trailing newline.
 */
struct linau_record *
linau_record_parse(const char *buf)
{
	struct linau_record *record;

	pjdlog_debug(3, " . . + linau_record_parse");

	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);

	record = linau_record_create();

	linau_record_move_type(record, linau_record_parse_type(buf));
	linau_record_set_id(record, linau_record_parse_id(buf));
	linau_record_set_time(record, linau_record_parse_time(buf));
	linau_record_move_fields(record, linau_record_parse_fields(buf));
	linau_record_set_text(record, buf);

	pjdlog_debug(3, " . . . > id (%u), time (%ju)",
	    linau_record_get_id(record), linau_record_get_time(record));

	pjdlog_debug(3, " . . -");

	return (record);
}

uint32_t
linau_record_parse_id(const char *buf)
{
	size_t idpos;
	size_t msgend;
	size_t msgstart;
	size_t nsecspos;
	size_t secspos;
	uint32_t id;

	pjdlog_debug(5, " . . . . + linau_record_parse_id");

	locate_msg(buf, &msgstart, &secspos, &nsecspos, &idpos, &msgend);

	id = extract_uint32(buf, idpos, msgend - 1);

	pjdlog_debug(5, " . . . . . id (%zu)", id);

	pjdlog_debug(5, " . . . . -");

	return (id);
}

nvlist_t *
linau_record_parse_fields(const char *buf)
{
	size_t buflen;
	size_t lastpos;
	size_t msgend;
	struct linau_field *field;
	nvlist_t *fields;

	pjdlog_debug(5, " . . . . + linau_record_parse_fields");

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	buflen = strlen(buf);

	/*
	 * XXX NV_FLAG_NO_UNIQUE is currently not supported because I cannot
	 * link the new library.
	 */
	/* fields = nvlist_create(NV_FLAG_NO_UNIQUE); */
	fields = nvlist_create(0);
	/* XXX Do we need this VERIFY? */
	PJDLOG_VERIFY(fields != NULL);

	/* Find the beginning of the field section. */
	PJDLOG_VERIFY(find_position(&msgend, buf, 0, ')'));
	PJDLOG_ASSERT(buf[msgend] == ')');
	PJDLOG_ASSERT(buf[msgend + 1] == ':');
	PJDLOG_ASSERT(buf[msgend + 2] == ' ');

	lastpos = msgend + 2;
	pjdlog_debug(5, " . . . . . lastpos (%zu)", lastpos);

	/* While not all bytes of the buf are processed. */
	while (lastpos < buflen) {
		field = NULL;

		field = linau_field_parse(buf, &lastpos);
		PJDLOG_ASSERT(field != NULL);

		/* Append the field to the fields list. */
		nvlist_move_string(fields, field->lf_name, field->lf_value);

		linau_field_shallow_destroy(field);
	}

	pjdlog_debug(5, " . . . . -");

	return (fields);
}

uint64_t
linau_record_parse_time(const char *buf)
{
	uint64_t time;
	size_t buflen;
	size_t idpos;
	size_t msgend;
	size_t msgstart;
	size_t nsecspos;
	size_t secspos;
	uint32_t nsecs;
	uint32_t secs;

	pjdlog_debug(5, " . . . . + linau_record_parse_time");

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	buflen = strlen(buf);

	locate_msg(buf, &msgstart, &secspos, &nsecspos, &idpos, &msgend);

	/* Set the id field. */
	secs = extract_uint32(buf, secspos, nsecspos - 2);
	nsecs = extract_uint32(buf, nsecspos, idpos - 2);

	time = combine_secs_with_nsecs(secs, nsecs);

	pjdlog_debug(5, " . . . . -");

	return (time);
}

char *
linau_record_parse_type(const char *buf)
{
	size_t buflen;
	size_t typeend;
	size_t typelen;
	size_t typenextspacepos;
	size_t typeprefixlen;
	size_t typestart;
	char *type;
	char *typenextspace;
	const char *typeprefix;

	pjdlog_debug(4, " . . . + linau_record_parse_type");

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0'));

	buflen = strlen(buf);

	typeprefix = "type";
	typeprefixlen = strlen(typeprefix);

	/* XXX Does it make sense? */
	PJDLOG_ASSERT(typeprefixlen + 2 < buflen);
	pjdlog_debug(4, " . . . . (%.*s), (%.*s)",
	    typeprefixlen, buf, typeprefixlen, typeprefix);
	PJDLOG_VERIFY(strncmp(buf, typeprefix, typeprefixlen) == 0);

	typestart = typeprefixlen + 1;

	PJDLOG_ASSERT(typestart < buflen);
	PJDLOG_ASSERT(isprint(buf[typestart]) != 0);

	typenextspace = strchr(buf + typestart, ' ');
	PJDLOG_VERIFY(typenextspace != NULL);
	typenextspacepos = typenextspace - buf;
	typeend = typenextspacepos - 1;
	PJDLOG_ASSERT(typestart <= typeend);
	PJDLOG_ASSERT(buf[typeend] != ' ');

	typelen = typeend - typestart + 1;
	pjdlog_debug(4, " . . . . Raw type: (%zu) (%.*s)", typelen,
	    (int)typelen, buf + typestart);

	type = extract_substring(buf, typestart, typelen);

	pjdlog_debug(4, " . . . -");

	return (type);
}

/*
 * I assume that every legal text file ends up with a newline.
 *
 * Returns NULL on EOF.
 */
struct linau_record *
linau_record_fetch(FILE *fp)
{
	size_t buflen;
	char *data;
	struct sbuf *inbuf;
	char rawbuf[BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE];
	struct linau_record *record;

	pjdlog_debug(3, " . . + linau_record_fetch");

	PJDLOG_ASSERT(fp != NULL);

	inbuf = sbuf_new_auto();
	PJDLOG_VERIFY(inbuf != NULL);

	do {
		errno = 0;

		if (fgets(rawbuf, sizeof(rawbuf), fp) == NULL) {
			PJDLOG_VERIFY(errno == 0);
			pjdlog_debug(3, " . . . EOF");
			sbuf_delete(inbuf);
			return NULL; /* EOF */
		}

		pjdlog_debug(3, " . . . rawbuf: (%s)", rawbuf);
		PJDLOG_VERIFY(sbuf_cat(inbuf, rawbuf) == 0);
	} while (strstr(rawbuf, "\n\0") == NULL);

	PJDLOG_VERIFY(sbuf_finish(inbuf) == 0);

	/* Check if the last record is valid (has a terminating newline). */
	PJDLOG_ASSERT(sbuf_len(inbuf) != -1);
	buflen = sbuf_len(inbuf);
	data = sbuf_data(inbuf);
	pjdlog_debug(3, " . . . buflen: (%zu)", buflen);
	/* XXX Assert or verify? This is a vital assumption. */
	PJDLOG_VERIFY(strcmp(data + (buflen - 1), "\n\0") == 0);

	/* Remove the trailing newline. */
	data[buflen - 1] = '\0';

	pjdlog_debug(3, " . . . Read record: (%s)", data);

	record = linau_record_parse(data);

	pjdlog_debug(3, " . . -");

	return (record);
}

/*
 * Compare the records' timestamps and ids.
 *
 * The logic follows the follwing pattern:
 * - Compare by the times and return either 1 or -1 if they differ;
 * - Compare by the ids and return either 1 or -1 if they differ;
 * - Return 0 if both times and ids matches.
 *
 * Returns -1 if reca seems to be earlier in terms of the time and the id
 * and 1 if recb seems to be earlier. 0 if the time and the ids are the
 * same.
 */
int
linau_record_comapre_origin(const struct linau_record *reca,
    const struct linau_record *recb)
{
	uint64_t recatime;
	uint64_t recbtime;
	uint32_t recaid;
	uint32_t recbid;

	PJDLOG_ASSERT(reca != NULL);
	PJDLOG_ASSERT(recb != NULL);

	recatime = linau_record_get_time(reca);
	recbtime = linau_record_get_time(recb);
	recaid = linau_record_get_id(reca);
	recbid = linau_record_get_id(recb);

	return (linau_proto_compare_origin(recaid, recatime, recbid, recbtime));
}

void
linau_record_to_au(int aurecordd, const struct linau_record *record)
{
	int typenum;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(record->lr_type != NULL);
	PJDLOG_ASSERT(record->lr_fields != NULL);
	PJDLOG_ASSERT(aurecordd >= 0);

	/* Get the identification number of the type. */
	typenum = get_linau_type_num(linau_record_get_type(record));

	/* Generate a token. */
	convert_to_au(aurecordd, record, typenum);
}

static int
get_linau_type_num(const char *type)
{

	PJDLOG_ASSERT(type != NULL);

	if (strcmp(LINAU_TYPE_GET_STR, type) == 0)
		return (LINAU_TYPE_GET);
	if (strcmp(LINAU_TYPE_SET_STR, type) == 0)
		return (LINAU_TYPE_SET);
	if (strcmp(LINAU_TYPE_LIST_STR, type) == 0)
		return (LINAU_TYPE_LIST);
	if (strcmp(LINAU_TYPE_ADD_STR, type) == 0)
		return (LINAU_TYPE_ADD);
	if (strcmp(LINAU_TYPE_DEL_STR, type) == 0)
		return (LINAU_TYPE_DEL);
	if (strcmp(LINAU_TYPE_USER_STR, type) == 0)
		return (LINAU_TYPE_USER);
	if (strcmp(AUDILINAU_TYPE_SIGNAL_INFO_STR, type) == 0)
		return (AUDILINAU_TYPE_SIGNAL_INFO);
	if (strcmp(LINAU_TYPE_ADD_RULE_STR, type) == 0)
		return (LINAU_TYPE_ADD_RULE);
	if (strcmp(LINAU_TYPE_DEL_RULE_STR, type) == 0)
		return (LINAU_TYPE_DEL_RULE);
	if (strcmp(LINAU_TYPE_LIST_RULES_STR, type) == 0)
		return (LINAU_TYPE_LIST_RULES);
	if (strcmp(LINAU_TYPE_TRIM_STR, type) == 0)
		return (LINAU_TYPE_TRIM);
	if (strcmp(LINAU_TYPE_MAKE_EQUIV_STR, type) == 0)
		return (LINAU_TYPE_MAKE_EQUIV);
	if (strcmp(LINAU_TYPE_TTY_GET_STR, type) == 0)
		return (LINAU_TYPE_TTY_GET);
	if (strcmp(LINAU_TYPE_TTY_SET_STR, type) == 0)
		return (LINAU_TYPE_TTY_SET);
	if (strcmp(LINAU_TYPE_SET_FEATURE_STR, type) == 0)
		return (LINAU_TYPE_SET_FEATURE);
	if (strcmp(LINAU_TYPE_GET_FEATURE_STR, type) == 0)
		return (LINAU_TYPE_GET_FEATURE);
	if (strcmp(AUDILINAU_TYPE_USER_ACCT_STR, type) == 0)
		return (AUDILINAU_TYPE_USER_ACCT);
	if (strcmp(AUDILINAU_TYPE_CRED_ACQ_STR, type) == 0)
		return (AUDILINAU_TYPE_CRED_ACQ);
	if (strcmp(AUDILINAU_TYPE_USER_START_STR, type) == 0)
		return (AUDILINAU_TYPE_USER_START);
	if (strcmp(AUDILINAU_TYPE_USER_AVC_STR, type) == 0)
		return (AUDILINAU_TYPE_USER_AVC);
	if (strcmp(AUDILINAU_TYPE_USER_ERR_STR, type) == 0)
		return (AUDILINAU_TYPE_USER_ERR);
	if (strcmp(AUDILINAU_TYPE_USYS_CONFIG_STR, type) == 0)
		return (AUDILINAU_TYPE_USYS_CONFIG);
	if (strcmp(LINAU_TYPE_USER_LOGIN_STR, type) == 0)
		return (LINAU_TYPE_USER_LOGIN);
	if (strcmp(LINAU_TYPE_USER_LOGOUT_STR, type) == 0)
		return (LINAU_TYPE_USER_LOGOUT);
	if (strcmp(LINAU_TYPE_ADD_USER_STR, type) == 0)
		return (LINAU_TYPE_ADD_USER);
	if (strcmp(LINAU_TYPE_DEL_USER_STR, type) == 0)
		return (LINAU_TYPE_DEL_USER);
	if (strcmp(LINAU_TYPE_ADD_GROUP_STR, type) == 0)
		return (LINAU_TYPE_ADD_GROUP);
	if (strcmp(LINAU_TYPE_DEL_GROUP_STR, type) == 0)
		return (LINAU_TYPE_DEL_GROUP);
	if (strcmp(LINAU_TYPE_DAC_CHECK_STR, type) == 0)
		return (LINAU_TYPE_DAC_CHECK);
	if (strcmp(LINAU_TYPE_CHGRP_ID_STR, type) == 0)
		return (LINAU_TYPE_CHGRP_ID);
	if (strcmp(LINAU_TYPE_TEST_STR, type) == 0)
		return (LINAU_TYPE_TEST);
	if (strcmp(LINAU_TYPE_TRUSTED_APP_STR, type) == 0)
		return (LINAU_TYPE_TRUSTED_APP);
	if (strcmp(LINAU_TYPE_USER_SELINUX_ERR_STR, type) == 0)
		return (LINAU_TYPE_USER_SELINUX_ERR);
	if (strcmp(LINAU_TYPE_USER_CMD_STR, type) == 0)
		return (LINAU_TYPE_USER_CMD);
	if (strcmp(LINAU_TYPE_USER_TTY_STR, type) == 0)
		return (LINAU_TYPE_USER_TTY);
	if (strcmp(LINAU_TYPE_CHUSER_ID_STR, type) == 0)
		return (LINAU_TYPE_CHUSER_ID);
	if (strcmp(LINAU_TYPE_GRP_AUTH_STR, type) == 0)
		return (LINAU_TYPE_GRP_AUTH);
	if (strcmp(LINAU_TYPE_MAC_CHECK_STR, type) == 0)
		return (LINAU_TYPE_MAC_CHECK);
	if (strcmp(LINAU_TYPE_ACCT_LOCK_STR, type) == 0)
		return (LINAU_TYPE_ACCT_LOCK);
	if (strcmp(LINAU_TYPE_ACCT_UNLOCK_STR, type) == 0)
		return (LINAU_TYPE_ACCT_UNLOCK);
	if (strcmp(LINAU_TYPE_SYSTEM_BOOT_STR, type) == 0)
		return (LINAU_TYPE_SYSTEM_BOOT);
	if (strcmp(LINAU_TYPE_SYSTEM_SHUTDOWN_STR, type) == 0)
		return (LINAU_TYPE_SYSTEM_SHUTDOWN);
	if (strcmp(LINAU_TYPE_SYSTEM_RUNLEVEL_STR, type) == 0)
		return (LINAU_TYPE_SYSTEM_RUNLEVEL);
	if (strcmp(LINAU_TYPE_SERVICE_START_STR, type) == 0)
		return (LINAU_TYPE_SERVICE_START);
	if (strcmp(LINAU_TYPE_SERVICE_STOP_STR, type) == 0)
		return (LINAU_TYPE_SERVICE_STOP);
	if (strcmp(LINAU_TYPE_GRP_MGMT_STR, type) == 0)
		return (LINAU_TYPE_GRP_MGMT);
	if (strcmp(LINAU_TYPE_GRP_CHAUTHTOK_STR, type) == 0)
		return (LINAU_TYPE_GRP_CHAUTHTOK);
	if (strcmp(LINAU_TYPE_DAEMON_START_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_START);
	if (strcmp(LINAU_TYPE_DAEMON_END_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_END);
	if (strcmp(LINAU_TYPE_DAEMON_ABORT_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_ABORT);
	if (strcmp(LINAU_TYPE_DAEMON_CONFIG_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_CONFIG);
	if (strcmp(LINAU_TYPE_DAEMON_RECONFIG_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_RECONFIG);
	if (strcmp(LINAU_TYPE_DAEMON_ROTATE_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_ROTATE);
	if (strcmp(LINAU_TYPE_DAEMON_RESUME_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_RESUME);
	if (strcmp(LINAU_TYPE_DAEMON_ACCEPT_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_ACCEPT);
	if (strcmp(LINAU_TYPE_DAEMON_CLOSE_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_CLOSE);
	if (strcmp(LINAU_TYPE_DAEMON_ERR_STR, type) == 0)
		return (LINAU_TYPE_DAEMON_ERR);
	if (strcmp(LINAU_TYPE_SYSCALL_STR, type) == 0)
		return (LINAU_TYPE_SYSCALL);
	if (strcmp(LINAU_TYPE_FS_WATCH_STR, type) == 0)
		return (LINAU_TYPE_FS_WATCH);
	if (strcmp(LINAU_TYPE_PATH_STR, type) == 0)
		return (LINAU_TYPE_PATH);
	if (strcmp(LINAU_TYPE_IPC_STR, type) == 0)
		return (LINAU_TYPE_IPC);
	if (strcmp(LINAU_TYPE_SOCKETCALL_STR, type) == 0)
		return (LINAU_TYPE_SOCKETCALL);
	if (strcmp(LINAU_TYPE_CONFIG_CHANGE_STR, type) == 0)
		return (LINAU_TYPE_CONFIG_CHANGE);
	if (strcmp(LINAU_TYPE_SOCKADDR_STR, type) == 0)
		return (LINAU_TYPE_SOCKADDR);
	if (strcmp(LINAU_TYPE_CWD_STR, type) == 0)
		return (LINAU_TYPE_CWD);
	if (strcmp(LINAU_TYPE_FS_INODE_STR, type) == 0)
		return (LINAU_TYPE_FS_INODE);
	if (strcmp(LINAU_TYPE_EXECVE_STR, type) == 0)
		return (LINAU_TYPE_EXECVE);
	if (strcmp(LINAU_TYPE_IPC_SET_PERM_STR, type) == 0)
		return (LINAU_TYPE_IPC_SET_PERM);
	if (strcmp(LINAU_TYPE_MQ_OPEN_STR, type) == 0)
		return (LINAU_TYPE_MQ_OPEN);
	if (strcmp(LINAU_TYPE_MQ_SENDRECV_STR, type) == 0)
		return (LINAU_TYPE_MQ_SENDRECV);
	if (strcmp(LINAU_TYPE_MQ_NOTIFY_STR, type) == 0)
		return (LINAU_TYPE_MQ_NOTIFY);
	if (strcmp(LINAU_TYPE_MQ_GETSETATTR_STR, type) == 0)
		return (LINAU_TYPE_MQ_GETSETATTR);
	if (strcmp(LINAU_TYPE_KERNEL_OTHER_STR, type) == 0)
		return (LINAU_TYPE_KERNEL_OTHER);
	if (strcmp(LINAU_TYPE_FD_PAIR_STR, type) == 0)
		return (LINAU_TYPE_FD_PAIR);
	if (strcmp(LINAU_TYPE_OBJ_PID_STR, type) == 0)
		return (LINAU_TYPE_OBJ_PID);
	if (strcmp(LINAU_TYPE_TTY_STR, type) == 0)
		return (LINAU_TYPE_TTY);
	if (strcmp(LINAU_TYPE_EOE_STR, type) == 0)
		return (LINAU_TYPE_EOE);
	if (strcmp(LINAU_TYPE_BPRM_FCAPS_STR, type) == 0)
		return (LINAU_TYPE_BPRM_FCAPS);
	if (strcmp(LINAU_TYPE_CAPSET_STR, type) == 0)
		return (LINAU_TYPE_CAPSET);
	if (strcmp(LINAU_TYPE_MMAP_STR, type) == 0)
		return (LINAU_TYPE_MMAP);
	if (strcmp(LINAU_TYPE_NETFILTER_PKT_STR, type) == 0)
		return (LINAU_TYPE_NETFILTER_PKT);
	if (strcmp(LINAU_TYPE_NETFILTER_CFG_STR, type) == 0)
		return (LINAU_TYPE_NETFILTER_CFG);
	if (strcmp(LINAU_TYPE_SECCOMP_STR, type) == 0)
		return (LINAU_TYPE_SECCOMP);
	if (strcmp(LINAU_TYPE_PROCTITLE_STR, type) == 0)
		return (LINAU_TYPE_PROCTITLE);
	if (strcmp(LINAU_TYPE_FEATURE_CHANGE_STR, type) == 0)
		return (LINAU_TYPE_FEATURE_CHANGE);
	if (strcmp(LINAU_TYPE_AVC_STR, type) == 0)
		return (LINAU_TYPE_AVC);
	if (strcmp(LINAU_TYPE_SELINUX_ERR_STR, type) == 0)
		return (LINAU_TYPE_SELINUX_ERR);
	if (strcmp(LINAU_TYPE_AVC_PATH_STR, type) == 0)
		return (LINAU_TYPE_AVC_PATH);
	if (strcmp(LINAU_TYPE_MAC_POLICY_LOAD_STR, type) == 0)
		return (LINAU_TYPE_MAC_POLICY_LOAD);
	if (strcmp(LINAU_TYPE_MAC_STATUS_STR, type) == 0)
		return (LINAU_TYPE_MAC_STATUS);
	if (strcmp(LINAU_TYPE_MAC_CONFIG_CHANGE_STR, type) == 0)
		return (LINAU_TYPE_MAC_CONFIG_CHANGE);
	if (strcmp(LINAU_TYPE_MAC_UNLBL_ALLOW_STR, type) == 0)
		return (LINAU_TYPE_MAC_UNLBL_ALLOW);
	if (strcmp(LINAU_TYPE_MAC_CIPSOV4_ADD_STR, type) == 0)
		return (LINAU_TYPE_MAC_CIPSOV4_ADD);
	if (strcmp(LINAU_TYPE_MAC_CIPSOV4_DEL_STR, type) == 0)
		return (LINAU_TYPE_MAC_CIPSOV4_DEL);
	if (strcmp(LINAU_TYPE_MAC_MAP_ADD_STR, type) == 0)
		return (LINAU_TYPE_MAC_MAP_ADD);
	if (strcmp(LINAU_TYPE_MAC_MAP_DEL_STR, type) == 0)
		return (LINAU_TYPE_MAC_MAP_DEL);
	if (strcmp(LINAU_TYPE_MAC_IPSEC_ADDSA_STR, type) == 0)
		return (LINAU_TYPE_MAC_IPSEC_ADDSA);
	if (strcmp(LINAU_TYPE_MAC_IPSEC_DELSA_STR, type) == 0)
		return (LINAU_TYPE_MAC_IPSEC_DELSA);
	if (strcmp(LINAU_TYPE_MAC_IPSEC_ADDSPD_STR, type) == 0)
		return (LINAU_TYPE_MAC_IPSEC_ADDSPD);
	if (strcmp(LINAU_TYPE_MAC_IPSEC_DELSPD_STR, type) == 0)
		return (LINAU_TYPE_MAC_IPSEC_DELSPD);
	if (strcmp(LINAU_TYPE_MAC_IPSEC_EVENT_STR, type) == 0)
		return (LINAU_TYPE_MAC_IPSEC_EVENT);
	if (strcmp(LINAU_TYPE_MAC_UNLBL_STCADD_STR, type) == 0)
		return (LINAU_TYPE_MAC_UNLBL_STCADD);
	if (strcmp(LINAU_TYPE_MAC_UNLBL_STCDEL_STR, type) == 0)
		return (LINAU_TYPE_MAC_UNLBL_STCDEL);
	if (strcmp(LINAU_TYPE_ANOM_PROMISCUOUS_STR, type) == 0)
		return (LINAU_TYPE_ANOM_PROMISCUOUS);
	if (strcmp(LINAU_TYPE_ANOM_ABEND_STR, type) == 0)
		return (LINAU_TYPE_ANOM_ABEND);
	if (strcmp(LINAU_TYPE_ANOM_LINK_STR, type) == 0)
		return (LINAU_TYPE_ANOM_LINK);
	if (strcmp(LINAU_TYPE_INTEGRITY_DATA_STR, type) == 0)
		return (LINAU_TYPE_INTEGRITY_DATA);
	if (strcmp(LINAU_TYPE_INTEGRITY_STATUS_STR, type) == 0)
		return (LINAU_TYPE_INTEGRITY_STATUS);
	if (strcmp(LINAU_TYPE_INTEGRITY_HASH_STR, type) == 0)
		return (LINAU_TYPE_INTEGRITY_HASH);
	if (strcmp(LINAU_TYPE_INTEGRITY_PCR_STR, type) == 0)
		return (LINAU_TYPE_INTEGRITY_PCR);
	if (strcmp(LINAU_TYPE_INTEGRITY_RULE_STR, type) == 0)
		return (LINAU_TYPE_INTEGRITY_RULE);
	if (strcmp(LINAU_TYPE_AA_STR, type) == 0)
		return (LINAU_TYPE_AA);
	if (strcmp(LINAU_TYPE_APPARMOR_AUDIT_STR, type) == 0)
		return (LINAU_TYPE_APPARMOR_AUDIT);
	if (strcmp(LINAU_TYPE_APPARMOR_ALLOWED_STR, type) == 0)
		return (LINAU_TYPE_APPARMOR_ALLOWED);
	if (strcmp(LINAU_TYPE_APPARMOR_DENIED_STR, type) == 0)
		return (LINAU_TYPE_APPARMOR_DENIED);
	if (strcmp(LINAU_TYPE_APPARMOR_HINT_STR, type) == 0)
		return (LINAU_TYPE_APPARMOR_HINT);
	if (strcmp(LINAU_TYPE_APPARMOR_STATUS_STR, type) == 0)
		return (LINAU_TYPE_APPARMOR_STATUS);
	if (strcmp(LINAU_TYPE_APPARMOR_ERROR_STR, type) == 0)
		return (LINAU_TYPE_APPARMOR_ERROR);
	if (strcmp(LINAU_TYPE_KERNEL_STR, type) == 0)
		return (LINAU_TYPE_KERNEL);
	if (strcmp(LINAU_TYPE_ANOM_LOGIN_FAILURES_STR, type) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_FAILURES);
	if (strcmp(LINAU_TYPE_ANOM_LOGIN_TIME_STR, type) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_TIME);
	if (strcmp(LINAU_TYPE_ANOM_LOGIN_SESSIONS_STR, type) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_SESSIONS);
	if (strcmp(LINAU_TYPE_ANOM_LOGIN_ACCT_STR, type) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_ACCT);
	if (strcmp(LINAU_TYPE_ANOM_LOGIN_LOCATION_STR, type) == 0)
		return (LINAU_TYPE_ANOM_LOGIN_LOCATION);
	if (strcmp(LINAU_TYPE_ANOM_MAX_DAC_STR, type) == 0)
		return (LINAU_TYPE_ANOM_MAX_DAC);
	if (strcmp(LINAU_TYPE_ANOM_MAX_MAC_STR, type) == 0)
		return (LINAU_TYPE_ANOM_MAX_MAC);
	if (strcmp(LINAU_TYPE_ANOM_AMTU_FAIL_STR, type) == 0)
		return (LINAU_TYPE_ANOM_AMTU_FAIL);
	if (strcmp(LINAU_TYPE_ANOM_RBAC_FAIL_STR, type) == 0)
		return (LINAU_TYPE_ANOM_RBAC_FAIL);
	if (strcmp(LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL_STR, type) == 0)
		return (LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL);
	if (strcmp(LINAU_TYPE_ANOM_CRYPTO_FAIL_STR, type) == 0)
		return (LINAU_TYPE_ANOM_CRYPTO_FAIL);
	if (strcmp(LINAU_TYPE_ANOM_ACCESS_FS_STR, type) == 0)
		return (LINAU_TYPE_ANOM_ACCESS_FS);
	if (strcmp(LINAU_TYPE_ANOM_EXEC_STR, type) == 0)
		return (LINAU_TYPE_ANOM_EXEC);
	if (strcmp(LINAU_TYPE_ANOM_MK_EXEC_STR, type) == 0)
		return (LINAU_TYPE_ANOM_MK_EXEC);
	if (strcmp(LINAU_TYPE_ANOM_ADD_ACCT_STR, type) == 0)
		return (LINAU_TYPE_ANOM_ADD_ACCT);
	if (strcmp(LINAU_TYPE_ANOM_DEL_ACCT_STR, type) == 0)
		return (LINAU_TYPE_ANOM_DEL_ACCT);
	if (strcmp(LINAU_TYPE_ANOM_MOD_ACCT_STR, type) == 0)
		return (LINAU_TYPE_ANOM_MOD_ACCT);
	if (strcmp(LINAU_TYPE_ANOM_ROOT_TRANS_STR, type) == 0)
		return (LINAU_TYPE_ANOM_ROOT_TRANS);
	if (strcmp(LINAU_TYPE_RESP_ANOMALY_STR, type) == 0)
		return (LINAU_TYPE_RESP_ANOMALY);
	if (strcmp(LINAU_TYPE_RESP_ALERT_STR, type) == 0)
		return (LINAU_TYPE_RESP_ALERT);
	if (strcmp(LINAU_TYPE_RESP_KILL_PROC_STR, type) == 0)
		return (LINAU_TYPE_RESP_KILL_PROC);
	if (strcmp(LINAU_TYPE_RESP_TERM_ACCESS_STR, type) == 0)
		return (LINAU_TYPE_RESP_TERM_ACCESS);
	if (strcmp(LINAU_TYPE_RESP_ACCT_REMOTE_STR, type) == 0)
		return (LINAU_TYPE_RESP_ACCT_REMOTE);
	if (strcmp(LINAU_TYPE_RESP_ACCT_LOCK_TIMED_STR, type) == 0)
		return (LINAU_TYPE_RESP_ACCT_LOCK_TIMED);
	if (strcmp(LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED_STR, type) == 0)
		return (LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED);
	if (strcmp(LINAU_TYPE_RESP_ACCT_LOCK_STR, type) == 0)
		return (LINAU_TYPE_RESP_ACCT_LOCK);
	if (strcmp(LINAU_TYPE_RESP_TERM_LOCK_STR, type) == 0)
		return (LINAU_TYPE_RESP_TERM_LOCK);
	if (strcmp(LINAU_TYPE_RESP_SEBOOL_STR, type) == 0)
		return (LINAU_TYPE_RESP_SEBOOL);
	if (strcmp(LINAU_TYPE_RESP_EXEC_STR, type) == 0)
		return (LINAU_TYPE_RESP_EXEC);
	if (strcmp(LINAU_TYPE_RESP_SINGLE_STR, type) == 0)
		return (LINAU_TYPE_RESP_SINGLE);
	if (strcmp(LINAU_TYPE_RESP_HALT_STR, type) == 0)
		return (LINAU_TYPE_RESP_HALT);
	if (strcmp(LINAU_TYPE_USER_ROLE_CHANGE_STR, type) == 0)
		return (LINAU_TYPE_USER_ROLE_CHANGE);
	if (strcmp(LINAU_TYPE_ROLE_ASSIGN_STR, type) == 0)
		return (LINAU_TYPE_ROLE_ASSIGN);
	if (strcmp(LINAU_TYPE_ROLE_REMOVE_STR, type) == 0)
		return (LINAU_TYPE_ROLE_REMOVE);
	if (strcmp(LINAU_TYPE_LABEL_OVERRIDE_STR, type) == 0)
		return (LINAU_TYPE_LABEL_OVERRIDE);
	if (strcmp(LINAU_TYPE_LABEL_LEVEL_CHANGE_STR, type) == 0)
		return (LINAU_TYPE_LABEL_LEVEL_CHANGE);
	if (strcmp(LINAU_TYPE_USER_LABELED_EXPORT_STR, type) == 0)
		return (LINAU_TYPE_USER_LABELED_EXPORT);
	if (strcmp(LINAU_TYPE_USER_UNLABELED_EXPORT_STR, type) == 0)
		return (LINAU_TYPE_USER_UNLABELED_EXPORT);
	if (strcmp(LINAU_TYPE_DEV_ALLOC_STR, type) == 0)
		return (LINAU_TYPE_DEV_ALLOC);
	if (strcmp(LINAU_TYPE_DEV_DEALLOC_STR, type) == 0)
		return (LINAU_TYPE_DEV_DEALLOC);
	if (strcmp(LINAU_TYPE_FS_RELABEL_STR, type) == 0)
		return (LINAU_TYPE_FS_RELABEL);
	if (strcmp(LINAU_TYPE_USER_MAC_POLICY_LOAD_STR, type) == 0)
		return (LINAU_TYPE_USER_MAC_POLICY_LOAD);
	if (strcmp(LINAU_TYPE_ROLE_MODIFY_STR, type) == 0)
		return (LINAU_TYPE_ROLE_MODIFY);
	if (strcmp(LINAU_TYPE_USER_MAC_CONFIG_CHANGE_STR, type) == 0)
		return (LINAU_TYPE_USER_MAC_CONFIG_CHANGE);
	if (strcmp(LINAU_TYPE_CRYPTO_TEST_USER_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_TEST_USER);
	if (strcmp(LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER);
	if (strcmp(LINAU_TYPE_CRYPTO_LOGIN_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_LOGIN);
	if (strcmp(LINAU_TYPE_CRYPTO_LOGOUT_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_LOGOUT);
	if (strcmp(LINAU_TYPE_CRYPTO_KEY_USER_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_KEY_USER);
	if (strcmp(LINAU_TYPE_CRYPTO_FAILURE_USER_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_FAILURE_USER);
	if (strcmp(LINAU_TYPE_CRYPTO_REPLAY_USER_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_REPLAY_USER);
	if (strcmp(LINAU_TYPE_CRYPTO_SESSION_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_SESSION);
	if (strcmp(LINAU_TYPE_CRYPTO_IKE_SA_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_IKE_SA);
	if (strcmp(LINAU_TYPE_CRYPTO_IPSEC_SA_STR, type) == 0)
		return (LINAU_TYPE_CRYPTO_IPSEC_SA);
	if (strcmp(LINAU_TYPE_VIRT_CONTROL_STR, type) == 0)
		return (LINAU_TYPE_VIRT_CONTROL);
	if (strcmp(LINAU_TYPE_VIRT_RESOURCE_STR, type) == 0)
		return (LINAU_TYPE_VIRT_RESOURCE);
	if (strcmp(LINAU_TYPE_VIRT_MACHINE_ID_STR, type) == 0)
		return (LINAU_TYPE_VIRT_MACHINE_ID);

	return (LINAU_TYPE_UNDEFINED);
}

static void
convert_to_au(int aurecordd, const struct linau_record *record, int typenum)
{
	token_t *tok;

	switch (typenum) {
	case LINAU_TYPE_UNDEFINED:
		/* FALLTHROUGH */
	case LINAU_TYPE_GET:
		/* FALLTHROUGH */
	case LINAU_TYPE_SET:
		/* FALLTHROUGH */
	case LINAU_TYPE_LIST:
		/* FALLTHROUGH */
	case LINAU_TYPE_ADD:
		/* FALLTHROUGH */
	case LINAU_TYPE_DEL:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER:
		/* FALLTHROUGH */
	case AUDILINAU_TYPE_SIGNAL_INFO:
		/* FALLTHROUGH */
	case LINAU_TYPE_ADD_RULE:
		/* FALLTHROUGH */
	case LINAU_TYPE_DEL_RULE:
		/* FALLTHROUGH */
	case LINAU_TYPE_LIST_RULES:
		/* FALLTHROUGH */
	case LINAU_TYPE_TRIM:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAKE_EQUIV:
		/* FALLTHROUGH */
	case LINAU_TYPE_TTY_GET:
		/* FALLTHROUGH */
	case LINAU_TYPE_TTY_SET:
		/* FALLTHROUGH */
	case LINAU_TYPE_SET_FEATURE:
		/* FALLTHROUGH */
	case LINAU_TYPE_GET_FEATURE:
		/* FALLTHROUGH */
	case AUDILINAU_TYPE_USER_ACCT:
		/* FALLTHROUGH */
	case AUDILINAU_TYPE_CRED_ACQ:
		/* FALLTHROUGH */
	case AUDILINAU_TYPE_USER_START:
		/* FALLTHROUGH */
	case AUDILINAU_TYPE_USER_AVC:
		/* FALLTHROUGH */
	case AUDILINAU_TYPE_USER_ERR:
		/* FALLTHROUGH */
	case AUDILINAU_TYPE_USYS_CONFIG:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER_LOGIN:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER_LOGOUT:
		/* FALLTHROUGH */
	case LINAU_TYPE_ADD_USER:
		/* FALLTHROUGH */
	case LINAU_TYPE_DEL_USER:
		/* FALLTHROUGH */
	case LINAU_TYPE_ADD_GROUP:
		/* FALLTHROUGH */
	case LINAU_TYPE_DEL_GROUP:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAC_CHECK:
		/* FALLTHROUGH */
	case LINAU_TYPE_CHGRP_ID:
		/* FALLTHROUGH */
	case LINAU_TYPE_TEST:
		/* FALLTHROUGH */
	case LINAU_TYPE_TRUSTED_APP:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER_SELINUX_ERR:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER_CMD:

		/* FALLTHROUGH */
	case LINAU_TYPE_USER_TTY:
		/* FALLTHROUGH */
	case LINAU_TYPE_CHUSER_ID:
		/* FALLTHROUGH */
	case LINAU_TYPE_GRP_AUTH:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_CHECK:
		/* FALLTHROUGH */
	case LINAU_TYPE_ACCT_LOCK:
		/* FALLTHROUGH */
	case LINAU_TYPE_ACCT_UNLOCK:
		/* FALLTHROUGH */
	case LINAU_TYPE_SYSTEM_BOOT:
		/* FALLTHROUGH */
	case LINAU_TYPE_SYSTEM_SHUTDOWN:
		/* FALLTHROUGH */
	case LINAU_TYPE_SYSTEM_RUNLEVEL:
		/* FALLTHROUGH */
	case LINAU_TYPE_SERVICE_START:
		/* FALLTHROUGH */
	case LINAU_TYPE_SERVICE_STOP:
		/* FALLTHROUGH */
	case LINAU_TYPE_GRP_MGMT:
		/* FALLTHROUGH */
	case LINAU_TYPE_GRP_CHAUTHTOK:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_START:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_END:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_ABORT:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_CONFIG:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_RECONFIG:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_ROTATE:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_RESUME:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_ACCEPT:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_CLOSE:
		/* FALLTHROUGH */
	case LINAU_TYPE_DAEMON_ERR:
		/* FALLTHROUGH */
	case LINAU_TYPE_SYSCALL:
		/* FALLTHROUGH */
	case LINAU_TYPE_FS_WATCH:
		/* FALLTHROUGH */
	case LINAU_TYPE_PATH:
		/* FALLTHROUGH */
	case LINAU_TYPE_IPC:
		/* FALLTHROUGH */
	case LINAU_TYPE_SOCKETCALL:
		/* FALLTHROUGH */
	case LINAU_TYPE_CONFIG_CHANGE:
		/* FALLTHROUGH */
	case LINAU_TYPE_SOCKADDR:
		/* FALLTHROUGH */
	case LINAU_TYPE_CWD:
		/* FALLTHROUGH */
	case LINAU_TYPE_FS_INODE:
		/* FALLTHROUGH */
	case LINAU_TYPE_EXECVE:
		/* FALLTHROUGH */
	case LINAU_TYPE_IPC_SET_PERM:
		/* FALLTHROUGH */
	case LINAU_TYPE_MQ_OPEN:
		/* FALLTHROUGH */
	case LINAU_TYPE_MQ_SENDRECV:
		/* FALLTHROUGH */
	case LINAU_TYPE_MQ_NOTIFY:
		/* FALLTHROUGH */
	case LINAU_TYPE_MQ_GETSETATTR:
		/* FALLTHROUGH */
	case LINAU_TYPE_KERNEL_OTHER:
		/* FALLTHROUGH */
	case LINAU_TYPE_FD_PAIR:
		/* FALLTHROUGH */
	case LINAU_TYPE_OBJ_PID:
		/* FALLTHROUGH */
	case LINAU_TYPE_TTY:
		/* FALLTHROUGH */
	case LINAU_TYPE_EOE:
		/* FALLTHROUGH */
	case LINAU_TYPE_BPRM_FCAPS:
		/* FALLTHROUGH */
	case LINAU_TYPE_CAPSET:
		/* FALLTHROUGH */
	case LINAU_TYPE_MMAP:
		/* FALLTHROUGH */
	case LINAU_TYPE_NETFILTER_PKT:
		/* FALLTHROUGH */
	case LINAU_TYPE_NETFILTER_CFG:
		/* FALLTHROUGH */
	case LINAU_TYPE_SECCOMP:
		/* FALLTHROUGH */
	case LINAU_TYPE_PROCTITLE:
		/* FALLTHROUGH */
	case LINAU_TYPE_FEATURE_CHANGE:
		/* FALLTHROUGH */
	case LINAU_TYPE_AVC:
		/* FALLTHROUGH */
	case LINAU_TYPE_SELINUX_ERR:
		/* FALLTHROUGH */
	case LINAU_TYPE_AVC_PATH:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_POLICY_LOAD:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_STATUS:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_CONFIG_CHANGE:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_UNLBL_ALLOW:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_CIPSOV4_ADD:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_CIPSOV4_DEL:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_MAP_ADD:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_MAP_DEL:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_IPSEC_ADDSA:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_IPSEC_DELSA:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_IPSEC_ADDSPD:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_IPSEC_DELSPD:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_IPSEC_EVENT:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_UNLBL_STCADD:
		/* FALLTHROUGH */
	case LINAU_TYPE_MAC_UNLBL_STCDEL:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_PROMISCUOUS:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_ABEND:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_LINK:
		/* FALLTHROUGH */
	case LINAU_TYPE_INTEGRITY_DATA:
		/* FALLTHROUGH */
	case LINAU_TYPE_INTEGRITY_STATUS:
		/* FALLTHROUGH */
	case LINAU_TYPE_INTEGRITY_HASH:
		/* FALLTHROUGH */
	case LINAU_TYPE_INTEGRITY_PCR:
		/* FALLTHROUGH */
	case LINAU_TYPE_INTEGRITY_RULE:
		/* FALLTHROUGH */
	case LINAU_TYPE_AA:
		/* FALLTHROUGH */
	case LINAU_TYPE_APPARMOR_AUDIT:
		/* FALLTHROUGH */
	case LINAU_TYPE_APPARMOR_ALLOWED:
		/* FALLTHROUGH */
	case LINAU_TYPE_APPARMOR_DENIED:
		/* FALLTHROUGH */
	case LINAU_TYPE_APPARMOR_HINT:
		/* FALLTHROUGH */
	case LINAU_TYPE_APPARMOR_STATUS:
		/* FALLTHROUGH */
	case LINAU_TYPE_APPARMOR_ERROR:
		/* FALLTHROUGH */
	case LINAU_TYPE_KERNEL:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_LOGIN_FAILURES:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_LOGIN_TIME:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_LOGIN_SESSIONS:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_LOGIN_ACCT:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_LOGIN_LOCATION:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_MAX_DAC:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_MAX_MAC:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_AMTU_FAIL:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_RBAC_FAIL:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_CRYPTO_FAIL:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_ACCESS_FS:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_EXEC:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_MK_EXEC:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_ADD_ACCT:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_DEL_ACCT:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_MOD_ACCT:
		/* FALLTHROUGH */
	case LINAU_TYPE_ANOM_ROOT_TRANS:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_ANOMALY:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_ALERT:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_KILL_PROC:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_TERM_ACCESS:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_ACCT_REMOTE:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_ACCT_LOCK_TIMED:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_ACCT_LOCK:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_TERM_LOCK:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_SEBOOL:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_EXEC:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_SINGLE:
		/* FALLTHROUGH */
	case LINAU_TYPE_RESP_HALT:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER_ROLE_CHANGE:
		/* FALLTHROUGH */
	case LINAU_TYPE_ROLE_ASSIGN:
		/* FALLTHROUGH */
	case LINAU_TYPE_ROLE_REMOVE:
		/* FALLTHROUGH */
	case LINAU_TYPE_LABEL_OVERRIDE:
		/* FALLTHROUGH */
	case LINAU_TYPE_LABEL_LEVEL_CHANGE:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER_LABELED_EXPORT:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER_UNLABELED_EXPORT:
		/* FALLTHROUGH */
	case LINAU_TYPE_DEV_ALLOC:
		/* FALLTHROUGH */
	case LINAU_TYPE_DEV_DEALLOC:
		/* FALLTHROUGH */
	case LINAU_TYPE_FS_RELABEL:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER_MAC_POLICY_LOAD:
		/* FALLTHROUGH */
	case LINAU_TYPE_ROLE_MODIFY:
		/* FALLTHROUGH */
	case LINAU_TYPE_USER_MAC_CONFIG_CHANGE:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_TEST_USER:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_LOGIN:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_LOGOUT:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_KEY_USER:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_FAILURE_USER:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_REPLAY_USER:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_SESSION:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_IKE_SA:
		/* FALLTHROUGH */
	case LINAU_TYPE_CRYPTO_IPSEC_SA:
		/* FALLTHROUGH */
	case LINAU_TYPE_VIRT_CONTROL:
		/* FALLTHROUGH */
	case LINAU_TYPE_VIRT_RESOURCE:
		/* FALLTHROUGH */
	case LINAU_TYPE_VIRT_MACHINE_ID:
		tok = au_to_text(linau_record_get_text(record));
		PJDLOG_VERIFY(tok != NULL);
		PJDLOG_VERIFY(au_write(aurecordd, tok) == 0);
		break;
	}
}
