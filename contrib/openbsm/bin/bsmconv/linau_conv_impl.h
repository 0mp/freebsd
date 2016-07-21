#ifndef _LINAU_CONV_IMPL_H_
#define _LINAU_CONV_IMPL_H_
#define LINAU_TYPE_UNDEFINED_STR		""
/* #define	LINAU_TYPE_GET_STR			"GET" */
/* #define	LINAU_TYPE_SET_STR			"SET" */
/* #define	LINAU_TYPE_LIST_STR			"LIST" */
/* #define	LINAU_TYPE_ADD_STR			"ADD" */
/* #define	LINAU_TYPE_DEL_STR			"DEL" */
#define	LINAU_TYPE_USER_STR			"USER"
#define	LINAU_TYPE_LOGIN_STR			"LOGIN"
/* #define	LINAU_TYPE_SIGNAL_INFO_STR		"SIGNAL_INFO" */
/* #define	LINAU_TYPE_ADD_RULE_STR			"ADD_RULE" */
/* #define	LINAU_TYPE_DEL_RULE_STR			"DEL_RULE" */
/* #define	LINAU_TYPE_LIST_RULES_STR		"LIST_RULES" */
/* #define	LINAU_TYPE_TRIM_STR			"TRIM" */
/* #define	LINAU_TYPE_MAKE_EQUIV_STR		"MAKE_EQUIV" */
/* #define	LINAU_TYPE_TTY_GET_STR			"TTY_GET" */
/* #define	LINAU_TYPE_TTY_SET_STR			"TTY_SET" */
/* #define	LINAU_TYPE_SET_FEATURE_STR		"SET_FEATURE" */
/* #define	LINAU_TYPE_GET_FEATURE_STR		"GET_FEATURE" */
#define	LINAU_TYPE_USER_AUTH_STR		"USER_AUTH"
#define	LINAU_TYPE_USER_ACCT_STR		"USER_ACCT"
#define	LINAU_TYPE_USER_MGMT_STR		"USER_MGMT"
#define	LINAU_TYPE_CRED_ACQ_STR			"CRED_ACQ"
#define	LINAU_TYPE_CRED_DISP_STR		"CRED_DISP"
#define	LINAU_TYPE_USER_START_STR		"USER_START"
#define	LINAU_TYPE_USER_END_STR			"USER_END"
#define	LINAU_TYPE_USER_AVC_STR			"USER_AVC"
#define	LINAU_TYPE_USER_CHAUTHTOK_STR		"USER_CHAUTHTOK"
#define	LINAU_TYPE_USER_ERR_STR			"USER_ERR"
#define	LINAU_TYPE_CRED_REFR_STR		"CRED_REFR"
#define	LINAU_TYPE_USYS_CONFIG_STR		"USYS_CONFIG"
#define	LINAU_TYPE_USER_LOGIN_STR		"USER_LOGIN"
#define	LINAU_TYPE_USER_LOGOUT_STR		"USER_LOGOUT"
#define	LINAU_TYPE_ADD_USER_STR			"ADD_USER"
#define	LINAU_TYPE_DEL_USER_STR			"DEL_USER"
#define	LINAU_TYPE_ADD_GROUP_STR		"ADD_GROUP"
#define	LINAU_TYPE_DEL_GROUP_STR		"DEL_GROUP"
#define	LINAU_TYPE_DAC_CHECK_STR		"DAC_CHECK"
#define	LINAU_TYPE_CHGRP_ID_STR			"CHGRP_ID"
#define	LINAU_TYPE_TEST_STR			"TEST"
#define	LINAU_TYPE_TRUSTED_APP_STR		"TRUSTED_APP"
#define	LINAU_TYPE_USER_SELINUX_ERR_STR		"USER_SELINUX_ERR"
#define	LINAU_TYPE_USER_CMD_STR			"USER_CMD"
#define	LINAU_TYPE_USER_TTY_STR			"USER_TTY"
#define	LINAU_TYPE_CHUSER_ID_STR		"CHUSER_ID"
#define	LINAU_TYPE_GRP_AUTH_STR			"GRP_AUTH"
#define	LINAU_TYPE_MAC_CHECK_STR		"MAC_CHECK"
#define	LINAU_TYPE_ACCT_LOCK_STR		"ACCT_LOCK"
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
/* #define	LINAU_TYPE_DAEMON_RECONFIG_STR		"DAEMON_RECONFIG" */
#define	LINAU_TYPE_DAEMON_ROTATE_STR		"DAEMON_ROTATE"
#define	LINAU_TYPE_DAEMON_RESUME_STR		"DAEMON_RESUME"
#define	LINAU_TYPE_DAEMON_ACCEPT_STR		"DAEMON_ACCEPT"
#define	LINAU_TYPE_DAEMON_CLOSE_STR		"DAEMON_CLOSE"
#define	LINAU_TYPE_DAEMON_ERR_STR		"DAEMON_ERR"
#define	LINAU_TYPE_SYSCALL_STR			"SYSCALL"
/* #define	LINAU_TYPE_FS_WATCH_STR			"FS_WATCH" */
#define	LINAU_TYPE_PATH_STR			"PATH"
#define	LINAU_TYPE_IPC_STR			"IPC"
#define	LINAU_TYPE_SOCKETCALL_STR		"SOCKETCALL"
#define	LINAU_TYPE_CONFIG_CHANGE_STR		"CONFIG_CHANGE"
#define	LINAU_TYPE_SOCKADDR_STR			"SOCKADDR"
#define	LINAU_TYPE_CWD_STR			"CWD"
/* #define	LINAU_TYPE_FS_INODE_STR			"FS_INODE" */
#define	LINAU_TYPE_EXECVE_STR			"EXECVE"
#define	LINAU_TYPE_IPC_SET_PERM_STR		"IPC_SET_PERM"
#define	LINAU_TYPE_MQ_OPEN_STR			"MQ_OPEN"
#define	LINAU_TYPE_MQ_SENDRECV_STR		"MQ_SENDRECV"
#define	LINAU_TYPE_MQ_NOTIFY_STR		"MQ_NOTIFY"
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
#define	LINAU_TYPE_PROCTITLE_STR		"PROCTITLE"
#define	LINAU_TYPE_FEATURE_CHANGE_STR		"FEATURE_CHANGE"
#define	LINAU_TYPE_AVC_STR			"AVC"
#define	LINAU_TYPE_SELINUX_ERR_STR		"SELINUX_ERR"
#define	LINAU_TYPE_AVC_PATH_STR			"AVC_PATH"
#define	LINAU_TYPE_MAC_POLICY_LOAD_STR		"MAC_POLICY_LOAD"
#define	LINAU_TYPE_MAC_STATUS_STR		"MAC_STATUS"
#define	LINAU_TYPE_MAC_CONFIG_CHANGE_STR	"MAC_CONFIG_CHANGE"
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
#define	LINAU_TYPE_ANOM_LINK_STR		"ANOM_LINK"
#define	LINAU_TYPE_INTEGRITY_DATA_STR		"INTEGRITY_DATA"
#define	LINAU_TYPE_INTEGRITY_METADATA_STR	"INTEGRITY_METADATA"
#define	LINAU_TYPE_INTEGRITY_STATUS_STR		"INTEGRITY_STATUS"
#define	LINAU_TYPE_INTEGRITY_HASH_STR		"INTEGRITY_HASH"
#define	LINAU_TYPE_INTEGRITY_PCR_STR		"INTEGRITY_PCR"
#define	LINAU_TYPE_INTEGRITY_RULE_STR		"INTEGRITY_RULE"
#define	LINAU_TYPE_AA_STR			"APPARMOR"
#define	LINAU_TYPE_APPARMOR_AUDIT_STR		"APPARMOR_AUDIT"
#define	LINAU_TYPE_APPARMOR_ALLOWED_STR		"APPARMOR_ALLOWED"
#define	LINAU_TYPE_APPARMOR_DENIED_STR		"APPARMOR_DENIED"
#define	LINAU_TYPE_APPARMOR_HINT_STR		"APPARMOR_HINT"
#define	LINAU_TYPE_APPARMOR_STATUS_STR		"APPARMOR_STATUS"
#define	LINAU_TYPE_APPARMOR_ERROR_STR		"APPARMOR_ERROR"
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
#define	LINAU_TYPE_ANOM_EXEC_STR		"ANOM_EXEC"
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
#define	LINAU_TYPE_RESP_EXEC_STR		"RESP_EXEC"
#define	LINAU_TYPE_RESP_SINGLE_STR		"RESP_SINGLE"
#define	LINAU_TYPE_RESP_HALT_STR		"RESP_HALT"
#define	LINAU_TYPE_USER_ROLE_CHANGE_STR		"USER_ROLE_CHANGE"
#define	LINAU_TYPE_ROLE_ASSIGN_STR		"ROLE_ASSIGN"
#define	LINAU_TYPE_ROLE_REMOVE_STR		"ROLE_REMOVE"
#define	LINAU_TYPE_LABEL_OVERRIDE_STR		"LABEL_OVERRIDE"
#define	LINAU_TYPE_LABEL_LEVEL_CHANGE_STR	"LABEL_LEVEL_CHANGE"
#define	LINAU_TYPE_USER_LABELED_EXPORT_STR	"USER_LABELED_EXPORT"
#define	LINAU_TYPE_USER_UNLABELED_EXPORT_STR	"USER_UNLABELED_EXPORT"
#define	LINAU_TYPE_DEV_ALLOC_STR		"DEV_ALLOC"
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

#define LINAU_TYPE_UNDEFINED			0
/* #define	LINAU_TYPE_GET				1 */
/* #define	LINAU_TYPE_SET				2 */
/* #define	LINAU_TYPE_LIST				3 */
/* #define	LINAU_TYPE_ADD				4 */
/* #define	LINAU_TYPE_DEL				5 */
#define	LINAU_TYPE_USER				6
#define	LINAU_TYPE_LOGIN			7
/* #define	LINAU_TYPE_SIGNAL_INFO			8 */
/* #define	LINAU_TYPE_ADD_RULE			9 */
/* #define	LINAU_TYPE_DEL_RULE			10 */
/* #define	LINAU_TYPE_LIST_RULES			11 */
/* #define	LINAU_TYPE_TRIM				12 */
/* #define	LINAU_TYPE_MAKE_EQUIV			13 */
/* #define	LINAU_TYPE_TTY_GET			14 */
/* #define	LINAU_TYPE_TTY_SET			15 */
/* #define	LINAU_TYPE_SET_FEATURE			16 */
/* #define	LINAU_TYPE_GET_FEATURE			17 */
#define	LINAU_TYPE_USER_AUTH			18
#define	LINAU_TYPE_USER_ACCT			19
#define	LINAU_TYPE_USER_MGMT			20
#define	LINAU_TYPE_CRED_ACQ			21
#define	LINAU_TYPE_CRED_DISP			22
#define	LINAU_TYPE_USER_START			23
#define	LINAU_TYPE_USER_END			24
#define	LINAU_TYPE_USER_AVC			25
#define	LINAU_TYPE_USER_CHAUTHTOK		26
#define	LINAU_TYPE_USER_ERR			27
#define	LINAU_TYPE_CRED_REFR			28
#define	LINAU_TYPE_USYS_CONFIG			29
#define	LINAU_TYPE_USER_LOGIN			30
#define	LINAU_TYPE_USER_LOGOUT			31
#define	LINAU_TYPE_ADD_USER			32
#define	LINAU_TYPE_DEL_USER			33
#define	LINAU_TYPE_ADD_GROUP			34
#define	LINAU_TYPE_DEL_GROUP			35
#define	LINAU_TYPE_DAC_CHECK			36
#define	LINAU_TYPE_CHGRP_ID			37
#define	LINAU_TYPE_TEST				38
#define	LINAU_TYPE_TRUSTED_APP			39
#define	LINAU_TYPE_USER_SELINUX_ERR		40
#define	LINAU_TYPE_USER_CMD			41
#define	LINAU_TYPE_USER_TTY			42
#define	LINAU_TYPE_CHUSER_ID			43
#define	LINAU_TYPE_GRP_AUTH			44
#define	LINAU_TYPE_MAC_CHECK			45
#define	LINAU_TYPE_ACCT_LOCK			46
#define	LINAU_TYPE_ACCT_UNLOCK			47
#define	LINAU_TYPE_SYSTEM_BOOT			48
#define	LINAU_TYPE_SYSTEM_SHUTDOWN		49
#define	LINAU_TYPE_SYSTEM_RUNLEVEL		50
#define	LINAU_TYPE_SERVICE_START		51
#define	LINAU_TYPE_SERVICE_STOP			52
#define	LINAU_TYPE_GRP_MGMT			53
#define	LINAU_TYPE_GRP_CHAUTHTOK		54
#define	LINAU_TYPE_DAEMON_START			55
#define	LINAU_TYPE_DAEMON_END			56
#define	LINAU_TYPE_DAEMON_ABORT			57
#define	LINAU_TYPE_DAEMON_CONFIG		58
/* #define	LINAU_TYPE_DAEMON_RECONFIG		59 */
#define	LINAU_TYPE_DAEMON_ROTATE		60
#define	LINAU_TYPE_DAEMON_RESUME		61
#define	LINAU_TYPE_DAEMON_ACCEPT		62
#define	LINAU_TYPE_DAEMON_CLOSE			63
#define	LINAU_TYPE_DAEMON_ERR			64
#define	LINAU_TYPE_SYSCALL			65
/* #define	LINAU_TYPE_FS_WATCH			66 */
#define	LINAU_TYPE_PATH				67
#define	LINAU_TYPE_IPC				68
#define	LINAU_TYPE_SOCKETCALL			69
#define	LINAU_TYPE_CONFIG_CHANGE		70
#define	LINAU_TYPE_SOCKADDR			71
#define	LINAU_TYPE_CWD				72
/* #define	LINAU_TYPE_FS_INODE			73 */
#define	LINAU_TYPE_EXECVE			74
#define	LINAU_TYPE_IPC_SET_PERM			75
#define	LINAU_TYPE_MQ_OPEN			76
#define	LINAU_TYPE_MQ_SENDRECV			77
#define	LINAU_TYPE_MQ_NOTIFY			78
#define	LINAU_TYPE_MQ_GETSETATTR		79
#define	LINAU_TYPE_KERNEL_OTHER			80
#define	LINAU_TYPE_FD_PAIR			81
#define	LINAU_TYPE_OBJ_PID			82
#define	LINAU_TYPE_TTY				83
#define	LINAU_TYPE_EOE				84
#define	LINAU_TYPE_BPRM_FCAPS			85
#define	LINAU_TYPE_CAPSET			86
#define	LINAU_TYPE_MMAP				87
#define	LINAU_TYPE_NETFILTER_PKT		88
#define	LINAU_TYPE_NETFILTER_CFG		89
#define	LINAU_TYPE_SECCOMP			90
#define	LINAU_TYPE_PROCTITLE			91
#define	LINAU_TYPE_FEATURE_CHANGE		92
#define	LINAU_TYPE_AVC				93
#define	LINAU_TYPE_SELINUX_ERR			94
#define	LINAU_TYPE_AVC_PATH			95
#define	LINAU_TYPE_MAC_POLICY_LOAD		96
#define	LINAU_TYPE_MAC_STATUS			97
#define	LINAU_TYPE_MAC_CONFIG_CHANGE		98
#define	LINAU_TYPE_MAC_UNLBL_ALLOW		99
#define	LINAU_TYPE_MAC_CIPSOV4_ADD		100
#define	LINAU_TYPE_MAC_CIPSOV4_DEL		101
#define	LINAU_TYPE_MAC_MAP_ADD			102
#define	LINAU_TYPE_MAC_MAP_DEL			103
#define	LINAU_TYPE_MAC_IPSEC_ADDSA		104
#define	LINAU_TYPE_MAC_IPSEC_DELSA		105
#define	LINAU_TYPE_MAC_IPSEC_ADDSPD		106
#define	LINAU_TYPE_MAC_IPSEC_DELSPD		107
#define	LINAU_TYPE_MAC_IPSEC_EVENT		108
#define	LINAU_TYPE_MAC_UNLBL_STCADD		109
#define	LINAU_TYPE_MAC_UNLBL_STCDEL		110
#define	LINAU_TYPE_ANOM_PROMISCUOUS		111
#define	LINAU_TYPE_ANOM_ABEND			112
#define	LINAU_TYPE_ANOM_LINK			113
#define	LINAU_TYPE_INTEGRITY_DATA		114
#define	LINAU_TYPE_INTEGRITY_METADATA		115
#define	LINAU_TYPE_INTEGRITY_STATUS		116
#define	LINAU_TYPE_INTEGRITY_HASH		117
#define	LINAU_TYPE_INTEGRITY_PCR		118
#define	LINAU_TYPE_INTEGRITY_RULE		119
#define	LINAU_TYPE_AA				120
#define	LINAU_TYPE_APPARMOR_AUDIT		121
#define	LINAU_TYPE_APPARMOR_ALLOWED		122
#define	LINAU_TYPE_APPARMOR_DENIED		123
#define	LINAU_TYPE_APPARMOR_HINT		124
#define	LINAU_TYPE_APPARMOR_STATUS		125
#define	LINAU_TYPE_APPARMOR_ERROR		126
#define	LINAU_TYPE_KERNEL			127
#define	LINAU_TYPE_ANOM_LOGIN_FAILURES		128
#define	LINAU_TYPE_ANOM_LOGIN_TIME		129
#define	LINAU_TYPE_ANOM_LOGIN_SESSIONS		130
#define	LINAU_TYPE_ANOM_LOGIN_ACCT		131
#define	LINAU_TYPE_ANOM_LOGIN_LOCATION		132
#define	LINAU_TYPE_ANOM_MAX_DAC			133
#define	LINAU_TYPE_ANOM_MAX_MAC			134
#define	LINAU_TYPE_ANOM_AMTU_FAIL		135
#define	LINAU_TYPE_ANOM_RBAC_FAIL		136
#define	LINAU_TYPE_ANOM_RBAC_INTEGRITY_FAIL	137
#define	LINAU_TYPE_ANOM_CRYPTO_FAIL		138
#define	LINAU_TYPE_ANOM_ACCESS_FS		139
#define	LINAU_TYPE_ANOM_EXEC			140
#define	LINAU_TYPE_ANOM_MK_EXEC			141
#define	LINAU_TYPE_ANOM_ADD_ACCT		142
#define	LINAU_TYPE_ANOM_DEL_ACCT		143
#define	LINAU_TYPE_ANOM_MOD_ACCT		144
#define	LINAU_TYPE_ANOM_ROOT_TRANS		145
#define	LINAU_TYPE_RESP_ANOMALY			146
#define	LINAU_TYPE_RESP_ALERT			147
#define	LINAU_TYPE_RESP_KILL_PROC		148
#define	LINAU_TYPE_RESP_TERM_ACCESS		149
#define	LINAU_TYPE_RESP_ACCT_REMOTE		150
#define	LINAU_TYPE_RESP_ACCT_LOCK_TIMED		151
#define	LINAU_TYPE_RESP_ACCT_UNLOCK_TIMED	152
#define	LINAU_TYPE_RESP_ACCT_LOCK		153
#define	LINAU_TYPE_RESP_TERM_LOCK		154
#define	LINAU_TYPE_RESP_SEBOOL			155
#define	LINAU_TYPE_RESP_EXEC			156
#define	LINAU_TYPE_RESP_SINGLE			157
#define	LINAU_TYPE_RESP_HALT			158
#define	LINAU_TYPE_USER_ROLE_CHANGE		159
#define	LINAU_TYPE_ROLE_ASSIGN			160
#define	LINAU_TYPE_ROLE_REMOVE			161
#define	LINAU_TYPE_LABEL_OVERRIDE		162
#define	LINAU_TYPE_LABEL_LEVEL_CHANGE		163
#define	LINAU_TYPE_USER_LABELED_EXPORT		164
#define	LINAU_TYPE_USER_UNLABELED_EXPORT	165
#define	LINAU_TYPE_DEV_ALLOC			166
#define	LINAU_TYPE_DEV_DEALLOC			167
#define	LINAU_TYPE_FS_RELABEL			168
#define	LINAU_TYPE_USER_MAC_POLICY_LOAD		169
#define	LINAU_TYPE_ROLE_MODIFY			170
#define	LINAU_TYPE_USER_MAC_CONFIG_CHANGE	171
#define	LINAU_TYPE_CRYPTO_TEST_USER		172
#define	LINAU_TYPE_CRYPTO_PARAM_CHANGE_USER	173
#define	LINAU_TYPE_CRYPTO_LOGIN			174
#define	LINAU_TYPE_CRYPTO_LOGOUT		175
#define	LINAU_TYPE_CRYPTO_KEY_USER		176
#define	LINAU_TYPE_CRYPTO_FAILURE_USER		177
#define	LINAU_TYPE_CRYPTO_REPLAY_USER		178
#define	LINAU_TYPE_CRYPTO_SESSION		179
#define	LINAU_TYPE_CRYPTO_IKE_SA		180
#define	LINAU_TYPE_CRYPTO_IPSEC_SA		181
#define	LINAU_TYPE_VIRT_CONTROL			182
#define	LINAU_TYPE_VIRT_RESOURCE		183
#define	LINAU_TYPE_VIRT_MACHINE_ID		184

#define LINAU_FIELD_NAME_UNDEFINED_STR		""
#define LINAU_FIELD_NAME_A0_STR			"a0"
#define LINAU_FIELD_NAME_A1_STR			"a1"
#define LINAU_FIELD_NAME_A2_STR			"a2"
#define LINAU_FIELD_NAME_A3_STR			"a3"
/* TODO: This one needs special attention. */
#define LINAU_FIELD_NAME_A_EXECVE_SYSCALL_STR	""
#define	LINAU_FIELD_NAME_ACCT_STR		"acct"
#define	LINAU_FIELD_NAME_ACL_STR		"acl"
#define	LINAU_FIELD_NAME_ACTION_STR		"action"
#define	LINAU_FIELD_NAME_ADDED_STR		"added"
#define	LINAU_FIELD_NAME_ADDR_STR		"addr"
#define	LINAU_FIELD_NAME_APPARMOR_STR		"apparmor"
#define	LINAU_FIELD_NAME_ARCH_STR		"arch"
#define	LINAU_FIELD_NAME_ARGC_STR		"argc"
#define	LINAU_FIELD_NAME_AUDIT_BACKLOG_LIMIT_STR	"audit_backlog_limit"
#define	LINAU_FIELD_NAME_AUDIT_BACKLOG_WAIT_TIME_STR	\
    "audit_backlog_wait_time"
#define	LINAU_FIELD_NAME_AUDIT_ENABLED_STR	"audit_enabled"
#define	LINAU_FIELD_NAME_AUDIT_FAILURE_STR	"audit_failure"
#define	LINAU_FIELD_NAME_AUID_STR		"auid"
#define	LINAU_FIELD_NAME_BANNERS_STR		"banners"
#define	LINAU_FIELD_NAME_BOOL_STR		"bool"
#define	LINAU_FIELD_NAME_BUS_STR		"bus"
#define	LINAU_FIELD_NAME_CAPABILITY_STR		"capability"
#define	LINAU_FIELD_NAME_CAP_FE_STR		"cap_fe"
#define	LINAU_FIELD_NAME_CAP_FI_STR		"cap_fi"
#define	LINAU_FIELD_NAME_CAP_FP_STR		"cap_fp"
#define	LINAU_FIELD_NAME_CAP_FVER_STR		"cap_fver"
#define	LINAU_FIELD_NAME_CAP_PE_STR		"cap_pe"
#define	LINAU_FIELD_NAME_CAP_PI_STR		"cap_pi"
#define	LINAU_FIELD_NAME_CAP_PP_STR		"cap_pp"
#define	LINAU_FIELD_NAME_CATEGORY_STR		"category"
#define	LINAU_FIELD_NAME_CGROUP_STR		"cgroup"
#define	LINAU_FIELD_NAME_CHANGED_STR		"changed"
#define	LINAU_FIELD_NAME_CIPHER_STR		"cipher"
#define	LINAU_FIELD_NAME_CLASS_STR		"class"
#define	LINAU_FIELD_NAME_CMD_STR		"cmd"
#define	LINAU_FIELD_NAME_CODE_STR		"code"
#define	LINAU_FIELD_NAME_COMM_STR		"comm"
#define	LINAU_FIELD_NAME_COMPAT_STR		"compat"
#define	LINAU_FIELD_NAME_CWD_STR		"cwd"
#define	LINAU_FIELD_NAME_DADDR_STR		"daddr"
#define	LINAU_FIELD_NAME_DATA_STR		"data"
#define	LINAU_FIELD_NAME_DEFAULT_STR		"default-context"
#define	LINAU_FIELD_NAME_DEV_STR		"dev"
/* #define	LINAU_FIELD_NAME_DEV2_STR		"dev" */
#define	LINAU_FIELD_NAME_DEVICE_STR		"device"
#define	LINAU_FIELD_NAME_DIR_STR		"dir"
#define	LINAU_FIELD_NAME_DIRECTION_STR		"direction"
#define	LINAU_FIELD_NAME_DMAC_STR		"dmac"
#define	LINAU_FIELD_NAME_DPORT_STR		"dport"
#define	LINAU_FIELD_NAME_EGID_STR		"egid"
#define	LINAU_FIELD_NAME_ENFORCING_STR		"enforcing"
#define	LINAU_FIELD_NAME_ENTRIES_STR		"entries"
#define	LINAU_FIELD_NAME_EUID_STR		"euid"
#define	LINAU_FIELD_NAME_EXE_STR		"exe"
#define	LINAU_FIELD_NAME_EXIT_STR		"exit"
#define	LINAU_FIELD_NAME_FAM_STR		"fam"
#define	LINAU_FIELD_NAME_FAMILY_STR		"family"
#define	LINAU_FIELD_NAME_FD_STR			"fd"
#define	LINAU_FIELD_NAME_FILE_STR		"file"
#define	LINAU_FIELD_NAME_FLAGS_STR		"flags"
#define	LINAU_FIELD_NAME_FE_STR			"fe"
#define	LINAU_FIELD_NAME_FEATURE_STR		"feature"
#define	LINAU_FIELD_NAME_FI_STR			"fi"
#define	LINAU_FIELD_NAME_FP_STR			"fp"
/* #define	LINAU_FIELD_NAME_FP2_STR			"fp" */
#define	LINAU_FIELD_NAME_FORMAT_STR		"format"
#define	LINAU_FIELD_NAME_FSGID_STR		"fsgid"
#define	LINAU_FIELD_NAME_FSUID_STR		"fsuid"
#define	LINAU_FIELD_NAME_FVER_STR		"fver"
#define	LINAU_FIELD_NAME_GID_STR		"gid"
#define	LINAU_FIELD_NAME_GRANTORS_STR		"grantors"
#define	LINAU_FIELD_NAME_GRP_STR		"grp"
#define	LINAU_FIELD_NAME_HOOK_STR		"hook"
#define	LINAU_FIELD_NAME_HOSTNAME_STR		"hostname"
#define	LINAU_FIELD_NAME_ICMP_TYPE_STR		"icmp_type"
#define	LINAU_FIELD_NAME_ID_STR			"id"
#define	LINAU_FIELD_NAME_IGID_STR		"igid"
#define	LINAU_FIELD_NAME_IMG_STR		"img-ctx"
#define	LINAU_FIELD_NAME_INIF_STR		"inif"
#define	LINAU_FIELD_NAME_IP_STR			"ip"
#define	LINAU_FIELD_NAME_IPID_STR		"ipid"
#define	LINAU_FIELD_NAME_INO_STR		"ino"
#define	LINAU_FIELD_NAME_INODE_STR		"inode"
#define	LINAU_FIELD_NAME_INODE_GID_STR		"inode_gid"
#define	LINAU_FIELD_NAME_INODE_UID_STR		"inode_uid"
#define	LINAU_FIELD_NAME_INVALID_CONTEXT_STR	"invalid_context"
#define	LINAU_FIELD_NAME_IOCTLCMD_STR		"ioctlcmd"
#define	LINAU_FIELD_NAME_IPX_STR		"ipx-net"
#define	LINAU_FIELD_NAME_ITEM_STR		"item"
#define	LINAU_FIELD_NAME_ITEMS_STR		"items"
#define	LINAU_FIELD_NAME_IUID_STR		"iuid"
#define	LINAU_FIELD_NAME_KERNEL_STR		"kernel"
#define	LINAU_FIELD_NAME_KEY_STR		"key"
#define	LINAU_FIELD_NAME_KIND_STR		"kind"
#define	LINAU_FIELD_NAME_KSIZE_STR		"ksize"
#define	LINAU_FIELD_NAME_LADDR_STR		"laddr"
#define	LINAU_FIELD_NAME_LEN_STR		"len"
#define	LINAU_FIELD_NAME_LPORT_STR		"lport"
#define	LINAU_FIELD_NAME_LIST_STR		"list"
#define	LINAU_FIELD_NAME_MAC_STR		"mac"
#define	LINAU_FIELD_NAME_MACPROTO_STR		"macproto"
#define	LINAU_FIELD_NAME_MAJ_STR		"maj"
#define	LINAU_FIELD_NAME_MAJOR_STR		"major"
#define	LINAU_FIELD_NAME_MINOR_STR		"minor"
#define	LINAU_FIELD_NAME_MODE_STR		"mode"
#define	LINAU_FIELD_NAME_MODEL_STR		"model"
#define	LINAU_FIELD_NAME_MSG_STR		"msg"
#define	LINAU_FIELD_NAME_NARGS_STR		"nargs"
#define	LINAU_FIELD_NAME_NAME_STR		"name"
#define	LINAU_FIELD_NAME_NAMETYPE_STR		"nametype"
#define	LINAU_FIELD_NAME_NET_STR		"net"
#define	LINAU_FIELD_NAME_NEW_STR		"new"
#define	LINAU_FIELD_NAME_NEW_CHARDEV_STR	"new-chardev"
#define	LINAU_FIELD_NAME_NEW_DISK_STR		"new-disk"
#define	LINAU_FIELD_NAME_NEW_ENABLED_STR	"new-enabled"
#define	LINAU_FIELD_NAME_NEW_FS_STR		"new-fs"
#define	LINAU_FIELD_NAME_NEW_GID_STR		"new_gid"
#define	LINAU_FIELD_NAME_NEW_LEVEL_STR		"new-level"
#define	LINAU_FIELD_NAME_NEW_LOCK_STR		"new_lock"
#define	LINAU_FIELD_NAME_NEW_LOG_PASSWD_STR	"new-log_passwd"
#define	LINAU_FIELD_NAME_NEW_MEM_STR		"new-mem"
#define	LINAU_FIELD_NAME_NEW_NET_STR		"new-net"
#define	LINAU_FIELD_NAME_NEW_PE_STR		"new_pe"
#define	LINAU_FIELD_NAME_NEW_PI_STR		"new_pi"
#define	LINAU_FIELD_NAME_NEW_PP_STR		"new_pp"
#define	LINAU_FIELD_NAME_NEW_RANGE_STR		"new-range"
#define	LINAU_FIELD_NAME_NEW_RNG_STR		"new-rng"
#define	LINAU_FIELD_NAME_NEW_ROLE_STR		"new-role"
#define	LINAU_FIELD_NAME_NEW_SEUSER_STR		"new-seuser"
#define	LINAU_FIELD_NAME_NEW_VCPU_STR		"new-vcpu"
#define	LINAU_FIELD_NAME_NLNK_FAM_STR		"nlnk-fam"
#define	LINAU_FIELD_NAME_NLNK_GRP_STR		"nlnk-grp"
#define	LINAU_FIELD_NAME_NLNK_PID_STR		"nlnk-pid"
#define	LINAU_FIELD_NAME_OAUID_STR		"oauid"
#define	LINAU_FIELD_NAME_OBJ_STR		"obj"
#define	LINAU_FIELD_NAME_OBJ_GID_STR		"obj_gid"
#define	LINAU_FIELD_NAME_OBJ_UID_STR		"obj_uid"
#define	LINAU_FIELD_NAME_OFLAG_STR		"oflag"
#define	LINAU_FIELD_NAME_OGID_STR		"ogid"
#define	LINAU_FIELD_NAME_OCOMM_STR		"ocomm"
#define	LINAU_FIELD_NAME_OLD_STR		"old"
/* #define	LINAU_FIELD_NAME_OLD2_STR		"old" */
#define	LINAU_FIELD_NAME_OLD_AUID_STR		"old-auid"
#define	LINAU_FIELD_NAME_OLD_CHARDEV_STR	"old-chardev"
#define	LINAU_FIELD_NAME_OLD_DISK_STR		"old-disk"
#define	LINAU_FIELD_NAME_OLD_ENABLED_STR	"old-enabled"
#define	LINAU_FIELD_NAME_OLD_ENFORCING_STR	"old_enforcing"
#define	LINAU_FIELD_NAME_OLD_FS_STR		"old-fs"
#define	LINAU_FIELD_NAME_OLD_LEVEL_STR		"old-level"
#define	LINAU_FIELD_NAME_OLD_LOCK_STR		"old_lock"
#define	LINAU_FIELD_NAME_OLD_LOG_PASSWD_STR	"old-log_passwd"
#define	LINAU_FIELD_NAME_OLD_MEM_STR		"old-mem"
#define	LINAU_FIELD_NAME_OLD_NET_STR		"old-net"
#define	LINAU_FIELD_NAME_OLD_PE_STR		"old_pe"
#define	LINAU_FIELD_NAME_OLD_PI_STR		"old_pi"
#define	LINAU_FIELD_NAME_OLD_PP_STR		"old_pp"
#define	LINAU_FIELD_NAME_OLD_PROM_STR		"old_prom"
#define	LINAU_FIELD_NAME_OLD_RANGE_STR		"old-range"
#define	LINAU_FIELD_NAME_OLD_RNG_STR		"old-rng"
#define	LINAU_FIELD_NAME_OLD_ROLE_STR		"old-role"
#define	LINAU_FIELD_NAME_OLD_SES_STR		"old-ses"
#define	LINAU_FIELD_NAME_OLD_SEUSER_STR		"old-seuser"
#define	LINAU_FIELD_NAME_OLD_VAL_STR		"old_val"
#define	LINAU_FIELD_NAME_OLD_VCPU_STR		"old-vcpu"
#define	LINAU_FIELD_NAME_OP_STR			"op"
#define	LINAU_FIELD_NAME_OPID_STR		"opid"
#define	LINAU_FIELD_NAME_OSES_STR		"oses"
#define	LINAU_FIELD_NAME_OUID_STR		"ouid"
#define	LINAU_FIELD_NAME_OUTIF_STR		"outif"
#define	LINAU_FIELD_NAME_PARENT_STR		"parent"
#define	LINAU_FIELD_NAME_PATH_STR		"path"
#define	LINAU_FIELD_NAME_PER_STR		"per"
#define	LINAU_FIELD_NAME_PERM_STR		"perm"
#define	LINAU_FIELD_NAME_PERM_MASK_STR		"perm_mask"
#define	LINAU_FIELD_NAME_PERMISSIVE_STR		"permissive"
#define	LINAU_FIELD_NAME_PFS_STR		"pfs"
#define	LINAU_FIELD_NAME_PID_STR		"pid"
#define	LINAU_FIELD_NAME_PPID_STR		"ppid"
#define	LINAU_FIELD_NAME_PRINTER_STR		"printer"
#define	LINAU_FIELD_NAME_PROM_STR		"prom"
#define	LINAU_FIELD_NAME_PROCTITLE_STR		"proctitle"
#define	LINAU_FIELD_NAME_PROTO_STR		"proto"
#define	LINAU_FIELD_NAME_QBYTES_STR		"qbytes"
#define	LINAU_FIELD_NAME_RANGE_STR		"range"
#define	LINAU_FIELD_NAME_RDEV_STR		"rdev"
#define	LINAU_FIELD_NAME_REASON_STR		"reason"
#define	LINAU_FIELD_NAME_REMOVED_STR		"removed"
#define	LINAU_FIELD_NAME_RES_STR		"res"
#define	LINAU_FIELD_NAME_RESRC_STR		"resrc"
#define	LINAU_FIELD_NAME_RESULT_STR		"result"
#define	LINAU_FIELD_NAME_ROLE_STR		"role"
#define	LINAU_FIELD_NAME_RPORT_STR		"rport"
#define	LINAU_FIELD_NAME_SADDR_STR		"saddr"
#define	LINAU_FIELD_NAME_SAUID_STR		"sauid"
#define	LINAU_FIELD_NAME_SCONTEXT_STR		"scontext"
#define	LINAU_FIELD_NAME_SELECTED_STR		"selected-context"
#define	LINAU_FIELD_NAME_SEPERM_STR		"seperm"
#define	LINAU_FIELD_NAME_SEQNO_STR		"seqno"
#define	LINAU_FIELD_NAME_SEPERMS_STR		"seperms"
#define	LINAU_FIELD_NAME_SERESULT_STR		"seresult"
#define	LINAU_FIELD_NAME_SES_STR		"ses"
#define	LINAU_FIELD_NAME_SEUSER_STR		"seuser"
#define	LINAU_FIELD_NAME_SGID_STR		"sgid"
#define	LINAU_FIELD_NAME_SIG_STR		"sig"
#define	LINAU_FIELD_NAME_SIGEV_SIGNO_STR	"sigev_signo"
#define	LINAU_FIELD_NAME_SMAC_STR		"smac"
#define	LINAU_FIELD_NAME_SPID_STR		"spid"
#define	LINAU_FIELD_NAME_SPORT_STR		"sport"
#define	LINAU_FIELD_NAME_STATE_STR		"state"
#define	LINAU_FIELD_NAME_SUBJ_STR		"subj"
#define	LINAU_FIELD_NAME_SUCCESS_STR		"success"
#define	LINAU_FIELD_NAME_SUID_STR		"suid"
#define	LINAU_FIELD_NAME_SYSCALL_STR		"syscall"
#define	LINAU_FIELD_NAME_TABLE_STR		"table"
#define	LINAU_FIELD_NAME_TCLASS_STR		"tclass"
#define	LINAU_FIELD_NAME_TCONTEXT_STR		"tcontext"
#define	LINAU_FIELD_NAME_TERMINAL_STR		"terminal"
#define	LINAU_FIELD_NAME_TTY_STR		"tty"
#define	LINAU_FIELD_NAME_TYPE_STR		"type"
#define	LINAU_FIELD_NAME_UID_STR		"uid"
#define	LINAU_FIELD_NAME_UNIT_STR		"unit"
#define	LINAU_FIELD_NAME_URI_STR		"uri"
#define	LINAU_FIELD_NAME_USER_STR		"user"
#define	LINAU_FIELD_NAME_UUID_STR		"uuid"
#define	LINAU_FIELD_NAME_VAL_STR		"val"
#define	LINAU_FIELD_NAME_VER_STR		"ver"
#define	LINAU_FIELD_NAME_VIRT_STR		"virt"
#define	LINAU_FIELD_NAME_VM_STR			"vm"
#define	LINAU_FIELD_NAME_VM_CTX_STR		"vm-ctx"
#define	LINAU_FIELD_NAME_VM_PID_STR		"vm-pid"
#define	LINAU_FIELD_NAME_WATCH_STR		"watch"

#define	LINAU_FIELD_NAME_UNDEFINED			0
#define LINAU_FIELD_NAME_A0				1
#define LINAU_FIELD_NAME_A1				2
#define LINAU_FIELD_NAME_A2				3
#define LINAU_FIELD_NAME_A3				4
/* TODO: This one needs special attention. */
#define LINAU_FIELD_NAME_A_EXECVE_SYSCALL		5
#define	LINAU_FIELD_NAME_ACCT				6
#define	LINAU_FIELD_NAME_ACL				7
#define	LINAU_FIELD_NAME_ACTION				8
#define	LINAU_FIELD_NAME_ADDED				9
#define	LINAU_FIELD_NAME_ADDR				10
#define	LINAU_FIELD_NAME_APPARMOR			11
#define	LINAU_FIELD_NAME_ARCH				12
#define	LINAU_FIELD_NAME_ARGC				13
#define	LINAU_FIELD_NAME_AUDIT_BACKLOG_LIMIT		14
#define	LINAU_FIELD_NAME_AUDIT_BACKLOG_WAIT_TIME	15
#define	LINAU_FIELD_NAME_AUDIT_ENABLED			16
#define	LINAU_FIELD_NAME_AUDIT_FAILURE			17
#define	LINAU_FIELD_NAME_AUID				18
#define	LINAU_FIELD_NAME_BANNERS			19
#define	LINAU_FIELD_NAME_BOOL				20
#define	LINAU_FIELD_NAME_BUS				21
#define	LINAU_FIELD_NAME_CAPABILITY			22
#define	LINAU_FIELD_NAME_CAP_FE				23
#define	LINAU_FIELD_NAME_CAP_FI				24
#define	LINAU_FIELD_NAME_CAP_FP				25
#define	LINAU_FIELD_NAME_CAP_FVER			26
#define	LINAU_FIELD_NAME_CAP_PE				27
#define	LINAU_FIELD_NAME_CAP_PI				28
#define	LINAU_FIELD_NAME_CAP_PP				29
#define	LINAU_FIELD_NAME_CATEGORY			30
#define	LINAU_FIELD_NAME_CGROUP				31
#define	LINAU_FIELD_NAME_CHANGED			32
#define	LINAU_FIELD_NAME_CIPHER				33
#define	LINAU_FIELD_NAME_CLASS				34
#define	LINAU_FIELD_NAME_CMD				35
#define	LINAU_FIELD_NAME_CODE				36
#define	LINAU_FIELD_NAME_COMM				37
#define	LINAU_FIELD_NAME_COMPAT				38
#define	LINAU_FIELD_NAME_CWD				39
#define	LINAU_FIELD_NAME_DADDR				40
#define	LINAU_FIELD_NAME_DATA				41
#define	LINAU_FIELD_NAME_DEFAULT			42
#define	LINAU_FIELD_NAME_DEV				43
/* #define	LINAU_FIELD_NAME_DEV2				44 */
#define	LINAU_FIELD_NAME_DEVICE				45
#define	LINAU_FIELD_NAME_DIR				46
#define	LINAU_FIELD_NAME_DIRECTION			47
#define	LINAU_FIELD_NAME_DMAC				48
#define	LINAU_FIELD_NAME_DPORT				49
#define	LINAU_FIELD_NAME_EGID				50
#define	LINAU_FIELD_NAME_ENFORCING			51
#define	LINAU_FIELD_NAME_ENTRIES			52
#define	LINAU_FIELD_NAME_EUID				53
#define	LINAU_FIELD_NAME_EXE				54
#define	LINAU_FIELD_NAME_EXIT				55
#define	LINAU_FIELD_NAME_FAM				56
#define	LINAU_FIELD_NAME_FAMILY				57
#define	LINAU_FIELD_NAME_FD				58
#define	LINAU_FIELD_NAME_FILE				59
#define	LINAU_FIELD_NAME_FLAGS				60
#define	LINAU_FIELD_NAME_FE				61
#define	LINAU_FIELD_NAME_FEATURE			62
#define	LINAU_FIELD_NAME_FI				63
#define	LINAU_FIELD_NAME_FP				64
/* #define	LINAU_FIELD_NAME_FP2				65 */
#define	LINAU_FIELD_NAME_FORMAT				66
#define	LINAU_FIELD_NAME_FSGID				67
#define	LINAU_FIELD_NAME_FSUID				68
#define	LINAU_FIELD_NAME_FVER				69
#define	LINAU_FIELD_NAME_GID				70
#define	LINAU_FIELD_NAME_GRANTORS			71
#define	LINAU_FIELD_NAME_GRP				72
#define	LINAU_FIELD_NAME_HOOK				73
#define	LINAU_FIELD_NAME_HOSTNAME			74
#define	LINAU_FIELD_NAME_ICMP_TYPE			75
#define	LINAU_FIELD_NAME_ID				76
#define	LINAU_FIELD_NAME_IGID				77
#define	LINAU_FIELD_NAME_IMG				78
#define	LINAU_FIELD_NAME_INIF				79
#define	LINAU_FIELD_NAME_IP				80
#define	LINAU_FIELD_NAME_IPID				81
#define	LINAU_FIELD_NAME_INO				82
#define	LINAU_FIELD_NAME_INODE				83
#define	LINAU_FIELD_NAME_INODE_GID			84
#define	LINAU_FIELD_NAME_INODE_UID			85
#define	LINAU_FIELD_NAME_INVALID_CONTEXT		86
#define	LINAU_FIELD_NAME_IOCTLCMD			87
#define	LINAU_FIELD_NAME_IPX				88
#define	LINAU_FIELD_NAME_ITEM				89
#define	LINAU_FIELD_NAME_ITEMS				90
#define	LINAU_FIELD_NAME_IUID				91
#define	LINAU_FIELD_NAME_KERNEL				92
#define	LINAU_FIELD_NAME_KEY				93
#define	LINAU_FIELD_NAME_KIND				94
#define	LINAU_FIELD_NAME_KSIZE				95
#define	LINAU_FIELD_NAME_LADDR				96
#define	LINAU_FIELD_NAME_LEN				97
#define	LINAU_FIELD_NAME_LPORT				98
#define	LINAU_FIELD_NAME_LIST				99
#define	LINAU_FIELD_NAME_MAC				100
#define	LINAU_FIELD_NAME_MACPROTO			101
#define	LINAU_FIELD_NAME_MAJ				102
#define	LINAU_FIELD_NAME_MAJOR				103
#define	LINAU_FIELD_NAME_MINOR				104
#define	LINAU_FIELD_NAME_MODE				105
#define	LINAU_FIELD_NAME_MODEL				106
#define	LINAU_FIELD_NAME_MSG				107
#define	LINAU_FIELD_NAME_NARGS				108
#define	LINAU_FIELD_NAME_NAME				109
#define	LINAU_FIELD_NAME_NAMETYPE			110
#define	LINAU_FIELD_NAME_NET				111
#define	LINAU_FIELD_NAME_NEW				112
#define	LINAU_FIELD_NAME_NEW_CHARDEV			113
#define	LINAU_FIELD_NAME_NEW_DISK			114
#define	LINAU_FIELD_NAME_NEW_ENABLED			115
#define	LINAU_FIELD_NAME_NEW_FS				116
#define	LINAU_FIELD_NAME_NEW_GID			117
#define	LINAU_FIELD_NAME_NEW_LEVEL			118
#define	LINAU_FIELD_NAME_NEW_LOCK			119
#define	LINAU_FIELD_NAME_NEW_LOG_PASSWD			120
#define	LINAU_FIELD_NAME_NEW_MEM			121
#define	LINAU_FIELD_NAME_NEW_NET			122
#define	LINAU_FIELD_NAME_NEW_PE				123
#define	LINAU_FIELD_NAME_NEW_PI				124
#define	LINAU_FIELD_NAME_NEW_PP				125
#define	LINAU_FIELD_NAME_NEW_RANGE			126
#define	LINAU_FIELD_NAME_NEW_RNG			127
#define	LINAU_FIELD_NAME_NEW_ROLE			128
#define	LINAU_FIELD_NAME_NEW_SEUSER			129
#define	LINAU_FIELD_NAME_NEW_VCPU			130
#define	LINAU_FIELD_NAME_NLNK_FAM			131
#define	LINAU_FIELD_NAME_NLNK_GRP			132
#define	LINAU_FIELD_NAME_NLNK_PID			133
#define	LINAU_FIELD_NAME_OAUID				134
#define	LINAU_FIELD_NAME_OBJ				135
#define	LINAU_FIELD_NAME_OBJ_GID			136
#define	LINAU_FIELD_NAME_OBJ_UID			137
#define	LINAU_FIELD_NAME_OFLAG				138
#define	LINAU_FIELD_NAME_OGID				139
#define	LINAU_FIELD_NAME_OCOMM				140
#define	LINAU_FIELD_NAME_OLD				141
/* #define	LINAU_FIELD_NAME_OLD2				142 */
#define	LINAU_FIELD_NAME_OLD_AUID			143
#define	LINAU_FIELD_NAME_OLD_CHARDEV			144
#define	LINAU_FIELD_NAME_OLD_DISK			145
#define	LINAU_FIELD_NAME_OLD_ENABLED			146
#define	LINAU_FIELD_NAME_OLD_ENFORCING			147
#define	LINAU_FIELD_NAME_OLD_FS				148
#define	LINAU_FIELD_NAME_OLD_LEVEL			149
#define	LINAU_FIELD_NAME_OLD_LOCK			150
#define	LINAU_FIELD_NAME_OLD_LOG_PASSWD			151
#define	LINAU_FIELD_NAME_OLD_MEM			152
#define	LINAU_FIELD_NAME_OLD_NET			153
#define	LINAU_FIELD_NAME_OLD_PE				154
#define	LINAU_FIELD_NAME_OLD_PI				155
#define	LINAU_FIELD_NAME_OLD_PP				156
#define	LINAU_FIELD_NAME_OLD_PROM			157
#define	LINAU_FIELD_NAME_OLD_RANGE			158
#define	LINAU_FIELD_NAME_OLD_RNG			159
#define	LINAU_FIELD_NAME_OLD_ROLE			160
#define	LINAU_FIELD_NAME_OLD_SES			161
#define	LINAU_FIELD_NAME_OLD_SEUSER			162
#define	LINAU_FIELD_NAME_OLD_VAL			163
#define	LINAU_FIELD_NAME_OLD_VCPU			164
#define	LINAU_FIELD_NAME_OP				165
#define	LINAU_FIELD_NAME_OPID				166
#define	LINAU_FIELD_NAME_OSES				167
#define	LINAU_FIELD_NAME_OUID				168
#define	LINAU_FIELD_NAME_OUTIF				169
#define	LINAU_FIELD_NAME_PARENT				170
#define	LINAU_FIELD_NAME_PATH				171
#define	LINAU_FIELD_NAME_PER				172
#define	LINAU_FIELD_NAME_PERM				173
#define	LINAU_FIELD_NAME_PERM_MASK			174
#define	LINAU_FIELD_NAME_PERMISSIVE			175
#define	LINAU_FIELD_NAME_PFS				176
#define	LINAU_FIELD_NAME_PID				177
#define	LINAU_FIELD_NAME_PPID				178
#define	LINAU_FIELD_NAME_PRINTER			179
#define	LINAU_FIELD_NAME_PROM				180
#define	LINAU_FIELD_NAME_PROCTITLE			181
#define	LINAU_FIELD_NAME_PROTO				182
#define	LINAU_FIELD_NAME_QBYTES				183
#define	LINAU_FIELD_NAME_RANGE				184
#define	LINAU_FIELD_NAME_RDEV				185
#define	LINAU_FIELD_NAME_REASON				186
#define	LINAU_FIELD_NAME_REMOVED			187
#define	LINAU_FIELD_NAME_RES				188
#define	LINAU_FIELD_NAME_RESRC				189
#define	LINAU_FIELD_NAME_RESULT				190
#define	LINAU_FIELD_NAME_ROLE				191
#define	LINAU_FIELD_NAME_RPORT				192
#define	LINAU_FIELD_NAME_SADDR				193
#define	LINAU_FIELD_NAME_SAUID				194
#define	LINAU_FIELD_NAME_SCONTEXT			195
#define	LINAU_FIELD_NAME_SELECTED			196
#define	LINAU_FIELD_NAME_SEPERM				197
#define	LINAU_FIELD_NAME_SEQNO				198
#define	LINAU_FIELD_NAME_SEPERMS			199
#define	LINAU_FIELD_NAME_SERESULT			200
#define	LINAU_FIELD_NAME_SES				201
#define	LINAU_FIELD_NAME_SEUSER				202
#define	LINAU_FIELD_NAME_SGID				203
#define	LINAU_FIELD_NAME_SIG				204
#define	LINAU_FIELD_NAME_SIGEV_SIGNO			205
#define	LINAU_FIELD_NAME_SMAC				206
#define	LINAU_FIELD_NAME_SPID				207
#define	LINAU_FIELD_NAME_SPORT				208
#define	LINAU_FIELD_NAME_STATE				209
#define	LINAU_FIELD_NAME_SUBJ				210
#define	LINAU_FIELD_NAME_SUCCESS			211
#define	LINAU_FIELD_NAME_SUID				212
#define	LINAU_FIELD_NAME_SYSCALL			213
#define	LINAU_FIELD_NAME_TABLE				214
#define	LINAU_FIELD_NAME_TCLASS				215
#define	LINAU_FIELD_NAME_TCONTEXT			216
#define	LINAU_FIELD_NAME_TERMINAL			217
#define	LINAU_FIELD_NAME_TTY				218
#define	LINAU_FIELD_NAME_TYPE				219
#define	LINAU_FIELD_NAME_UID				220
#define	LINAU_FIELD_NAME_UNIT				221
#define	LINAU_FIELD_NAME_URI				222
#define	LINAU_FIELD_NAME_USER				223
#define	LINAU_FIELD_NAME_UUID				224
#define	LINAU_FIELD_NAME_VAL				225
#define	LINAU_FIELD_NAME_VER				226
#define	LINAU_FIELD_NAME_VIRT				227
#define	LINAU_FIELD_NAME_VM				228
#define	LINAU_FIELD_NAME_VM_CTX				229
#define	LINAU_FIELD_NAME_VM_PID				230
#define	LINAU_FIELD_NAME_WATCH				231

#endif
