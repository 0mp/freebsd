<!-- page_number: true -->

# Mechianizmy śledzenia zmian w systemach FreeBSD i Linux

## Mateusz Piotrowski <0mp@FreeBSD.org>

---

# Konfiguracja `auditd(8)`

Najważniejszym plikiem konfiguracyjnym jest `audit_control(5)`.

Przykładowa zawartość `/etc/security/audit_control`:

```
dir:/var/audit
dist:off
flags:all
minfree:5
naflags:all
policy:cnt,argv,arge,seq,
filesz:2M
expire-after:10M
```

Najciekawszymi opcjami są `flags`, `naflags` oraz `policy`.

|Parametr|Znaczenie|
|:-:|:-:|
|`flags`|Deskrytory klasy monitorowanych zdarzeń.|
|`naflags`|Deskrytory klasy monitorowanych zdarzeń, gdy nie znamy użytkownika.|
|`policy`|Szczegóły śledzenia zdarzeń. |

Definicje `flags` oraz `naflags` znajdują się w `/etc/security/audit_user`
(`audit_user(5)`).

## `flags` / `naflags`

Domyślne klasy zdefiniowane w `/etc/security/audit_class`:

```
0x00000000:no:invalid class
0x00000001:fr:file read
0x00000002:fw:file write
0x00000004:fa:file attribute access
0x00000008:fm:file attribute modify
0x00000010:fc:file create
0x00000020:fd:file delete
0x00000040:cl:file close
0x00000080:pc:process
0x00000100:nt:network
0x00000200:ip:ipc
0x00000400:na:non attributable
0x00000800:ad:administrative
0x00001000:lo:login_logout
0x00002000:aa:authentication and authorization
0x00004000:ap:application
0x20000000:io:ioctl
0x40000000:ex:exec
0x80000000:ot:miscellaneous
0xffffffff:all:all flags set
```

Klasy są używane przez `/etc/security/audit_event` (fragment):

```
43001:AUE_GETFSSTAT:getfsstat(2):fa
43002:AUE_PTRACE:ptrace(2):pc
43003:AUE_CHFLAGS:chflags(2):fm
43004:AUE_FCHFLAGS:fchflags(2):fm
43005:AUE_PROFILE:profil(2):pc
43006:AUE_KTRACE:ktrace(2):pc
43007:AUE_SETLOGIN:setlogin(2):pc
43008:AUE_OPENBSM_REVOKE:revoke(2):cl
43009:AUE_UMASK:umask(2):pc
43010:AUE_MPROTECT:mprotect(2):fm
43011:AUE_MKFIFO:mkfifo(2):fc
43012:AUE_POLL:poll(2):no
43013:AUE_FUTIMES:futimes(2):fm
```

Mapowanie pomiędzy identyfikatorami zdarzeń a numerami zachodzi
w `/usr/include/bsm/audit_kevent.h` oraz `/usr/include/bsm/audit_uevent.h`:

```
#define	AUE_at_create		6144
#define	AUE_at_delete		6145
#define	AUE_at_perm		6146
#define	AUE_cron_invoke		6147
#define	AUE_crontab_create	6148
#define	AUE_crontab_delete	6149
#define	AUE_crontab_perm	6150
#define	AUE_inetd_connect	6151
#define	AUE_login		6152
#define	AUE_logout		6153
#define	AUE_telnet		6154
#define	AUE_rlogin		6155
#define	AUE_mountd_mount	6156
#define	AUE_mountd_umount	6157
#define	AUE_rshd		6158
#define	AUE_su			6159
#define	AUE_halt		6160
#define	AUE_reboot		6161
#define	AUE_rexecd		6162
#define	AUE_passwd		6163
#define	AUE_rexd		6164
#define	AUE_ftpd		6165
```

