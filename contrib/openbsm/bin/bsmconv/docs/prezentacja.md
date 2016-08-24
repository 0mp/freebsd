<!-- page_number: true -->

# Mechianizmy śledzenia zmian w systemach FreeBSD i Linux

## Mateusz Piotrowski <0mp@FreeBSD.org>

---

# 0. Plan prezentacji

1. Konfiguracja `auditd(8)`.
2. Krótko o `auditdistd(8)`.
3. Formatu BSM i biblioteka `libbsm(3)`.
4. Środowskio Linux Audit.
5. Narzędzia do konwersji Linux Audit do BSM.

---

# 1. Konfiguracja `auditd(8)`

Najważniejszym plikiem konfiguracyjnym jest `audit_control(5)`.

Przykładowa zawartość `/etc/security/audit_control`:

```sh
dir:/var/audit
dist:off
flags:all
minfree:5
naflags:all
policy:cnt,argv,arge,seq,
filesz:2M
expire-after:10M
```

- Powyższa konfiguracja pozwala monitorować i zapisuje wszystko, co tylko można wyciągnąć z FreeBSD.
- Najciekawszymi opcjami są `flags`, `naflags` oraz `policy`.

---

## 1.1. Czym są `flags`, `naflags` oraz `policy`?


|Parametr|Znaczenie|man|
|:-:|-|:-:|
|`flags`|Deskrytory klasy monitorowanych zdarzeń.|`audit_class(5)`|
|`naflags`|Deskrytory klasy monitorowanych zdarzeń, gdy nie znamy użytkownika.|`audit_class(5)`|
|`policy`|Szczegóły śledzenia zdarzeń. |`audit_control(5)`|

---

## 1.2. `flags` / `naflags`

Definicje `flags` oraz `naflags` znajdują się w `/etc/security/audit_class` (`audit_class(5)`).

Pełne ścieżkie do plików omawianych na kolejnych slajdach:

- `/etc/security/audit_class`
- `/etc/security/audit_event`
- `/usr/include/bsm/audit_kevents.h`
- `/usr/include/bsm/audit_uevents.h`

---

### 1.2.1. Standardowe klasy (`audit_class`)

```rust
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

---

### 1.2.2. Klasy są używane przez `audit_event`

```rust
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

---

### 1.2.3. Biblioteki z identyfikatorami zdarzeń, z których możemy korzystać, to w `audit_kevents.h` oraz `audit_uevents.h`

```rust
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
```

---

### 1.2.4. Jak to wszystko się łączy?

- `/etc/security/audit_control`:

    ```rust
    flags:pc
    ```

- `/etc/security/audit_class`:

    ```rust
    0x00000080:pc:process
    ```

- `/etc/security/audit_event`:
  
    ```rust
    2:AUE_FORK:fork(2):pc
    ```
    
- `/usr/include/bsm/audit_kevents.h`:

    ```rust
    #define	AUE_FORK		2
    ```

---

## 1.3. `policy`

FreeBSD oferuje następujące opcje:

|Opcja|Znaczenie|
|:-:|-|
|cnt|Nie zatrzymuj systemu, jeżeli nie możesz go monitorować.|
|ahlt|Zatrzymaj system, jeżeli nie możesz monitorować zdarzeń.|
|argv|Monitoruj argumenty przekazywane do `execve(2)`.|
|arge|Monitoruj zmienne środowiskowe przekazywane do `execve(2)`.|

Standard OpenBSM definiuje dużo więcej opcji, ale nie są one jeszcze zaimplementowane we FreeBSD.

---

## 1.4. Włączanie `auditd(8)`

1. Dodajemy do `auditd_enable="YES"` do `/etc/rc.conf`.
2. Włączmy demon przy użyciu 

    ```sh
    service auditd start
    ```
3. Wygenerowane logi lądują domyślnie do `/var/audit/`.

---

## 1.5. Przeglądanie logów

Logi możemy przeglądać przy użyciu `praudit(1)` - wyświetla on przystępną reprezentację binarnego formatu BSM. 

Przykłady uzycia:
- Wyświetlenie pliku z logami:

    ```sh
    praudit /var/audit/20160813110801.20160813110999
    ```
- Śledzenie bieżących logów:

    ```sh
    # Gorszy sposób.
    tail -f /var/audit/current | praudit
    # Lepszy sposób.
    praudit /dev/auditpipe
    ```
---

## 1.6. Czy macie jakieś pytania odnośnie `auditd(8)`?

---

# 2. `auditdistd(8)`

Demon służący do bezpiecznej dystrybucji logów audytowych.

---

## 2.1. Konfiguracja `auditdistd(8)`

Zwięzłą listę kroków można znaleźć na [stronie Wiki FreeBSD poświęconej auditdistd (link)]( https://wiki.freebsd.org/auditdistd).

---

# 3. Struktura formatu BSM

```ini
header,56,11,audit startup,0,Tue Jun  2 04:03:22 1970,\
  + 0 msec
text,auditd::Audit startup
return,success,0
trailer,56
header,104,11,su(1),0,Sat Jun 27 15:02:34 1970, + 0 msec
subject,-1,root,wheel,0mp,wheel,1650,1650,0,0.0.0.0
text,bad su 0mp to root on /dev/pts/3
return,failure : Operation not permitted,1
trailer,104
header,97,11,su(1),0,Sat Jun 27 15:02:34 1970, + 0 msec
subject,-1,root,wheel,0mp,wheel,1651,1651,0,0.0.0.0
text,successful authentication
return,success,0
trailer,97
header,57,11,audit shutdown,0,Tue Jun  2 04:03:22 1970,\
  + 0 msec
text,auditd::Audit shutdown
return,success,0
trailer,57
```

---

## 3.1. Struktura formatu BSM: plik

- Opcjonalny _file token_;
- Rekordy.

Przykład (bez _file token_):
```ini
header,56,11,audit startup,0,Tue Jun  2 04:03:22 1970,\
  + 0 msec
(...)
trailer,56
header,104,11,su(1),0,Sat Jun 27 15:02:34 1970, + 0 msec
(...)
trailer,104
header,97,11,su(1),0,Sat Jun 27 15:02:34 1970, + 0 msec
(...)
trailer,97
header,57,11,audit shutdown,0,Tue Jun  2 04:03:22 1970,\
  + 0 msec
(...)
trailer,57
```

---

## 3.2. Struktura formatu BSM: rekord

- _Header token_;
- _Tokeny_ z informacjiami o zdarzeniu;
- _Trailer token_.

```ini
header,88,11,recvfrom(2),0,Wed Aug 24 02:45:19 2016,\
  + 778 msec
argument,1,0x5,fd
socket-unix,1,
path,/
subject,-1,root,wheel,root,wheel,427,0,0,0.0.0.0
return,success,51
trailer,88
```

---

## 3.3. Struktura formatu BSM: format binarny

Format BSM jest w zasadzie formatem binarnym (w przeciwieństwie do Linux Audit). Oto rekord z poprzedniego slajdu, ale tym razem w postaci binarnej:

```ini
20,88,11,191,0,1471999519,778
45,1,0x5,fd
130,1,
35,/
36,-1,0,0,0,0,427,0,0,0.0.0.0
39,0,51
19,88
```
---

## 3.4. Biblioteka `libbsm(3)`. Jak tworzyć _tokeny_?

W uproszczeniu tworzenie logów wygląda tak:

```c
char buf[MAX_RECORD_SIZE];
token_t *tok;
size_t buflen;
int aurd;

/* Pozyskaj deskryptor do nowego rekordu. */
aurd = au_open(); 
/* Stwórz 'text token'. */
tok = au_to_text("bad su"); 
/* Dodaj 'token' do rekordu. */
au_write(aurd, tok); 
/* Zamknij deskryptor i zakończ tworzenie rekordu. */
au_close_buffer(aurd, AUE_SOME_EVENT_ID, buf, buflen);
```

Bufor `buf` zawiera teraz cały jeden rekord o długości `buflen` bajtów.

---

## 3.5. Czy macie jakieś pytania odnośnie BSM?

---

# 4. Linux Audit

Linux Audit, to:

- Narzędzia dla użytkowników: https://github.com/linux-audit/audit-userspace;
- Część jądra Linux: https://github.com/linux-audit/audit-kernel

---

## 4.1. Struktura formatu Linux Audit

### 4.1.1. Plik

Plik zbudowany jest ze zdarzeń (_events_). 

```
type=DAEMON_START msg=audit(1470137689.319:9585):\
 op=start ver=2.6.6 format=raw\
 kernel=4.7.0-1.el7.elrepo.x86_64 auid=4294967295\
 pid=15404 subj=system_u:system_r:auditd_t:s0\
 res=success
type=CONFIG_CHANGE msg=audit(1470137689.342:161):\
  auid=4294967295 ses=4294967295\
  subj=system_u:system_r:unconfined_service_t:s0\
  op="add_rule" key="0mp_watch_files_in_home" list=4\
  res=1
type=SERVICE_START msg=audit(1470137689.348:165): pid=1\
  uid=0 auid=4294967295 ses=4294967295\
  subj=system_u:system_r:init_t:s0 msg='unit=auditd\
  comm="systemd" exe="/usr/lib/systemd/systemd"\
  hostname=? addr=? terminal=? res=success'
```
---

### 4.1.2. Zdarzenie (_event_)

Zdarzenie jest zbudowane z jednego lub kilku rekordów, które mają taki sam znacznik czasu (_timestamp_) i identyfikator zdarzenia, np. odpowiednio: `1470137689.354` i `166`.
```
type=SYSCALL msg=audit(1470137689.354:166):\
  arch=c000003e syscall=2 success=yes exit=0\
  a0=7f8876596ab2 a1=80000 a2=1 a3=7f887679d5b0 items=1\
  ppid=2 pid=15426 auid=4294967295 uid=0 gid=0 euid=0\
  suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none)\
  ses=4294967295 comm="systemd-cgroups"\
  exe="/usr/lib/systemd/systemd-cgroups-agent"\
  subj=system_u:system_r:init_t:s0\
  key="0mp_watch_files_in_etc"
type=CWD msg=audit(1470137689.354:166):  cwd="/"
type=PATH msg=audit(1470137689.354:166):\
  item=0 name="/etc/ld.so.cache" inode=18047765\
  dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00\
  obj=unconfined_u:object_r:ld_so_cache_t:s0\
  nametype=NORMAL
type=PROCTITLE msg=audit(1470137689.354:166):\
  proctitle=2F7573722F6C69622F73797374656D...
```

---

### 4.1.3. Rekord

Rekord zbudowany jest z pola (_field_) `type`, `msg` oraz pewnej liczby charakterystycznych pól dla danego typu rekordu wypisanych po dwukropku.
```ini
type=SYSCALL msg=audit(1470137689.354:166):\
  arch=c000003e syscall=2 success=yes exit=0\
  a0=7f8876596ab2 a1=80000 a2=1 a3=7f887679d5b0 items=1\
  ppid=2 pid=15426 auid=4294967295 uid=0 gid=0 euid=0\
  suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none)\
  ses=4294967295 comm="systemd-cgroups"\
  exe="/usr/lib/systemd/systemd-cgroups-agent"\
  subj=system_u:system_r:init_t:s0\
  key="0mp_watch_files_in_etc"
```

---

### 4.1.4. Pole

- Pola powinny być zdefiniowane w [słowniku pól](https://github.com/linux-audit/audit-documentation/blob/master/specs/fields/field-dictionary.csv), ale w praktyce bywa różnie (standard Linux Audit wyznaczany jest przez zaimplementowane narzędzia i biblioteki, a nie na dokumentację).

- Pola mają format:

    ```
    nazwa_pola=wartość
    ```
- Zdarzają się anomalie w rodzaju:

    ```python
    type=FOOBAR msg=audit(1470137689.354:1): user res=1
    ```
    
    Które nie są opisane w żadnym dokumencie.
    
---

## 4.2. Narzędzia Linux Audit

Omawiane na przykładzie systemu CentOS 7.

### 4.2.1. `auditd(8)`

Zasady monitorowania systemu umieszczamy w plikach w `/etc/audit/rules.d`. Na przykład:

```ini
-w /home -p waxr -k 0mp_watch_home
```

zapisuje informacje o wszystkim, co dzieje się w folderach domowych.

### 4.2.2 `audispd(8)` oraz `audisp-remote(8)`

`audispd(8)` pozwala na powielanie i przekazywanie logów do różnych narzędzi w czasie rzeczywistym. Mogą to być zarówno nasze skrypty, jak i standardowe wtyczki (np.: `audisp-remote(8)`).

---

## 4.3. Czy macie jakieś pytania odnośnie Linux Audit?

---

# 5. Narzędzia do konwersji Linux Audit do BSM.

---

## 5.1. Biblioteka `linau.h`

Zastosowania:

- Parsowanie logów w formacie Linux Audit;
- Konwersja Linux Audit do BSM.

---

## 5.2. Jak działa konwersja?

### 5.2.1. Struktury

```c
struct linau_conv_field {
	int	lcf_id;
	union {
		int (*lcf_validate)(const char *);
		struct linau_string_queue *(*lcf_match)
		    (const struct linau_record *);
	};
};

struct linau_conv_token {
	void (*lct_write)(int aurd, 
	    const struct linau_record *);
	const struct linau_conv_field *lct_fields[];
};

struct linau_conv_record_type {
	int				 lcrt_id;
	const char			*lcrt_str;
	const struct linau_conv_token	*lcrt_tokens[];
};
```

---

### 5.2.2. Schemat konwersji

1. Odszukujemy odpowiednią dla konertowanego rekordu strukturę _lcrectype_.
2. Iterujemy po wszystkich _lctokenach_ i próbujemy wygenerować symbole BSM używając funkcji i informacji zawartych w _lctokenie_.
3. Wszystkie pola, które były niepoprawne lub nie dało się przypisać do żadnego symbolu zapisujemy do deskryptora jako _text token_.

Fragment funkcji `linau_conv_process_record`:
```c
for (ti = 0; lcrectype->lcrt_tokens[ti] != NULL; ti++)
	lcrectype->lcrt_tokens[ti]->lct_write(aurd, 
	    record);

linau_conv_write_unprocessed_fields(aurd, record, 
    lcrectype);
```

---

## 5.3. Główne wady i braki aktualnej wersji biblioteki

- Wartości pól nie jest są walidowane, tzn.: biblioteka nie jest przygotowana na pola typu `pid="foo"`;
- Brak mapowania pomiędzy typami rekordów Linux Audit, a wartościami w `audit_event`.
- Instnieją zdarzenia w Linux Audit, których rekord należałoby interpretować jako całość, a nie oddzielnie (np.: `type=SYSLOG`).

---

## 5.4. Narzędzie do konwersji logów (`bsmconv`)

```sh
./bsmconv < linux-audit.log
```

Na wyjściu otrzymamy przekonwertowane logi w formacie BSM.

Opcja `-v` służy zwiększania poziomu debugu. Użycie `-v` skutkuje tym, że logi nie zostaną wypisane w formacie BSM; zamiast tego zostanie wypisana zawartość wewnętrznej struktury `linau_event`.

---


## 5.5. Czy macie jakieś pytania odnośnie mojego projektu _Non-BSM to BSM Conversion Tools_?

---

# 6. Dziękuję za uwagę.