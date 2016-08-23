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
