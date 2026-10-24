# Audit Checklist

| ID | مشکل | شدت | وضعیت | اصلاح انجام‌شده | تست قبل | تست بعد | شواهد |
|---|---|---|---|---|---|---|---|
| H-01 | یونیت‌های یتیم hashem-monitor/webui در crash-loop | High | Open | - | NRestarts=29005/46770 | - | AUDIT_REPORT.md H-01 |
| M-01 | آپدیت بدون checksum اجباری (fail-open) | Medium | Open | - | - | - | update.go L120 |
| M-02 | WSS CheckOrigin=true | Medium (Unverified) | Open | - | - | - | wss_carrier.go L360 |
| M-03 | هش رمز SHA-256 بدون salt + کوکی legacy ثابت | Medium | Open | - | - | - | auth.go/main.go |
| L-01 | journald 4GB بدون سقف | Low | Open | - | - | - | journalctl --disk-usage |
| L-02 | پوشش تست 43% | Low | Open | - | - | - | go test -cover |
