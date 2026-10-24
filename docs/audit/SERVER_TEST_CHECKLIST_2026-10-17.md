# چک‌لیست تست روی سرور لینوکس — اصلاح‌های ۱۷ اکتبر ۲۰۲۶

این چک‌لیست اصلاح‌هایی را پوشش می‌دهد که روی ویندوز قابل تأیید نبودند. شناسه‌ها (C1، H4 و غیره) به [BUG_REPORT_2026-10-17.md](BUG_REPORT_2026-10-17.md) اشاره دارند.

## پیش‌نیاز

- دو سرور لینوکس: یکی **ایران** و یکی **خارج**. برای Peer Link و کلاستر، اگر ممکن است یک سرور ایران دوم هم داشته باشید.
- باینری از همین نسخه‌ی کد ساخته شود:
  ```bash
  cd panel && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o gre-panel-linux-amd64 .
  ```
- `hashem.sh` همین نسخه روی هر دو سرور کپی شود (`/usr/local/bin/hashem` و `/usr/local/bin/hashem.sh`).
- قبل از شروع یک بکاپ بگیرید: `hashem backup now`.

## ۱. تست‌های خودکار روی لینوکس

| # | دستور | انتظار |
|---|---|---|
| 1.1 | `cd panel && go test ./...` | همه پاس شوند. حدود ۲۲ تستی که روی ویندوز شکست می‌خوردند باید اینجا پاس شوند. |
| 1.2 | `cd panel && go test -race -run 'Cluster\|Peer\|License' ./...` | بدون گزارش data race (C3). |
| 1.3 | `for t in tests/*.sh; do bash "$t"; done` | همه `PASS` بدهند، به‌خصوص `test_autopool.sh`، `test_install_verify.sh`، `test_update_channel.sh` و `test_tcpmux_default.sh` که روی ویندوز اجرا نشدند. |

## ۲. امنیت و تنظیمات پنل

| # | مورد | مراحل | انتظار |
|---|---|---|---|
| 2.1 | C1 | روی سرور دارای لایسنس، 2FA و ترمینال را فعال کنید، بعد `systemctl restart gre-panel` بزنید. | 2FA هنوز فعال است و لاگین کد می‌خواهد. ترمینال هنوز فعال است. |
| 2.2 | C2 | مقدار `pass_hash` را از `/etc/gre-panel/panel.json` به‌عنوان رمز وارد کنید. | لاگین رد می‌شود. |
| 2.3 | H10 | `hashem license deactivate` بزنید، یک دقیقه صبر کنید و پنل را ری‌استارت کنید. | لایسنس غیرفعال می‌ماند. `hashem license status` هم «FREE» نشان می‌دهد. |
| 2.4 | H11 | از بیرون، ۶ بار لاگین اشتباه با هدرهای `X-Forwarded-For` متفاوت بفرستید. | قفل per-IP بعد از ۵ تلاش فعال می‌شود. |
| 2.5 | H11 | اگر nginx جلوی پنل است: `TRUSTED_PROXY_IPS=127.0.0.1` را با `systemctl edit gre-panel` اضافه کنید. | در لاگ audit، IP واقعی کاربر ثبت می‌شود. |
| 2.6 | L20 | `hashem reset-password ' Pass with space '` بزنید و با همان رمز لاگین کنید. | لاگین موفق است. |
| 2.7 | M2 | `hashem panel-port 8088`، بعد `panel-user admin2`، بعد `panel-path my-panel-1`. | هر سه بدون «Unknown command» اجرا می‌شوند و پنل روی آدرس جدید باز می‌شود. |
| 2.8 | M6 | `hashem backup key` بزنید، بعد در پنل بخش «Backup encryption key» را با رمز درست و غلط امتحان کنید. | کلید فقط با رمز درست نمایش داده می‌شود. فایل بکاپ با دستور `openssl` نشان‌داده‌شده باز می‌شود. |
| 2.9 | M15 | `ls -l /etc/frp/*.toml /etc/backhaul/*.toml` | همه‌ی فایل‌ها `-rw-------` هستند. |

## ۳. تونل‌ها

| # | مورد | مراحل | انتظار |
|---|---|---|---|
| 3.1 | H2 | روی سرور خارج Auto-Pool را روشن کنید و ۱۰ دقیقه `journalctl -u frpc -f` را نگاه کنید. | frpc فقط وقتی ری‌استارت می‌شود که `auto_pool.json` تصمیم `applied` ثبت کند، نه هر دقیقه. |
| 3.2 | H3 | در پنل ایران، پورت یک peer FRP را عوض کنید. | `frps-N.toml` دست نمی‌خورد و تونل وصل می‌ماند. پیام «Apply them on the foreign server» نمایش داده می‌شود. |
| 3.3 | M14 | روی سرور خارج با PROXY protocol v2، پورت‌ها را از پنل عوض کنید. | `transport.proxyProtocolVersion` در بلوک‌های جدید `frpc.toml` باقی است. |
| 3.4 | H4 | Switch Engine را از FRP به Backhaul و برگشت امتحان کنید (یک بار هم با هسته‌ی Backhaul نسخه‌ی ۲). | کانفیگ Backhaul با بخش‌های `[listener]` و `[security]` نوشته می‌شود و تونل بالا می‌آید. |
| 3.5 | H4 | `client.toml` را عمداً خراب کنید، یا بدون peer در دسترس سوییچ کنید. | خطا برمی‌گردد، پیام «previous engine restored» نمایش داده می‌شود و تونل قبلی کار می‌کند. |
| 3.6 | H8 | از پنل یک peer با ترنسپورت KCP اضافه کنید. | نصب موفق است و `frps-N.toml` شامل `kcpBindPort` است. |
| 3.7 | H7 | نصب Iran را روی یک لینک کند اجرا کنید. | بعد از ۶۰ ثانیه قطع نمی‌شود. |
| 3.8 | M5 | `hashem update` بزنید وقتی کاربر فعال وجود دارد. | خروجی «already up to date — nothing restarted» است، یا فقط سرویسی که کانفیگش عوض شده ری‌استارت می‌شود. |
| 3.9 | M18 | یک پورت کنترل FRP انتخاب کنید که xray روی آن است. | xray kill نمی‌شود و پیام «held by 'xray'» نمایش داده می‌شود. |
| 3.10 | M19 | قبل از «Remove tunnel» یک تونل sit یا ipip دستی بسازید. | تونل دستی بعد از حذف باقی می‌ماند. |
| 3.11 | M20 | `sysctl net.ipv4.ip_local_reserved_ports` | پورت پنل، پورت‌های frps و پورت‌های فوروارد در فهرست هستند. |
| 3.12 | M21 | `hashem setup-foreign` را تعاملی اجرا کنید. | دیگر برای پورت کنترل FRP سؤالی نمی‌پرسد. |
| 3.13 | M3 | `hashem setup-foreign --bundle bh1_...` | Backhaul خارج نصب می‌شود (نه خطای «Invalid remote public IP»). |
| 3.14 | L19 | GRE ICMP را مسدود کنید، ولی frpc وصل باشد. | Watchdog تونل را DOWN اعلام نمی‌کند. |

## ۴. Peer Link، کلاستر و Rescue

| # | مورد | مراحل | انتظار |
|---|---|---|---|
| 4.1 | H1 | دو سرور با base pathهای متفاوت، Peer Link را وصل کنید و «Test» بزنید. | وصل می‌شود. در `peer_link.json` فیلدهای `peer_base_path` و `internal_port` پر شده‌اند. |
| 4.2 | H1 | از بنچمارک ایران، `frp:quic` یا `fou:443` را Apply کنید. | روی هر دو سرور اعمال می‌شود. اگر سرور مقابل نتواند، سرور ایران به carrier قبلی برمی‌گردد. |
| 4.3 | H1 | `curl -i http://<server>:<port>/_hp/api/peer/ping` بدون secret | جواب `404` ساده است. |
| 4.4 | C4 | یک bundle Bagher را روی سرور خارج اعمال کنید. | تونل SSH وصل می‌شود. خط `authorized_keys` با `restrict,port-forwarding,permitlisten=` شروع می‌شود و بقیه‌ی کلیدهای روت سر جایشان هستند. |
| 4.5 | H6 | پورت پنل سرور مقابل را با فایروال ببندید (ping باز بماند). | فقط بنر «Block detected» نمایش داده می‌شود و Rescue خودکار فعال نمی‌شود. |
| 4.6 | M8 | روی سرور پشت NAT یک bundle بسازید. | IP داخل bundle عمومی است، نه `10.x` یا `172.16-31.x`. |
| 4.7 | M1 | `hashem cluster revert` | `cluster.json` سالم می‌ماند و nodeها پاک نمی‌شوند. chainهای `HASHEM-CLUSTER-*` خالی می‌شوند. |
| 4.8 | M16، L22 | صفحه‌ی کلاستر را باز کنید. | پینگ و «last seen» درست نمایش داده می‌شوند. بدون تونل شناخته‌شده، وضعیت «UNKNOWN» است. |
| 4.9 | M12 | `wss_carrier.json` را بدون `auth_token` بگذارید و carrier را WSS کنید. | سرور WSS بالا نمی‌آید و خطا ثبت می‌شود. با توکن، قطع WebSocket بدون ترافیک هم reconnect می‌شود. |

## ۵. پنل، ترمینال و نگهداری

| # | مورد | مراحل | انتظار |
|---|---|---|---|
| 5.1 | H5 | ترمینال وب را باز کنید و ۲ دقیقه کاری نکنید. | باز می‌ماند و تا ۱۰ دقیقه بی‌کاری بسته نمی‌شود. |
| 5.2 | M7 | از طریق HTTPS پنل، «Renew» را بزنید. | بدون خطای شبکه جواب می‌دهد. |
| 5.3 | M7 | `certbot renew --force-renewal` بزنید و تا یک ساعت صبر کنید (یا پنل را ری‌استارت کنید و ۱ دقیقه صبر کنید). | گواهی جدید روی HTTPS پنل سرو می‌شود (`openssl s_client`). |
| 5.4 | M6 | Watchdog را خاموش کنید و بکاپ ساعتی بگذارید. | بکاپ ساخته می‌شود و `systemctl is-active hashem-watchdog.timer` جواب `active` می‌دهد. |
| 5.5 | M9 | روی سرور بدون Bagher: `ls /root/.ssh/hashem-fwd*` | کلیدی ساخته نشده است. |
| 5.6 | M11 | Doctor را روی سرور Backhaul بدون GRE اجرا کنید. | «Critical» نیست. «Fix» هم `gre-tunnel` را ری‌استارت نمی‌کند. |
| 5.7 | L6 | `systemctl show gre-panel -p WatchdogUSec` | اگر WatchdogSec تنظیم است، پنل در حالت عادی ری‌استارت نمی‌شود (`journalctl -u gre-panel`). |
| 5.8 | L12 | Doctor | مقدار `limit_nofile` همان محدودیت frps یا frpc است (`cat /proc/$(pidof frps)/limits`). |
| 5.9 | H12 | دسترسی به github.com را موقتاً ببندید و `hashem update` بزنید. | نصب با پیام «refusing to install unverified files» متوقف می‌شود و پنل فعلی کار می‌کند. |
| 5.10 | M4 | با build ناموفق (مثلاً بدون Go و بدون اینترنت) `hashem update` بزنید. | پنل خاموش نمی‌ماند. |
| 5.11 | سنتینل | نصب، start/stop/restart و حذف سنتینل از پنل. | خطاها نمایش داده می‌شوند، پورت انتخاب‌شده استفاده می‌شود و URL درست است. |

## ثبت نتیجه

برای هر ردیف «✓» یا «✗ + خروجی خطا» بنویسید. موارد ✗ را به همراه `journalctl -u gre-panel -n 200` و فایل کانفیگ مربوطه برای بررسی بفرستید.
