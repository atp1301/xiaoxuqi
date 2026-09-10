## Docker 启停实测（本机）

日期：2026-09-10 / 主机：ASUS TUF Gaming F16 FX607JV
引擎：Docker Desktop 4.90.0 (Engine 29.7.2, linux/amd64)；端口只发布到 127.0.0.1。
计时用 bash 纳秒整数运算（本机无 `bc`）。就绪探测带重试，避免把"还没起来"误记成失败。

```text
engine=29.7.2 os=Docker Desktop mem=8125480960

=== local-web | lab/docker-compose.yml ===
$ docker compose -f lab/docker-compose.yml down -v
$ docker compose -f lab/docker-compose.yml up -d --build
up   exit=0 wall=1279 ms
ready after 1 polls (130 ms), GET / -> HTTP 200
running containers: training-web 
down exit=0 wall=3866 ms

=== complex-web | lab/complex_web/docker-compose.yml ===
$ docker compose -f lab/complex_web/docker-compose.yml down -v
$ docker compose -f lab/complex_web/docker-compose.yml up -d --build
up   exit=0 wall=2082 ms
ready after 2 polls (770 ms), GET / -> HTTP 200
running containers: app-api edge-gateway internal-admin 
down exit=0 wall=7344 ms

```
