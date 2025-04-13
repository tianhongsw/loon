#!/bin/bash

# 设置最大文件描述符
echo ">> 设置 /etc/security/limits.conf ..."
cat <<EOF >> /etc/security/limits.conf

* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

# 确保 pam 启用 limits
echo ">> 修改 PAM 配置 ..."
grep -q pam_limits.so /etc/pam.d/common-session || echo "session required pam_limits.so" >> /etc/pam.d/common-session

# 设置内核参数优化 + BBR
echo ">> 写入 /etc/sysctl.conf 网络优化参数 ..."
cat <<EOF >> /etc/sysctl.conf

# 自建代理优化参数
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

# 应用新内核参数
sysctl -p

# 创建 systemd 服务文件（路径根据你提供的配置）
echo ">> 创建 sing-box systemd 服务 ..."
cat <<EOF > /etc/systemd/system/sing-box.service
[Unit]
Description=Sing-box VLESS Reality
After=network.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/conf/VLESS-REALITY-10156.json
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# 启动并设置为开机启动
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable sing-box
systemctl restart sing-box

# 状态查看
echo ">> Sing-box 状态："
systemctl status sing-box --no-pager

echo "✅ 系统优化完成！ulimit + BBR + systemd 已配置"