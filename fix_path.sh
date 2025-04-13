#!/bin/bash

# 修正文件路径中的 'VLESA' 为 'VLESS'
echo ">> 修正文件路径中的 'VLESA' 为 'VLESS' ..."
sed -i 's/VLESA/VLESS/g' /etc/systemd/system/sing-box.service

# 检查并重载 systemd 配置
echo ">> 重载 systemd 配置 ..."
systemctl daemon-reload

# 重启 Sing-box 服务
echo ">> 重启 sing-box 服务 ..."
systemctl restart sing-box

# 查看服务状态
echo ">> sing-box 状态："
systemctl status sing-box --no-pager

echo "✅ 文件路径修正完成，服务已重启。"