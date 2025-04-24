#!/bin/bash

# ========== 基本配置 ==========
INTERFACE="ens4"
LIMIT_MB=194560
EMAIL="tianhongws@gmail.com"
SCRIPT_PATH="/usr/local/bin/check_traffic.sh"
FLAG_FILE="/var/run/traffic_shutdown_flag"
LOG_FILE="/var/log/traffic-check.log"

# ========== 安装依赖 ==========
echo "[1/5] 安装依赖..."
apt update -y
apt install -y vnstat mailutils cron

# ========== 初始化 vnstat ==========
echo "[2/5] 初始化流量监控..."
vnstat -u -i $INTERFACE
systemctl enable vnstat
systemctl restart vnstat

# ========== 写入检测脚本 ==========
echo "[3/5] 写入流量检测脚本..."
cat > $SCRIPT_PATH <<EOF
#!/bin/bash

USAGE=\$(vnstat -i $INTERFACE --oneline | awk -F ';' '{print \$(NF-2)}' | sed 's/ //g')

if echo "\$USAGE" | grep -qi "GB"; then
    VALUE=\$(echo "\$USAGE" | grep -o '[0-9.]\+' | awk '{printf("%.0f", \$1 * 1024)}')
elif echo "\$USAGE" | grep -qi "MB"; then
    VALUE=\$(echo "\$USAGE" | grep -o '[0-9.]\+' | awk '{printf("%.0f", \$1)}')
else
    VALUE=0
fi

if [ "\$VALUE" -ge $LIMIT_MB ]; then
    if [ -f "$FLAG_FILE" ]; then
        exit 0
    fi
    echo "流量超过限制：\$VALUE MB，已执行关机。" | mail -s "【警告】流量超标，自动关机" $EMAIL
    touch "$FLAG_FILE"
    shutdown -h now
fi
EOF

chmod +x $SCRIPT_PATH

# ========== 配置定时任务 ==========
echo "[4/5] 设置定时任务..."
crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH" > /tmp/current_cron
cat >> /tmp/current_cron <<CRON
*/10 * * * * $SCRIPT_PATH >> $LOG_FILE 2>&1
0 0 1 * * rm -f $FLAG_FILE
@reboot sleep 60 && $SCRIPT_PATH >> $LOG_FILE 2>&1
CRON
crontab /tmp/current_cron
rm -f /tmp/current_cron

# ========== 完成 ==========
echo "[5/5] 部署完成。开始流量监控。"
vnstat -i $INTERFACE -m