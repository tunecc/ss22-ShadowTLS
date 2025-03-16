#!/bin/bash

# 定义颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
LIGHT_GREEN='\033[1;32m'
LIGHT_CYAN='\033[1;36m'
RESET='\033[0m'

# 与ss.sh兼容的路径定义
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/shadowtls"
SS_RUST_BIN="/usr/local/bin/ss-rust"
SS_RUST_CONFIG="/etc/ss-rust/config.json"
SERVICE_FILE="/etc/systemd/system/shadowtls.service"

# 检查是否以 root 权限运行
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}请以 root 权限运行此脚本${RESET}"
        exit 1
    fi
}

# 检查系统类型并安装依赖
install_requirements() {
    echo -e "${CYAN}正在检查并安装必要依赖...${RESET}"
    
    # 检测系统类型
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        apt update -qq
        apt install -y wget curl jq
    elif [ -f /etc/redhat-release ]; then
        # CentOS/RHEL
        if command -v dnf &>/dev/null; then
            dnf -y install wget curl jq systemd
        else
            yum -y install wget curl jq systemd
        fi
    else
        echo -e "${YELLOW}未能确定系统类型，尝试使用apt...${RESET}"
        apt update -qq
        apt install -y wget curl jq
    fi
    
    echo -e "${GREEN}依赖安装完成${RESET}"
}

# 获取最新版本
get_latest_version() {
    echo -e "${CYAN}正在检查 ShadowTLS 最新版本...${RESET}" >&2
    latest_version=$(curl -s --connect-timeout 10 "https://api.github.com/repos/ihciah/shadow-tls/releases/latest" | jq -r .tag_name 2>/dev/null)
    if [ -z "$latest_version" ] || [ "$latest_version" == "null" ]; then
        echo -e "${YELLOW}无法获取最新版本，使用默认版本 v0.2.25${RESET}" >&2
        echo "v0.2.25"
    else
        echo -e "${GREEN}获取到最新版本: ${latest_version}${RESET}" >&2
        echo "$latest_version"
    fi
}

# 检查 SS-Rust 是否已安装
check_ssrust() {
    if [ -f "$SS_RUST_BIN" ] && [ -f "$SS_RUST_CONFIG" ]; then
        return 0  # 已安装
    else
        return 1  # 未安装
    fi
}

# 获取 SS 端口 - 更新为使用jq处理json
get_ssrust_port() {
    if [ ! -f "$SS_RUST_CONFIG" ]; then
        echo ""
        return 1
    fi
    local port=$(jq -r '.server_port // empty' "$SS_RUST_CONFIG" 2>/dev/null)
    if [ -z "$port" ]; then
        echo ""
        return 1
    fi
    echo "$port"
}

# 获取 SS 密码 - 更新为使用jq处理json
get_ssrust_password() {
    if [ ! -f "$SS_RUST_CONFIG" ]; then
        echo ""
        return 1
    fi
    local password=$(jq -r '.password // empty' "$SS_RUST_CONFIG" 2>/dev/null)
    if [ -z "$password" ]; then
        echo ""
        return 1
    fi
    echo "$password"
}

# 获取 SS 加密方式 - 更新为使用jq处理json
get_ssrust_method() {
    if [ ! -f "$SS_RUST_CONFIG" ]; then
        echo ""
        return 1
    fi
    local method=$(jq -r '.method // empty' "$SS_RUST_CONFIG" 2>/dev/null)
    if [ -z "$method" ]; then
        echo ""
        return 1
    fi
    echo "$method"
}

# 优化的获取服务器IP函数
get_server_ip() {
    local ipv4=""

    for ip_service in "ipv4.icanhazip.com" "api.ipify.org" "ip.sb" "ifconfig.me" "ipinfo.io/ip"; do
        echo -e "${YELLOW}尝试从 $ip_service 获取IP...${RESET}" >&2
        ipv4=$(curl -s4 --connect-timeout 5 "$ip_service" 2>/dev/null)
        if [ -n "$ipv4" ]; then
            echo -e "${GREEN}成功获取IP: $ipv4${RESET}" >&2
            break
        fi
    done
    
    if [ -z "$ipv4" ]; then
        echo -e "${YELLOW}警告: 无法获取IPv4地址${RESET}" >&2
        return 1
    fi
    
    echo "$ipv4"
    return 0
}

# 生成安全的Base64编码
urlsafe_base64() {
    echo -n "$1" | base64 | tr '+/' '-_' | tr -d '='
}

# 生成随机端口 (避免常用端口)
generate_random_port() {
    local min_port=10000
    local max_port=65000
    
    # 检查是否安装shuf
    if command -v shuf &> /dev/null; then
        echo $(shuf -i "${min_port}-${max_port}" -n 1)
    else
        # 备选方案，使用$RANDOM
        echo $(( min_port + RANDOM % (max_port - min_port + 1) ))
    fi
}

# 检查端口是否被占用
check_port_in_use() {
    if command -v ss &> /dev/null; then
        ss -tuln | grep -q ":$1 "
        return $?
    elif command -v netstat &> /dev/null; then
        netstat -tuln | grep -q ":$1 "
        return $?
    else
        # 如果两个命令都没有，直接返回未占用
        return 1
    fi
}

# 生成 SS 链接和配置
generate_ss_links() {
    local server_ip=$1
    local listen_port=$2
    local ssrust_password=$3
    local ssrust_method=$4
    local stls_password=$5
    local stls_sni=$6
    local backend_port=$7
    
    echo -e "${YELLOW} ================= 服务器配置信息 =================${RESET}"
    
    echo -e "\n${GREEN}● Shadowsocks 配置${RESET}"
    echo -e "  IP地址: ${CYAN}${server_ip}${RESET}"
    echo -e "  端口: ${CYAN}${backend_port}${RESET}"
    echo -e "  加密方式: ${CYAN}${ssrust_method}${RESET}"
    echo -e "  密码: ${CYAN}${ssrust_password}${RESET}"
    
    echo -e "\n${GREEN}● ShadowTLS 配置${RESET}"
    echo -e "  端口: ${CYAN}${listen_port}${RESET}"
    echo -e "  密码: ${CYAN}${stls_password}${RESET}"
    echo -e "  SNI域名: ${CYAN}${stls_sni}${RESET}"
    echo -e "  版本: ${CYAN}3${RESET}"
    
    # 生成 SS + ShadowTLS 合并链接
    local userinfo
    if [[ "${ssrust_method}" == 2022* ]]; then
        # 2022系列加密方式需要特殊处理
        userinfo=$(echo -n "${ssrust_method}:${ssrust_password}" | base64 | tr -d '\n' | tr -d '=' | tr '+/' '-_')
    else
        userinfo=$(echo -n "${ssrust_method}:${ssrust_password}" | base64 | tr -d '\n' | tr -d '=' | tr '+/' '-_')
    fi
    
    local shadow_tls_config="{\"version\":\"3\",\"password\":\"${stls_password}\",\"host\":\"${stls_sni}\",\"port\":\"${listen_port}\",\"address\":\"${server_ip}\"}"
    local shadow_tls_base64=$(echo -n "${shadow_tls_config}" | base64 | tr -d '\n' | tr -d '=' | tr '+/' '-_')
    local ss_url="ss://${userinfo}@${server_ip}:${backend_port}?shadow-tls=${shadow_tls_base64}#SS-${server_ip}"

    echo -e "\n${GREEN}Shadowsocks 配置${RESET}"
    echo -e "${CYAN}ss-${server_ip} = ss, ${server_ip}, ${backend_port}, encrypt-method=${ssrust_method}, password=${ssrust_password}, udp-relay=true${RESET}"

    echo -e "\n${GREEN}Shadowsocks+ShadowTLS  配置${RESET}"
    echo -e "${CYAN}ss-${server_ip} = ss, ${server_ip}, ${listen_port}, encrypt-method=${ssrust_method}, password=${ssrust_password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${backend_port}${RESET}"

    # 保存配置到文件
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/config.txt" << EOF
# 配置信息 - 保存于 $(date '+%Y-%m-%d %H:%M:%S')

Shadowsocks 配置:
- 服务器IP: ${server_ip}
- 端口: ${backend_port}
- 加密方式: ${ssrust_method}
- 密码: ${ssrust_password}

ShadowTLS 配置:
- 端口: ${listen_port}
- 密码: ${stls_password}
- SNI域名: ${stls_sni}
- 版本: 3

Shadowsocks  配置:
ss-${server_ip} = ss, ${server_ip}, ${backend_port}, encrypt-method=${ssrust_method}, password=${ssrust_password}, udp-relay=true

Shadowsocks+ShadowTLS  配置:
ss-${server_ip} = ss, ${server_ip}, ${listen_port}, encrypt-method=${ssrust_method}, password=${ssrust_password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${backend_port}

EOF
    echo -e "\n${GREEN}● 配置已保存至 ${CONFIG_DIR}/config.txt${RESET}"
}

# 安装 ShadowTLS
install_shadowtls() {
    echo -e "${CYAN}正在安装 ShadowTLS...${RESET}"
    
    if [ -f "$INSTALL_DIR/shadow-tls" ] && systemctl is-enabled shadowtls &>/dev/null; then
        echo -e "${YELLOW}检测到ShadowTLS已安装，是否重新安装? [y/N]${RESET}"
        read -r reinstall
        if [[ ! "${reinstall,,}" =~ ^y(es)?$ ]]; then
            echo -e "${GREEN}已取消重新安装${RESET}"
            return 0
        fi

        systemctl stop shadowtls &>/dev/null
    fi

    if ! check_ssrust; then
        echo -e "${RED}未检测到 Shadowsocks Rust，请先安装${RESET}"
        echo -e "${YELLOW}提示: 可以使用 ./ss22.sh 安装 Shadowsocks Rust${RESET}"
        return 1
    fi
    
    # 安装必要工具
    install_requirements
    
    # 获取系统架构
    local arch
    case $(uname -m) in
        x86_64)
            arch="x86_64-unknown-linux-musl"
            ;;
        aarch64)
            arch="aarch64-unknown-linux-musl"
            ;;
        armv7*)
            arch="armv7-unknown-linux-musleabihf"
            ;;
        *)
            echo -e "${RED}不支持的系统架构: $(uname -m)${RESET}"
            exit 1
            ;;
    esac
    
    # 获取最新版本
    local version=$(get_latest_version)

    echo -e "${CYAN}正在下载 ShadowTLS ${version}...${RESET}"
    local download_url="https://github.com/ihciah/shadow-tls/releases/download/${version}/shadow-tls-${arch}"
    echo -e "${YELLOW}下载URL: ${download_url}${RESET}"
    
    # 使用最简单的下载命令
    echo -e "${YELLOW}尝试使用wget下载...${RESET}"
    wget -O "/tmp/shadow-tls.tmp" "$download_url"
    local download_result=$?
    
    echo -e "${YELLOW}wget 退出状态: $download_result${RESET}"
    
    # 如果wget失败，尝试curl
    if [ $download_result -ne 0 ] || [ ! -s "/tmp/shadow-tls.tmp" ]; then
        echo -e "${RED}wget下载失败，尝试使用curl...${RESET}"
        curl -L -o "/tmp/shadow-tls.tmp" "$download_url"
        download_result=$?
        
        if [ $download_result -ne 0 ] || [ ! -s "/tmp/shadow-tls.tmp" ]; then
            echo -e "${RED}下载失败，尝试查看详细错误信息...${RESET}"
            echo -e "${YELLOW}直接尝试访问URL:${RESET}"
            curl -v "$download_url"
            exit 1
        fi
    fi
    
    # 检查下载的文件是否为可执行文件
    echo -e "${YELLOW}检查下载的文件...${RESET}"
    if [ -f "/tmp/shadow-tls.tmp" ]; then
        if file "/tmp/shadow-tls.tmp" | grep -q "executable"; then
            echo -e "${GREEN}下载成功，文件看起来是有效的可执行文件${RESET}"
        else
            echo -e "${RED}文件不是可执行文件，可能下载到了错误页面${RESET}"
            echo -e "${YELLOW}文件内容预览:${RESET}"
            head -n 20 "/tmp/shadow-tls.tmp"
            exit 1
        fi
    else
        echo -e "${RED}文件不存在，下载可能失败${RESET}"
        exit 1
    fi

    # 移动到最终位置并设置权限
    mv "/tmp/shadow-tls.tmp" "$INSTALL_DIR/shadow-tls"
    chmod +x "$INSTALL_DIR/shadow-tls"
    
    # 生成随机密码
    local password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
    
    # 获取 SS 端口 - 自动从配置中读取
    local ss_port=$(get_ssrust_port)
    if [ -z "$ss_port" ]; then
        echo -e "${RED}无法自动获取 Shadowsocks Rust 端口${RESET}"
        read -rp "请手动输入 Shadowsocks Rust 的后端端口: " ss_port
        if [ -z "$ss_port" ]; then
            echo -e "${RED}错误: 必须提供 Shadowsocks Rust 端口${RESET}"
            return 1
        fi
    else
        echo -e "${GREEN}已自动获取 Shadowsocks Rust 后端端口: ${ss_port}${RESET}"
    fi
    
    # 获取ShadowTLS对外监听端口
    local listen_port
    while true; do
        local default_port=$(generate_random_port)
        read -rp "请输入 ShadowTLS 对外监听端口 [1-65535] (回车随机): " listen_port
        
        # 如果用户未输入，使用默认值
        if [ -z "$listen_port" ]; then
            listen_port=$default_port
            echo -e "${GREEN}使用随机端口: ${listen_port}${RESET}"
            break
        fi
        
        # 验证端口
        if ! [[ "$listen_port" =~ ^[0-9]+$ ]] || [ "$listen_port" -lt 1 ] || [ "$listen_port" -gt 65535 ]; then
            echo -e "${RED}错误: 端口必须是1-65535之间的数字${RESET}"
            continue
        fi
        
        # 检查端口是否被占用
        if check_port_in_use "$listen_port"; then
            echo -e "${RED}错误: 端口 ${listen_port} 已被占用，请选择其他端口${RESET}"
            continue
        fi
        
        break
    done
    
    # 获取伪装域名输入
    read -rp "请输入 TLS 伪装域名 (回车默认为 www.microsoft.com): " tls_domain
    
    # 如果用户未输入域名，使用默认值
    if [ -z "$tls_domain" ]; then
        tls_domain="www.microsoft.com"
    fi
    
    # 检测虚拟化类型
    local virt_type="unknown"
    if command -v systemd-detect-virt &>/dev/null; then
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    fi
    
    # 创建服务文件
    cat > "/etc/systemd/system/shadowtls.service" << EOF
[Unit]
Description=Shadow-TLS Server Service for Shadowsocks
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Restart=on-failure
RestartSec=5s
EOF

    # 如果是KVM环境，添加ulimit配置
    if [[ "$virt_type" == "kvm" ]]; then
        echo 'ExecStartPre=/bin/sh -c "ulimit -n 51200"' >> "/etc/systemd/system/shadowtls.service"
        echo -e "${GREEN}检测到KVM虚拟化环境，已添加性能优化选项${RESET}"
    fi
    
    # 继续添加服务配置
    cat >> "/etc/systemd/system/shadowtls.service" << EOF
Environment=MONOIO_FORCE_LEGACY_DRIVER=1
ExecStart=$INSTALL_DIR/shadow-tls --v3 --fastopen server --listen [::]:${listen_port} --server 127.0.0.1:${ss_port} --tls ${tls_domain} --password ${password}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=shadowtls

[Install]
WantedBy=multi-user.target
EOF
    
    # 保存配置信息到文件
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/env" << EOF
# ShadowTLS 环境配置
LISTEN_PORT=${listen_port}
TLS_DOMAIN=${tls_domain}
PASSWORD=${password}
SS_PORT=${ss_port}
EOF
    
    # 重新加载 systemd 配置
    systemctl daemon-reload
    
    # 启动服务并设置开机自启
    echo -e "${CYAN}启动 ShadowTLS 服务...${RESET}"
    systemctl enable shadowtls
    systemctl start shadowtls
    sleep 2
    
    # 获取服务器IP
    local server_ip=$(get_server_ip)
    if [ -z "$server_ip" ]; then
        server_ip="<无法获取IP，请手动填写>"
    fi
    
    # 验证服务状态
    if ! systemctl is-active --quiet shadowtls; then
        echo -e "${RED}ShadowTLS 服务未能正常运行，请检查日志${RESET}"
        echo -e "\n${YELLOW}服务状态:${RESET}"
        systemctl status shadowtls --no-pager
        echo -e "\n${YELLOW}查看完整日志请运行: ${CYAN}journalctl -u shadowtls -n 50${RESET}\n"
        return 1
    fi
    
    echo -e "\n${GREEN}=== ShadowTLS 安装成功! ====${RESET}"
    
    # 显示配置
    local ssrust_password=$(get_ssrust_password)
    local ssrust_method=$(get_ssrust_method)
    generate_ss_links "${server_ip}" "${listen_port}" "${ssrust_password}" "${ssrust_method}" "${password}" "${tls_domain}" "${ss_port}"

    echo -e "\n${GREEN}服务已启动并设置为开机自启${RESET}"
    
    # 添加每天5点5分自动重启的定时任务
    echo -e "${CYAN}正在设置 ShadowTLS 每天 5:05 自动重启...${RESET}"
    
    # 设置重启时间为5:05
    local hour="5"
    local minute="5"
    
    # 获取现有的crontab配置
    local current_cron
    current_cron=$(crontab -l 2>/dev/null)
    
    # 构建新的crontab条目
    local cron_line="${minute} ${hour} * * * systemctl restart shadowtls"
    
    # 检查是否已有shadowtls重启任务
    if echo "$current_cron" | grep -q "systemctl restart shadowtls"; then
        # 删除现有任务
        current_cron=$(echo "$current_cron" | grep -v "systemctl restart shadowtls")
        echo -e "${YELLOW}已删除旧的定时重启任务${RESET}"
    fi
    
    # 更新crontab
    (echo "${current_cron}"; echo "${cron_line}") | sort | uniq | crontab -
    
    echo -e "${GREEN}● 定时重启已自动设置成功${RESET}"
    echo -e "  ShadowTLS 将在每天 ${CYAN}${hour}:${minute}${RESET} 自动重启"
}

# 卸载 ShadowTLS
uninstall_shadowtls() {
    echo -e "${CYAN}正在卸载 ShadowTLS...${RESET}"
    
    read -rp "确认要卸载 ShadowTLS? (y/回车确认，其他键取消): " confirm

    if [[ "${confirm,,}" =~ ^y(es)?$ || -z "$confirm" ]]; then
        echo -e "${GREEN}开始卸载...${RESET}"
    else
        echo -e "${YELLOW}已取消卸载操作${RESET}"
        return 0
    fi
    
    # 停止并禁用服务
    echo -e "${CYAN}停止并移除服务...${RESET}"
    systemctl stop shadowtls &>/dev/null
    systemctl disable shadowtls &>/dev/null
    
    # 删除服务文件
    rm -f "/etc/systemd/system/shadowtls.service"
    
    # 删除二进制文件
    echo -e "${CYAN}删除 ShadowTLS 程序文件...${RESET}"
    rm -f "$INSTALL_DIR/shadow-tls"
    
    # 删除配置目录 (不进行备份)
    echo -e "${CYAN}删除配置文件...${RESET}"
    if [ -d "$CONFIG_DIR" ]; then
        rm -rf "$CONFIG_DIR"
        echo -e "${GREEN}已删除配置目录${RESET}"
    fi
    
    # 删除定时重启任务
    echo -e "${CYAN}检查并删除定时重启任务...${RESET}"
    if crontab -l 2>/dev/null | grep -q "systemctl restart shadowtls"; then
        crontab -l 2>/dev/null | grep -v "systemctl restart shadowtls" | crontab -
        echo -e "${GREEN}已删除定时重启任务${RESET}"
    fi
    
    # 重新加载 systemd 配置
    systemctl daemon-reload
    
    echo -e "${GREEN}ShadowTLS 已成功卸载${RESET}"
}

# 查看配置
view_config() {
    echo -e "${CYAN}正在获取配置信息...${RESET}"
    
    # 检查服务是否安装
    if [ ! -f "/etc/systemd/system/shadowtls.service" ] && [ ! -f "/etc/systemd/system/shadowtls-ss.service" ]; then
        echo -e "${RED}ShadowTLS 未安装${RESET}"
        return 1
    fi
    
    # 获取服务器IP
    local server_ip=$(get_server_ip)
    if [ -z "$server_ip" ]; then
        server_ip="<无法获取，请手动填写>"
    fi
    
    # 检查服务文件
    local service_file="/etc/systemd/system/shadowtls.service"
    if [ ! -f "$service_file" ]; then
        service_file="/etc/systemd/system/shadowtls-ss.service"
    fi
    
    # 从服务文件中提取配置信息
    local listen_port
    local tls_domain
    local password
    
    if [ -f "$service_file" ]; then
        # 提取监听端口 (兼容IPv6和IPv4格式)
        listen_port=$(grep -oP '(?<=--listen \[?::\]?:)\d+' "$service_file" 2>/dev/null)
        # 如果上面匹配失败，尝试其他格式
        if [ -z "$listen_port" ]; then
            listen_port=$(grep -oP '(?<=--listen )\S+?:\K\d+' "$service_file" 2>/dev/null)
        fi
        
        # 提取TLS域名
        tls_domain=$(grep -oP '(?<=--tls )[^ ]+' "$service_file" 2>/dev/null)
        
        # 提取密码
        password=$(grep -oP '(?<=--password )[^ ]+' "$service_file" 2>/dev/null)
    fi
    
    # 获取SS配置并显示
    if check_ssrust; then
        local ss_port=$(get_ssrust_port)
        local ssrust_password=$(get_ssrust_password)
        local ssrust_method=$(get_ssrust_method)
        
        if [ -n "$listen_port" ] && [ -n "$tls_domain" ] && [ -n "$password" ] && [ -n "$ss_port" ] && [ -n "$ssrust_password" ] && [ -n "$ssrust_method" ]; then
            generate_ss_links "${server_ip}" "${listen_port}" "${ssrust_password}" "${ssrust_method}" "${password}" "${tls_domain}" "${ss_port}"
        else
            echo -e "${RED}无法获取完整配置信息${RESET}"
            echo -e "监听端口: ${listen_port:-未知}"
            echo -e "TLS域名: ${tls_domain:-未知}"
            echo -e "ShadowTLS密码: ${password:-未知}"
            echo -e "SS端口: ${ss_port:-未知}"
            echo -e "SS密码: ${ssrust_password:-未知}"
            echo -e "SS加密方式: ${ssrust_method:-未知}"
        fi
    else
        echo -e "${RED}未检测到 Shadowsocks Rust 安装${RESET}"
    fi
}

show_service_status() {
    echo -e "\n${YELLOW}=== ShadowTLS 服务状态 ===${RESET}"
    if systemctl list-unit-files | grep -q shadowtls; then
        systemctl status shadowtls --no-pager 2>/dev/null || systemctl status shadowtls-ss --no-pager 2>/dev/null
        echo -e "\n${GREEN}● 查看完整日志:${RESET} ${CYAN}journalctl -u shadowtls -n 50${RESET}"
    else
        echo -e "${RED}未找到 ShadowTLS 服务${RESET}"
    fi
}

# 设置定时重启
schedule_restart() {
    echo -e "${CYAN}设置 ShadowTLS 定时重启...${RESET}"
    
    # 检查是否已安装
    if ! systemctl list-unit-files | grep -q shadowtls; then
        echo -e "${RED}未检测到 ShadowTLS 服务，请先安装${RESET}"
        return 1
    fi
    
    # 获取现有的crontab配置
    local current_cron
    current_cron=$(crontab -l 2>/dev/null)
    
    # 检查是否已有shadowtls重启任务
    if echo "$current_cron" | grep -q "systemctl restart shadowtls"; then
        echo -e "${YELLOW}已检测到现有的定时重启任务${RESET}"
        echo -e "$(echo "$current_cron" | grep "systemctl restart shadowtls")"
        read -rp "是否删除现有任务并创建新任务? (y/N): " confirm
        if [[ ! "${confirm,,}" =~ ^y(es)?$ ]]; then
            echo -e "${YELLOW}已取消操作${RESET}"
            return 0
        fi
        # 删除现有任务
        current_cron=$(echo "$current_cron" | grep -v "systemctl restart shadowtls")
    fi
    
    echo -e "\n${YELLOW}请设置定时重启时间:${RESET}"
    
    # 获取小时
    local hour
    while true; do
        read -rp "请输入小时 (0-23): " hour
        if [[ "$hour" =~ ^[0-9]+$ ]] && [ "$hour" -ge 0 ] && [ "$hour" -le 23 ]; then
            break
        else
            echo -e "${RED}无效输入，请输入0-23之间的数字${RESET}"
        fi
    done
    
    # 获取分钟
    local minute
    while true; do
        read -rp "请输入分钟 (0-59): " minute
        if [[ "$minute" =~ ^[0-9]+$ ]] && [ "$minute" -ge 0 ] && [ "$minute" -le 59 ]; then
            break
        else
            echo -e "${RED}无效输入，请输入0-59之间的数字${RESET}"
        fi
    done
    
    # 构建新的crontab条目
    local cron_line="${minute} ${hour} * * * systemctl restart shadowtls"
    
    # 更新crontab
    (echo "${current_cron}"; echo "${cron_line}") | sort | uniq | crontab -
    
    echo -e "\n${GREEN}● 定时重启已设置成功${RESET}"
    echo -e "  ShadowTLS 将在每天 ${CYAN}${hour}:${minute}${RESET} 重启"
    
    return 0
}

# 升级 ShadowTLS
upgrade_shadowtls() {
    echo -e "${CYAN}正在检查 ShadowTLS 更新...${RESET}"
    
    # 检查是否已安装
    if [ ! -f "$INSTALL_DIR/shadow-tls" ]; then
        echo -e "${RED}ShadowTLS 未安装，请先安装${RESET}"
        return 1
    fi
    
    # 备份现有配置信息
    local listen_port=""
    local tls_domain=""
    local password=""
    local ss_port=""
    
    # 从服务文件中提取配置
    local service_file="/etc/systemd/system/shadowtls.service"
    if [ ! -f "$service_file" ]; then
        service_file="/etc/systemd/system/shadowtls-ss.service"
    fi
    
    if [ -f "$service_file" ]; then
        listen_port=$(grep -oP '(?<=--listen \[?::\]?:)\d+' "$service_file" 2>/dev/null)
        if [ -z "$listen_port" ]; then
            listen_port=$(grep -oP '(?<=--listen )\S+?:\K\d+' "$service_file" 2>/dev/null)
        fi
        
        tls_domain=$(grep -oP '(?<=--tls )[^ ]+' "$service_file" 2>/dev/null)
        password=$(grep -oP '(?<=--password )[^ ]+' "$service_file" 2>/dev/null)
        ss_port=$(grep -oP '(?<=--server 127.0.0.1:)\d+' "$service_file" 2>/dev/null)
    fi
    
    # 获取当前版本
    local current_version=""
    if [ -f "$INSTALL_DIR/shadow-tls" ]; then
        current_version=$($INSTALL_DIR/shadow-tls --version 2>&1 | grep -oP 'shadow-tls \K[0-9.]+' || echo "未知")
    fi
    
    # 获取最新版本
    local latest_version=$(get_latest_version | sed 's/^v//')
    
    echo -e "${YELLOW}当前版本: ${current_version}${RESET}"
    echo -e "${YELLOW}最新版本: ${latest_version}${RESET}"
    
    # 判断是否需要更新
    if [ "$current_version" = "$latest_version" ]; then
        echo -e "${GREEN}已是最新版本，无需更新${RESET}"
        return 0
    fi
    
    # 确认升级
    read -rp "是否升级到最新版本? (y/N): " confirm
    if [[ ! "${confirm,,}" =~ ^y(es)?$ ]]; then
        echo -e "${YELLOW}已取消升级${RESET}"
        return 0
    fi
    
    echo -e "${CYAN}开始升级 ShadowTLS...${RESET}"
    
    # 获取系统架构
    local arch
    case $(uname -m) in
        x86_64)
            arch="x86_64-unknown-linux-musl"
            ;;
        aarch64)
            arch="aarch64-unknown-linux-musl"
            ;;
        armv7*)
            arch="armv7-unknown-linux-musleabihf"
            ;;
        *)
            echo -e "${RED}不支持的系统架构: $(uname -m)${RESET}"
            exit 1
            ;;
    esac
    
    # 获取最新版本
    local version=$(get_latest_version)
    
    # 停止服务
    echo -e "${CYAN}停止 ShadowTLS 服务...${RESET}"
    systemctl stop shadowtls 2>/dev/null || systemctl stop shadowtls-ss 2>/dev/null
    
    # ===== 修改的下载部分开始 =====
    echo -e "${CYAN}开始下载新版本...${RESET}"
    local download_url="https://github.com/ihciah/shadow-tls/releases/download/${version}/shadow-tls-${arch}"
    echo -e "${YELLOW}下载URL: ${download_url}${RESET}"
    
    # 简单的下载尝试，避免过多复杂参数
    echo -e "${YELLOW}尝试使用wget下载...${RESET}"
    wget -O "/tmp/shadow-tls.tmp" "$download_url"
    local download_result=$?
    
    # 检查下载结果
    if [ $download_result -ne 0 ] || [ ! -s "/tmp/shadow-tls.tmp" ]; then
        echo -e "${RED}wget下载失败，错误码: $download_result${RESET}"
        
        echo -e "${YELLOW}尝试使用curl下载...${RESET}"
        curl -L -o "/tmp/shadow-tls.tmp" "$download_url"
        download_result=$?
        
        if [ $download_result -ne 0 ] || [ ! -s "/tmp/shadow-tls.tmp" ]; then
            echo -e "${RED}curl下载也失败了，错误码: $download_result${RESET}"
            echo -e "${RED}下载失败，尝试重新启动原服务...${RESET}"
            systemctl start shadowtls 2>/dev/null || systemctl start shadowtls-ss 2>/dev/null
            
            echo -e "${YELLOW}尝试直接下载查看错误信息...${RESET}"
            wget "$download_url"
            
            return 1
        fi
    fi
    
    echo -e "${GREEN}下载成功，检查文件...${RESET}"
    
    # 检查文件是否为二进制可执行文件
    file_type=$(file "/tmp/shadow-tls.tmp" | grep -i executable)
    if [ -z "$file_type" ]; then
        echo -e "${RED}下载的文件不是可执行文件!${RESET}"
        echo -e "${YELLOW}文件信息: $(file "/tmp/shadow-tls.tmp")${RESET}"
        echo -e "${YELLOW}文件内容预览:${RESET}"
        head -n 20 "/tmp/shadow-tls.tmp"
        
        echo -e "${RED}下载失败，尝试重新启动原服务...${RESET}"
        systemctl start shadowtls 2>/dev/null || systemctl start shadowtls-ss 2>/dev/null
        return 1
    fi
    
    # 备份旧版本
    mv "$INSTALL_DIR/shadow-tls" "$INSTALL_DIR/shadow-tls.old"
    
    # 安装新版本
    mv "/tmp/shadow-tls.tmp" "$INSTALL_DIR/shadow-tls"
    chmod +x "$INSTALL_DIR/shadow-tls"
    
    # 启动服务
    echo -e "${CYAN}启动 ShadowTLS 服务...${RESET}"
    systemctl start shadowtls 2>/dev/null || systemctl start shadowtls-ss 2>/dev/null
    
    # 检查服务状态
    if systemctl is-active --quiet shadowtls 2>/dev/null || systemctl is-active --quiet shadowtls-ss 2>/dev/null; then
        echo -e "${GREEN}ShadowTLS 已成功升级到 v${latest_version} 并重新启动${RESET}"
        rm -f "$INSTALL_DIR/shadow-tls.old"
    else
        echo -e "${RED}升级后服务启动失败，正在回滚...${RESET}"
        mv "$INSTALL_DIR/shadow-tls.old" "$INSTALL_DIR/shadow-tls"
        systemctl start shadowtls 2>/dev/null || systemctl start shadowtls-ss 2>/dev/null
        echo -e "${YELLOW}已回滚到之前版本${RESET}"
    fi
}

# 主菜单
main_menu() {
    while true; do
        clear
        local status="未安装"
        local version="未知"
        local is_installed=false
        
        # 检查ShadowTLS运行状态
        if [ -f "$INSTALL_DIR/shadow-tls" ]; then
            is_installed=true
            version=$($INSTALL_DIR/shadow-tls --version 2>&1 | grep -oP 'shadow-tls \K[0-9.]+' || echo "未知")
            
            if systemctl is-active --quiet shadowtls 2>/dev/null || systemctl is-active --quiet shadowtls-ss 2>/dev/null; then
                status="${LIGHT_GREEN}已安装且运行中${RESET}"
            else
                status="${YELLOW}已安装但未运行${RESET}"
            fi
        else
            status="${RED}未安装${RESET}"
        fi
        
        echo -e "\n ${LIGHT_CYAN}═════════════ ${WHITE}ShadowTLS V3 管理脚本${RESET} ${LIGHT_GREEN}v1.1.0${RESET} ${LIGHT_CYAN}═════════════${RESET}"
        echo -e ""
        echo -e " ${MAGENTA}●${RESET} 当前状态: $status"
        
        # 仅当已安装时才显示版本信息
        if [ "$is_installed" = true ]; then
            if [ "$version" = "未知" ]; then
                echo -e " ${MAGENTA}●${RESET} 当前版本: ${YELLOW}未知${RESET}"
            else
                echo -e " ${MAGENTA}●${RESET} 当前版本: ${LIGHT_GREEN}v$version${RESET}"
            fi
        fi
        
        echo -e ""
        echo -e " ${WHITE}───────────────── 功能选项 ─────────────────${RESET}"
        echo -e " ${LIGHT_GREEN}1.${RESET} ${CYAN}安装 ShadowTLS${RESET}"
        echo -e " ${LIGHT_GREEN}2.${RESET} ${CYAN}卸载 ShadowTLS${RESET}"
        echo -e " ${LIGHT_GREEN}3.${RESET} ${CYAN}查看配置${RESET}"
        echo -e " ${LIGHT_GREEN}4.${RESET} ${CYAN}查看运行状态${RESET}"
        echo -e " ${LIGHT_GREEN}5.${RESET} ${CYAN}升级 ShadowTLS${RESET}"
        echo -e " ${LIGHT_GREEN}6.${RESET} ${CYAN}设置定时重启${RESET}"
        echo -e " ${LIGHT_GREEN}0.${RESET} ${CYAN}退出脚本${RESET}"
        echo -e " ${LIGHT_CYAN}═════════════════════════════════════════════${RESET}"
        
        echo -en " 请输入选项 [0-6]: "
        read -r choice
        
        case "$choice" in
            1)
                install_shadowtls
                read -rp "按任意键继续..." -n 1
                ;;
            2)
                uninstall_shadowtls
                read -rp "按任意键继续..." -n 1
                ;;
            3)
                view_config
                read -rp "按任意键继续..." -n 1
                ;;
            4)
                show_service_status
                read -rp "按任意键继续..." -n 1
                ;;
            5)
                upgrade_shadowtls
                read -rp "按任意键继续..." -n 1
                ;;
            6)
                schedule_restart
                read -rp "按任意键继续..." -n 1
                ;;
            0)
                clear
                echo -e "${LIGHT_GREEN}感谢使用 ShadowTLS 管理脚本，再见！${RESET}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请重试${RESET}"
                sleep 1
                ;;
        esac
    done
}

# 检查root权限
check_root

# 如果直接运行此脚本，则显示主菜单
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_menu
fi
