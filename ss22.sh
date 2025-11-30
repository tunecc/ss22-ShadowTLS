#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 启用管道错误检测
set -o pipefail

sh_ver="1.7.4"
filepath=$(cd "$(dirname "$0")" || exit; pwd)

# 使用 readonly 保护常量
readonly FOLDER="/etc/ss-rust"
readonly FILE="/usr/local/bin/ss-rust"
readonly CONF="/etc/ss-rust/config. json"
readonly Now_ver_File="/etc/ss-rust/ver. txt"
readonly BACKUP_DIR="/etc/ss-rust/backups"
readonly LOG_FILE="/var/log/ss-rust-manager.log"

# 颜色定义
readonly Green_font_prefix="\033[32m"
readonly Red_font_prefix="\033[31m"
readonly Green_background_prefix="\033[42;37m"
readonly Red_background_prefix="\033[41;37m"
readonly Font_color_suffix="\033[0m"
readonly Yellow_font_prefix="\033[0;33m"
readonly Cyan_font_prefix="\033[36m"
readonly Blue_font_prefix="\033[34m"
readonly Purple_background_prefix="\033[45;37m"

# 消息类型
readonly Info="${Green_font_prefix}[信息]${Font_color_suffix}"
readonly Error="${Red_font_prefix}[错误]${Font_color_suffix}"
readonly Tip="${Yellow_font_prefix}[注意]${Font_color_suffix}"
readonly Warning="${Yellow_font_prefix}[警告]${Font_color_suffix}"

# 加密方式数组
declare -A CIPHERS=(
    [1]="aes-128-gcm"
    [2]="aes-256-gcm"
    [3]="chacha20-ietf-poly1305"
    [4]="plain"
    [5]="none"
    [6]="table"
    [7]="aes-128-cfb"
    [8]="aes-256-cfb"
    [9]="aes-256-ctr"
    [10]="camellia-256-cfb"
    [11]="rc4-md5"
    [12]="chacha20-ietf"
    [13]="2022-blake3-aes-128-gcm"
    [14]="2022-blake3-aes-256-gcm"
    [15]="2022-blake3-chacha20-poly1305"
    [16]="2022-blake3-chacha8-poly1305"
)

# 清理函数
cleanup() {
    local exit_code=$? 
    rm -f /tmp/config. json.tmp 2>/dev/null
    rm -f /tmp/config.json 2>/dev/null
    rm -f /tmp/ss-rust-download.* 2>/dev/null
    exit $exit_code
}
trap cleanup EXIT

# 日志记录函数
write_log() {
    local level=$1
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null
}

# 统一日志输出函数
log_info()    { echo -e "${Info} $*"; write_log "INFO" "$*"; }
log_error()   { echo -e "${Error} $*"; write_log "ERROR" "$*"; }
log_warning() { echo -e "${Warning} $*"; write_log "WARN" "$*"; }
log_tip()     { echo -e "${Tip} $*"; }

# 确认提示函数
confirm() {
    local prompt="${1:-确认操作? }"
    local default="${2:-n}"
    local response
    
    if [[ "$default" == "y" ]]; then
        read -e -p "$prompt [Y/n]: " response
        [[ -z "$response" || "$response" =~ ^[Yy] ]]
    else
        read -e -p "$prompt [y/N]: " response
        [[ "$response" =~ ^[Yy] ]]
    fi
}

# 端口验证函数
validate_port() {
    local port=$1
    if !  [[ "$port" =~ ^[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
        return 1
    fi
    return 0
}

# 服务状态管理函数
ensure_service_running() {
    local service_name=$1
    local action=$2
    
    systemctl "$action" "$service_name"
    sleep 1
    
    local status
    status=$(systemctl is-active "$service_name" 2>/dev/null)
    case "$action" in
        start|restart)
            [[ "$status" == "active" ]] && return 0 || return 1
            ;;
        stop)
            [[ "$status" != "active" ]] && return 0 || return 1
            ;;
    esac
}

# 带重试的下载函数
download_with_retry() {
    local url=$1
    local output=$2
    local max_retries=${3:-3}
    local retry=0
    
    while [[ $retry -lt $max_retries ]]; do
        if wget --no-check-certificate -q --show-progress -O "$output" "$url" 2>/dev/null || \
           wget --no-check-certificate -N "$url" -O "$output" 2>/dev/null; then
            [[ -f "$output" && -s "$output" ]] && return 0
        fi
        ((retry++))
        log_warning "下载失败，正在重试 ($retry/$max_retries)..."
        sleep 2
    done
    return 1
}

# 显示进度条函数（优化版）
show_progress() {
    local duration=$1
    local width=50
    local delay
    delay=$(awk "BEGIN {printf \"%.3f\", $duration / $width}")
    
    printf "["
    for ((i=0; i<width; i++)); do
        printf "#"
        sleep "$delay"
    done
    printf "]\n"
}

# 检查是否为ROOT用户
check_root(){
    if [[ $EUID != 0 ]]; then
        log_error "当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。"
        exit 1
    fi
}

# 检测系统类型
check_sys(){
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif grep -q -E -i "debian" /etc/issue 2>/dev/null; then
        release="debian"
    elif grep -q -E -i "ubuntu" /etc/issue 2>/dev/null; then
        release="ubuntu"
    elif grep -q -E -i "centos|red hat|redhat" /etc/issue 2>/dev/null; then
        release="centos"
    elif grep -q -E -i "debian" /proc/version 2>/dev/null; then
        release="debian"
    elif grep -q -E -i "ubuntu" /proc/version 2>/dev/null; then
        release="ubuntu"
    elif grep -q -E -i "centos|red hat|redhat" /proc/version 2>/dev/null; then
        release="centos"
    else
        log_error "未能识别系统类型，请联系脚本作者！"
        exit 1
    fi
}

# 检测系统架构
sysArch() {
    local uname
    uname=$(uname -m)
    log_info "正在检测系统架构，当前 uname: ${uname}"
    
    case "$uname" in
        i386|i686)
            arch="i686"
            target_triple="i686-unknown-linux-gnu"
            ;;
        x86_64|amd64)
            arch="x86_64"
            target_triple="x86_64-unknown-linux-gnu"
            ;;
        aarch64|armv8)
            arch="aarch64"
            target_triple="aarch64-unknown-linux-gnu"
            ;;
        armv7*)
            arch="armv7"
            if grep -q "gnueabihf" /proc/cpuinfo 2>/dev/null || [[ -f /lib/arm-linux-gnueabihf/libc.so.6 ]]; then
                target_triple="armv7-unknown-linux-gnueabihf"
            else
                target_triple="arm-unknown-linux-gnueabi"
            fi
            ;;
        arm*)
            arch="arm"
            target_triple="arm-unknown-linux-gnueabi"
            ;;
        *)
            log_error "不支持的系统架构: ${uname}"
            exit 1
            ;;
    esac
    log_info "架构检测结果: ${Green_font_prefix}${target_triple}${Font_color_suffix}"
}

# 检查是否已安装
check_installed_status(){
    if [[ !  -e ${FILE} ]]; then
        log_error "Shadowsocks Rust 没有安装，请检查！"
        Before_Start_Menu
    fi
}

# 检查服务状态
check_status(){
    status=$(systemctl status ss-rust 2>/dev/null | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    [[ -z "$status" ]] && status="unknown"
}

# 检查端口占用
check_port_occupied(){
    local port=$1
    local occupied
    occupied=$(lsof -i:"${port}" -t 2>/dev/null)
    [[ -n "$occupied" ]]
}

# 检查配置文件权限
check_config_permissions() {
    if [[ -f "${CONF}" ]]; then
        local perms
        perms=$(stat -c %a "${CONF}" 2>/dev/null)
        if [[ "$perms" != "600" ]]; then
            chmod 600 "${CONF}"
            log_info "已修复配置文件权限为 600"
        fi
    fi
}

# 验证配置文件JSON格式
validate_config() {
    if [[ ! -f "${CONF}" ]]; then
        return 1
    fi
    if ! jq empty "${CONF}" 2>/dev/null; then
        log_error "配置文件 JSON 格式无效！"
        return 1
    fi
    return 0
}

# 备份配置文件
backup_config() {
    mkdir -p "$BACKUP_DIR"
    local backup_file="${BACKUP_DIR}/config_$(date +%Y%m%d_%H%M%S).json"
    
    if [[ -f "${CONF}" ]]; then
        cp "${CONF}" "$backup_file"
        # 保留最近 5 个备份
        ls -t "${BACKUP_DIR}"/config_*. json 2>/dev/null | tail -n +6 | xargs -r rm -f
        log_info "配置已备份到: $backup_file"
    fi
}

# 获取最新版本
check_new_ver(){
    log_info "正在检查最新版本..."
    new_ver=$(wget -qO- --no-check-certificate https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases 2>/dev/null | jq -r '[.[] | select(.prerelease == false) | select(.draft == false) | .tag_name] | .[0]' 2>/dev/null)
    
    if [[ -z ${new_ver} ]]; then
        log_error "获取 Shadowsocks Rust 最新版本失败！"
        if confirm "是否继续使用默认版本安装？" "y"; then
            new_ver="v1.18.4"
            log_info "将使用默认版本 ${new_ver} 继续安装"
        else
            log_info "已取消安装"
            exit 1
        fi
    else
        log_info "检测到 Shadowsocks Rust 最新版本为 ${Green_font_prefix}${new_ver}${Font_color_suffix}"
    fi
}

# 比较版本
check_ver_comparison(){
    local now_ver
    now_ver=$(cat ${Now_ver_File} 2>/dev/null)
    
    if [[ "${now_ver}" != "${new_ver}" ]]; then
        log_info "发现 Shadowsocks Rust 已有新版本 ${Green_font_prefix}${new_ver}${Font_color_suffix}，旧版本 ${Red_font_prefix}${now_ver}${Font_color_suffix}"
        
        if confirm "是否更新？" "y"; then
            check_status
            backup_config
            \cp "${CONF}" "/tmp/config.json"
            
            if Download; then
                mv -f "/tmp/config.json" "${CONF}"
                chmod 600 "${CONF}"
                log_info "配置文件已恢复"
                Restart
            else
                log_error "更新失败，将恢复配置文件"
                if [[ -f "/tmp/config.json" ]]; then
                    mv -f "/tmp/config.json" "${CONF}"
                    log_info "已从临时备份恢复配置"
                fi
            fi
        fi
    else
        log_info "当前 Shadowsocks Rust 已是最新版本 ${Green_font_prefix}${new_ver}${Font_color_suffix} ！"
        exit 1
    fi
}

# 官方源下载
stable_Download() {
    log_info "开始下载官方源 Shadowsocks Rust..."
    
    local filename="shadowsocks-${new_ver}.${target_triple}.tar.xz"
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${new_ver}/${filename}"
    
    log_info "下载地址: ${download_url}"
    
    if !  download_with_retry "$download_url" "$filename" 3; then
        log_error "Shadowsocks Rust 官方源下载失败！"
        return 1
    fi
    
    if [[ !  -e "${filename}" ]]; then
        log_error "下载文件不存在！"
        return 1
    fi
    
    log_info "下载成功，开始解压..."
    if ! tar -xJf "${filename}"; then
        log_error "Shadowsocks Rust 解压失败！"
        rm -f "${filename}"
        return 1
    fi
    
    if [[ !  -e "ssserver" ]]; then
        log_error "解压后未找到 ssserver 文件！"
        rm -f "${filename}"
        return 1
    fi
    
    log_info "解压成功，开始安装..."
    rm -rf "${filename}"
    chmod +x ssserver
    mv -f ssserver "${FILE}"
    rm -f sslocal ssmanager ssservice ssurl 2>/dev/null
    echo "${new_ver}" > ${Now_ver_File}
    log_info "Shadowsocks Rust 主程序安装完成！"
    return 0
}

# 备用源下载
backup_Download() {
    log_info "尝试使用备份源下载（旧版本）Shadowsocks Rust..."
    local backup_ver="v1.18.4"
    
    local filename="shadowsocks-${backup_ver}.${target_triple}. tar.xz"
    local backup_url="https://gh-proxy.com/https://github.com/shadowsocks/shadowsocks-rust/releases/download/${backup_ver}/${filename}"
    
    if [[ ! -e "${filename}" ]]; then
        if ! download_with_retry "$backup_url" "$filename" 3; then
            log_error "从备份源下载 Shadowsocks Rust 失败！"
            return 1
        fi
    fi
    
    if !  tar -xJf "${filename}"; then
        log_error "备份源 Shadowsocks Rust 解压失败！"
        rm -f "${filename}"
        return 1
    fi
    
    if [[ ! -e "ssserver" ]]; then
        log_error "解压后未找到 ssserver 文件！"
        rm -f "${filename}"
        return 1
    fi
    
    rm -rf "${filename}"
    chmod +x ssserver
    mv -f ssserver "${FILE}"
    rm -f sslocal ssmanager ssservice ssurl 2>/dev/null
    echo "${backup_ver}" > ${Now_ver_File}
    log_info "备份源 Shadowsocks Rust 主程序安装完成！"
    return 0
}

# 整合下载功能
Download() {
    if [[ !  -d "${FOLDER}" ]]; then
        if !  mkdir -p "${FOLDER}"; then
            log_error "创建文件夹 ${FOLDER} 失败，请检查权限！"
            exit 1
        fi
        log_info "创建目录 ${FOLDER} 成功"
    fi
    
    if stable_Download; then
        return 0
    fi
    
    log_warning "官方源下载失败，尝试备用源..."
    if backup_Download; then
        return 0
    fi
    
    log_error "所有下载源均失败，无法继续安装！"
    return 1
}

# 创建服务
Service(){
    local virt_type
    virt_type="$(systemd-detect-virt 2>/dev/null || echo "unknown")"
    log_info "检测到虚拟化类型: ${Green_font_prefix}${virt_type}${Font_color_suffix}"
    
    local service_content='[Unit]
Description=Shadowsocks Rust Service
Documentation=https://github.com/shadowsocks/shadowsocks-rust
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
LimitNOFILE=1048576
Type=simple
User=root
Restart=on-failure
RestartSec=5s'
    
    if [[ "$virt_type" == "kvm" ]]; then
        service_content+='
ExecStartPre=/bin/sh -c '\''ulimit -n 51200'\'''
        log_info "检测到KVM虚拟化环境，已添加 ExecStartPre 配置以提高性能"
    else
        log_info "检测到${virt_type}虚拟化环境，不添加额外的性能优化配置"
    fi
    
    service_content+='
ExecStart=/usr/local/bin/ss-rust -c /etc/ss-rust/config.json
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target'
    
    log_info "正在创建系统服务..."
    echo "$service_content" > /etc/systemd/system/ss-rust.service
    
    systemctl daemon-reload
    systemctl enable ss-rust
    
    log_info "Shadowsocks Rust 服务配置完成！"
}

# 安装依赖
Installation_dependency(){
    log_info "正在安装/更新必要组件..."
    
    local packages_to_install=""
    local check_commands=("jq" "wget" "curl" "openssl" "lsof" "tar")
    
    for cmd in "${check_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            case $cmd in
                "jq"|"wget"|"curl"|"openssl"|"lsof"|"tar")
                    packages_to_install+=" $cmd"
                    ;;
            esac
        fi
    done
    
    if [[ -n $packages_to_install ]]; then
        log_info "检测到缺少以下组件:${Green_font_prefix}${packages_to_install}${Font_color_suffix}"
        
        if [[ ${release} == "centos" ]]; then
            log_info "更新并安装组件中..."
            yum update -y
            # shellcheck disable=SC2086
            yum install -y $packages_to_install xz unzip gzip
        else
            log_info "更新并安装组件中..."
            apt-get update
            # shellcheck disable=SC2086
            apt-get install -y $packages_to_install xz-utils unzip gzip
        fi
        
        if [[ $? -ne 0 ]]; then
            log_error "安装组件失败，请手动安装后重试！"
            exit 1
        fi
    else
        log_info "所需组件已安装，跳过安装步骤"
    fi
    
    log_info "正在设置系统时区为 Asia/Shanghai..."
    if [[ -f "/usr/share/zoneinfo/Asia/Shanghai" ]]; then
        ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
        echo "Asia/Shanghai" > /etc/timezone
        log_info "时区设置完成"
    else
        log_warning "时区文件不存在，跳过设置"
    fi
}

# 写入配置文件
Write_config(){
    log_info "正在生成配置文件..."
    
    local dns_config=""
    if [[ -n "${dns}" ]]; then
        dns_config=",
    \"nameserver\": \"${dns}\""
    fi
    
    cat > "${CONF}" <<-EOF
{
    "server": "::",
    "server_port": ${port},
    "password": "${password}",
    "method": "${cipher}",
    "fast_open": ${tfo},
    "mode": "tcp_and_udp",
    "user": "nobody",
    "timeout": 300,
    "ecn": ${ecn}${dns_config}
}
EOF
    
    chmod 600 "${CONF}"
    
    if !  validate_config; then
        log_error "生成的配置文件格式无效，请检查！"
        return 1
    fi
    
    log_info "配置文件已生成并设置适当权限"
    return 0
}

# 读取配置文件（优化版）
Read_config(){
    if [[ !  -e ${CONF} ]]; then
        log_error "Shadowsocks Rust 配置文件不存在！"
        return 1
    fi
    
    if ! validate_config; then
        return 1
    fi
    
    # 一次性读取所有配置
    port=$(jq -r '.server_port' "${CONF}")
    password=$(jq -r '.password' "${CONF}")
    cipher=$(jq -r '. method' "${CONF}")
    tfo=$(jq -r '. fast_open' "${CONF}")
    dns=$(jq -r '.nameserver // empty' "${CONF}")
    ecn=$(jq -r '. ecn // false' "${CONF}")
    
    return 0
}

# 设置端口
Set_port(){
    while true; do
        log_tip "脚本稍后将尝试自动配置防火墙开放此端口。"
        echo -e "请输入 Shadowsocks Rust 端口 [1-65535]"
        read -e -p "(回车随机生成)：" port
        
        if [[ -z "${port}" ]]; then
            while true; do
                port=$(shuf -i 9000-19999 -n 1)
                check_port_occupied "$port" || break
            done
            log_info "已随机生成端口: ${Green_font_prefix}${port}${Font_color_suffix}"
        else
            if !  validate_port "$port"; then
                log_error "请输入有效的端口号 (1-65535)!"
                continue
            fi
            
            if check_port_occupied "$port"; then
                log_error "端口 ${port} 已被占用，请更换其他端口!"
                continue
            fi
        fi
        
        echo && echo "=================================="
        echo -e "端口: ${Red_background_prefix} ${port} ${Font_color_suffix}"
        echo "==================================" && echo
        break
    done
}

# 配置防火墙
Config_Firewall(){
    local port_to_open=$1
    log_info "正在检查并配置防火墙..."
    
    # 检查 UFW
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -qw active; then
            log_info "检测到 UFW 防火墙，正在添加规则..."
            ufw allow "${port_to_open}/tcp"
            ufw allow "${port_to_open}/udp"
            log_info "UFW: 已放行端口 ${port_to_open}"
        fi
    fi
    
    # 检查 Firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null | grep -q running; then
            log_info "检测到 Firewalld 防火墙，正在添加规则..."
            firewall-cmd --zone=public --add-port="${port_to_open}/tcp" --permanent
            firewall-cmd --zone=public --add-port="${port_to_open}/udp" --permanent
            firewall-cmd --reload
            log_info "Firewalld: 已放行端口 ${port_to_open}"
        fi
    fi

    # 检查 iptables
    if command -v iptables >/dev/null 2>&1; then
        if !  command -v ufw >/dev/null 2>&1 && ! command -v firewall-cmd >/dev/null 2>&1; then
            log_info "检测到 iptables，正在添加规则..."
            if !  iptables -C INPUT -p tcp --dport "${port_to_open}" -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -p tcp --dport "${port_to_open}" -j ACCEPT
            fi
            if ! iptables -C INPUT -p udp --dport "${port_to_open}" -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -p udp --dport "${port_to_open}" -j ACCEPT
            fi
            
            if [[ -f /etc/redhat-release ]]; then
                service iptables save 2>/dev/null || /usr/libexec/iptables/iptables.init save 2>/dev/null
            else
                iptables-save > /etc/iptables. rules 2>/dev/null
                log_warning "Debian/Ubuntu 系统提示：如未使用 UFW，建议安装 iptables-persistent 以确保重启后规则不丢失。"
            fi
            log_info "iptables: 已放行端口 ${port_to_open}"
        fi
    fi
}

# 设置TCP Fast Open
Set_tfo(){
    echo -e "是否开启 TCP Fast Open ？"
    log_tip "开启此选项仅修改 Shadowsocks 配置，不会自动修改系统参数"
    
    local tfo_available=false
    if [[ -f /proc/sys/net/ipv4/tcp_fastopen ]]; then
        local tfo_status
        tfo_status=$(cat /proc/sys/net/ipv4/tcp_fastopen)
        if [[ $tfo_status -gt 0 ]]; then
            tfo_available=true
            log_info "系统已启用 TCP Fast Open，状态值: ${tfo_status}"
        else
            log_warning "系统未启用 TCP Fast Open，如需完全启用，请手动执行: echo 3 > /proc/sys/net/ipv4/tcp_fastopen"
        fi
    else
        log_warning "系统不支持 TCP Fast Open"
    fi
    
    echo "=================================="
    echo -e " ${Green_font_prefix}1. ${Font_color_suffix} 启用"
    echo -e " ${Green_font_prefix}2.${Font_color_suffix} 禁用 (默认)"
    echo "=================================="
    
    read -e -p "(默认: 2): " tfo_choice
    [[ -z "${tfo_choice}" ]] && tfo_choice="2"

    if [[ ${tfo_choice} == "1" ]]; then
        tfo=true
        if [[ "$tfo_available" == "false" ]]; then
            log_info "正在尝试自动开启系统 TCP Fast Open..."
            echo 3 > /proc/sys/net/ipv4/tcp_fastopen
            if !  grep -q "net.ipv4.tcp_fastopen" /etc/sysctl.conf; then
                echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
                log_info "已将 TFO 参数写入 /etc/sysctl.conf"
            fi
        fi
    else
        tfo=false
    fi
    
    echo && echo "=================================="
    echo -e "TCP Fast Open: ${Red_background_prefix} ${tfo} ${Font_color_suffix}"
    echo "==================================" && echo
}

# 设置加密方式
Set_method() {
    echo -e "请选择 Shadowsocks Rust 加密方式"
    echo "=================================="
    echo -e " ${Green_font_prefix} 1.${Font_color_suffix} aes-128-gcm"
    echo -e " ${Green_font_prefix} 2.${Font_color_suffix} aes-256-gcm"
    echo -e " ${Green_font_prefix} 3.${Font_color_suffix} chacha20-ietf-poly1305"
    echo -e " ${Green_font_prefix} 4.${Font_color_suffix} plain ${Red_font_prefix}(不推荐)${Font_color_suffix}"
    echo -e " ${Green_font_prefix} 5.${Font_color_suffix} none ${Red_font_prefix}(不推荐)${Font_color_suffix}"
    echo -e " ${Green_font_prefix} 6.${Font_color_suffix} table"
    echo -e " ${Green_font_prefix} 7.${Font_color_suffix} aes-128-cfb"
    echo -e " ${Green_font_prefix} 8.${Font_color_suffix} aes-256-cfb"
    echo -e " ${Green_font_prefix} 9.${Font_color_suffix} aes-256-ctr"
    echo -e " ${Green_font_prefix}10.${Font_color_suffix} camellia-256-cfb"
    echo -e " ${Green_font_prefix}11.${Font_color_suffix} rc4-md5"
    echo -e " ${Green_font_prefix}12.${Font_color_suffix} chacha20-ietf"
    echo "=================================="
    log_tip "AEAD 2022 加密（须v1.15.0及以上版本且密码须经过Base64加密）"
    echo "=================================="
    echo -e " ${Green_font_prefix}13.${Font_color_suffix} 2022-blake3-aes-128-gcm ${Green_font_prefix}(推荐)${Font_color_suffix}"
    echo -e " ${Green_font_prefix}14. ${Font_color_suffix} 2022-blake3-aes-256-gcm ${Green_font_prefix}(默认推荐)${Font_color_suffix}"
    echo -e " ${Green_font_prefix}15.${Font_color_suffix} 2022-blake3-chacha20-poly1305"
    echo -e " ${Green_font_prefix}16.${Font_color_suffix} 2022-blake3-chacha8-poly1305"
    echo "=================================="
    
    read -e -p "(默认: 14.  2022-blake3-aes-256-gcm): " method_choice
    [[ -z "${method_choice}" ]] && method_choice="14"
    
    cipher="${CIPHERS[$method_choice]:-2022-blake3-aes-256-gcm}"
    
    echo && echo "=================================="
    echo -e "加密: ${Red_background_prefix} ${cipher} ${Font_color_suffix}"
    echo "==================================" && echo
}

# 设置密码
Set_password() {
    echo "请输入 Shadowsocks Rust 密码 [0-9][a-z][A-Z]"
    read -e -p "(回车随机生成): " password
    
    if [[ -z "${password}" ]]; then
        case "${cipher}" in
            "2022-blake3-aes-128-gcm")
                password=$(openssl rand -base64 16)
                ;;
            "2022-blake3-aes-256-gcm"|"2022-blake3-chacha20-poly1305"|"2022-blake3-chacha8-poly1305")
                password=$(openssl rand -base64 32)
                local retry_count=0
                while [[ ${#password} -ne 44 && $retry_count -lt 10 ]]; do
                    password=$(openssl rand -base64 32)
                    ((retry_count++))
                done
                ;;
            *)
                password=$(openssl rand -base64 16)
                ;;
        esac
        log_info "已随机生成密码"
    fi
    
    if [[ "${cipher}" =~ "2022-blake3" ]]; then
        local required_bytes=32
        [[ "${cipher}" == "2022-blake3-aes-128-gcm" ]] && required_bytes=16
        
        local decoded_length
        decoded_length=$(echo -n "${password}" | base64 -d 2>/dev/null | wc -c)
        
        if [[ ${decoded_length} -ne ${required_bytes} ]]; then
            log_error "密码长度不符合要求，请重新设置密码！"
            Set_password
            return
        fi
    fi
    
    echo && echo "=================================="
    echo -e "密码: ${Red_background_prefix} ${password} ${Font_color_suffix}"
    echo "==================================" && echo
}

# 设置ECN
Set_ecn(){
    echo -e "是否开启 ECN (Explicit Congestion Notification)？"
    log_tip "少数客户端（如Surge等）支持此选项"
    echo "=================================="
    echo -e " ${Green_font_prefix}1.${Font_color_suffix} 启用"
    echo -e " ${Green_font_prefix}2.${Font_color_suffix} 禁用 (默认)"
    echo "=================================="
    
    read -e -p "(默认: 2): " ecn_choice
    [[ -z "${ecn_choice}" ]] && ecn_choice="2"
    
    if [[ ${ecn_choice} == "1" ]]; then
        ecn="true"
    else
        ecn="false"
    fi
    
    echo && echo "=================================="
    echo -e "ECN 开启状态: ${Red_background_prefix} ${ecn} ${Font_color_suffix}"
    echo "==================================" && echo
}

# 设置DNS
Set_dns(){
    echo -e "请选择 DNS 配置方式:"
    echo "=================================="
    echo -e " ${Green_font_prefix}1.${Font_color_suffix} 使用系统默认 DNS ${Green_font_prefix}(推荐)${Font_color_suffix}"
    echo -e " ${Green_font_prefix}2.${Font_color_suffix} 自定义 DNS 服务器"
    echo "=================================="
    
    read -e -p "(默认: 1): " dns_choice
    [[ -z "${dns_choice}" ]] && dns_choice="1"
    
    if [[ ${dns_choice} == "2" ]]; then
        echo -e "请输入自定义 DNS 服务器地址（多个 DNS 用逗号分隔，如: 8.8.8.8,8.8.4.4）"
        read -e -p "(默认: 8.8.8.8): " dns
        [[ -z "${dns}" ]] && dns="8.8.8.8"
        
        if !  echo "$dns" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(,([0-9]{1,3}\.){3}[0-9]{1,3})*$'; then
            log_error "DNS地址格式不正确，请输入正确的IP地址格式!"
            Set_dns
            return
        fi
        
        echo && echo "=================================="
        echo -e "DNS: ${Red_background_prefix} ${dns} ${Font_color_suffix}"
        echo "==================================" && echo
    else
        dns=""
        echo && echo "=================================="
        echo -e "DNS: ${Red_background_prefix} 使用系统默认 DNS ${Font_color_suffix}"
        echo "==================================" && echo
    fi
}

# 修改配置
Set(){
    check_installed_status
    echo && echo -e "请选择要修改的配置:"
    echo "=================================="
    echo -e " ${Green_font_prefix}1.${Font_color_suffix} 修改 端口配置"
    echo -e " ${Green_font_prefix}2.${Font_color_suffix} 修改 加密配置"
    echo -e " ${Green_font_prefix}3.${Font_color_suffix} 修改 密码配置"
    echo -e " ${Green_font_prefix}4.${Font_color_suffix} 修改 TFO 配置"
    echo -e " ${Green_font_prefix}5.${Font_color_suffix} 修改 DNS 配置"
    echo -e " ${Green_font_prefix}6.${Font_color_suffix} 修改 ECN 配置"
    echo "=================================="
    echo -e " ${Green_font_prefix}7.${Font_color_suffix} 修改 全部配置"
    echo "=================================="
    
    read -e -p "(回车取消): " modify
    [[ -z "${modify}" ]] && echo "已取消..." && exit 1
    
    backup_config
    
    case "${modify}" in
        1)
            Read_config && Set_port && Write_config && Restart
            ;;
        2)
            Read_config && Set_method && Set_password && Write_config && Restart
            ;;
        3)
            Read_config && Set_password && Write_config && Restart
            ;;
        4)
            Read_config && Set_tfo && Write_config && Restart
            ;;
        5)
            Read_config && Set_dns && Write_config && Restart
            ;;
        6)
            Read_config && Set_ecn && Write_config && Restart
            ;;
        7)
            Read_config && Set_port && Set_method && Set_password && Set_tfo && Set_dns && Set_ecn && Write_config && Restart
            ;;
        *)
            log_error "请输入正确的数字 [1-7]"
            exit 1
            ;;
    esac
}

# 安装
Install(){
    if [[ -e ${FILE} ]]; then
        log_error "检测到 Shadowsocks Rust 已安装！"
        Before_Start_Menu
        return
    fi
    
    echo -e "\n${Yellow_font_prefix}===============================================${Font_color_suffix}"
    echo -e "${Green_font_prefix}开始 Shadowsocks Rust 安装...${Font_color_suffix}"
    echo -e "${Yellow_font_prefix}===============================================${Font_color_suffix}\n"
    
    write_log "INFO" "开始安装 Shadowsocks Rust"
    
    mkdir -p "${FOLDER}"
    mkdir -p "${BACKUP_DIR}"
    
    log_info "开始设置配置..."
    Set_port
    Set_method
    Set_password
    Set_tfo
    Set_dns
    Set_ecn
    
    log_info "开始安装/配置依赖..."
    Installation_dependency
    
    log_info "开始下载/安装..."
    check_new_ver
    if !  Download; then
        log_error "下载或解压失败，退出安装！"
        exit 1
    fi
    
    log_info "开始安装系统服务脚本..."
    Service
    
    log_info "开始配置防火墙..."
    Config_Firewall "${port}"
    
    log_info "开始写入配置文件..."
    Write_config
    
    log_info "所有步骤安装完毕，开始启动..."
    Start
    
    # 设置每日重启
    log_info "正在设置每日5:00自动重启..."
    local RESTART_HOUR="5"
    local RESTART_MINUTE="0"
    local JOB_LINE="${RESTART_MINUTE} ${RESTART_HOUR} * * * /usr/bin/systemctl restart ss-rust"
    local CRONTAB_CONTENT
    CRONTAB_CONTENT=$(crontab -l 2>/dev/null)
    
    if echo "${CRONTAB_CONTENT}" | grep -q "${JOB_LINE}"; then
        log_info "已存在每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的任务，无需重复添加"
    else
        (echo "${CRONTAB_CONTENT}"; echo "${JOB_LINE}") | crontab -
        log_info "已添加每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的计划任务"
    fi
    
    write_log "INFO" "安装完成，端口: $port, 加密: $cipher"
    log_info "启动完成！"
    
    echo -e "\n${Yellow_font_prefix}===============================================${Font_color_suffix}"
    echo -e "${Green_font_prefix}Shadowsocks Rust 已成功安装! ${Font_color_suffix}"
    echo -e "${Yellow_font_prefix}===============================================${Font_color_suffix}"
    echo -e "\n${Cyan_font_prefix}是否需要继续安装 ShadowTLS 进行流量混淆?  [Y/n]${Font_color_suffix}"
    
    read -r install_stls
    case "$install_stls" in
        [yY][eE][sS]|[yY]|"")
            echo -e "${Green_font_prefix}正在准备安装 ShadowTLS... ${Font_color_suffix}"
            install_shadowtls
            ;;
        *)
            echo -e "${Yellow_font_prefix}已跳过 ShadowTLS 安装，如需安装请稍后在菜单中选择安装选项${Font_color_suffix}"
            log_info "显示当前配置信息..."
            View
            ;;
    esac
    
    echo -e "\n${Green_font_prefix}安装过程已完成! ${Font_color_suffix}"
    sleep 1s
    Before_Start_Menu
}

# 启动
Start(){
    check_installed_status
    check_status
    
    if [[ "$status" == "running" ]]; then
        log_info "Shadowsocks Rust 已在运行！"
    else
        log_info "启动 Shadowsocks Rust 服务..."
        
        if ensure_service_running ss-rust start; then
            log_info "Shadowsocks Rust 启动${Green_font_prefix}成功${Font_color_suffix}！"
            write_log "INFO" "服务启动成功"
        else
            log_error "Shadowsocks Rust 启动${Red_font_prefix}失败${Font_color_suffix}！"
            log_info "可能是配置错误导致，请检查配置文件或日志: journalctl -u ss-rust"
            write_log "ERROR" "服务启动失败"
            exit 1
        fi
    fi
}

# 停止
Stop(){
    check_installed_status
    check_status
    
    if [[ "$status" != "running" ]]; then
        log_error "Shadowsocks Rust 未在运行，无需停止！"
        exit 1
    fi
    
    log_info "正在停止 Shadowsocks Rust 服务..."
    
    if ensure_service_running ss-rust stop; then
        log_info "Shadowsocks Rust 已停止运行！"
        write_log "INFO" "服务已停止"
    else
        log_error "Shadowsocks Rust 停止失败，请检查日志: journalctl -u ss-rust"
        write_log "ERROR" "服务停止失败"
        exit 1
    fi
    Start_Menu
}

# 重启
Restart(){
    check_installed_status
    log_info "正在重启 Shadowsocks Rust 服务..."
    
    if ensure_service_running ss-rust restart; then
        log_info "Shadowsocks Rust 重启${Green_font_prefix}成功${Font_color_suffix}！"
        write_log "INFO" "服务重启成功"
    else
        log_error "Shadowsocks Rust 重启${Red_font_prefix}失败${Font_color_suffix}！"
        log_info "可能是配置错误导致，请检查配置文件或日志: journalctl -u ss-rust"
        write_log "ERROR" "服务重启失败"
    fi
    sleep 1s
    Start_Menu
}

# 更新
Update(){
    check_installed_status
    check_new_ver
    check_ver_comparison
    log_info "Shadowsocks Rust 更新完毕！"
    sleep 1s
    Start_Menu
}

# 卸载
Uninstall(){
    check_installed_status
    
    if !  confirm "确定要卸载 Shadowsocks Rust ?" "y"; then
        echo && echo "卸载已取消..." && echo
        sleep 2s
        Start_Menu
        return
    fi
    
    write_log "INFO" "开始卸载 Shadowsocks Rust"
    
    check_status
    [[ "$status" == "running" ]] && systemctl stop ss-rust
    systemctl disable ss-rust
    
    rm -rf "${FOLDER}"
    rm -f "${FILE}" "/etc/systemd/system/ss-rust.service"
    
    systemctl daemon-reload
    
    log_info "正在检查并删除定时重启任务..."
    local crontab_content
    crontab_content=$(crontab -l 2>/dev/null)
    if echo "${crontab_content}" | grep -q "systemctl restart ss-rust"; then
        echo "${crontab_content}" | grep -v "systemctl restart ss-rust" | crontab -
        log_info "已删除 Shadowsocks Rust 的定时重启任务"
    fi
    
    write_log "INFO" "Shadowsocks Rust 卸载完成"
    log_info "Shadowsocks Rust 卸载完成！"
    
    if [[ -f "/usr/local/bin/shadow-tls" ]] && systemctl is-enabled shadowtls &>/dev/null; then
        echo -e "\n${Yellow_font_prefix}===============================================${Font_color_suffix}"
        echo -e "${Cyan_font_prefix}检测到系统中已安装 ShadowTLS，是否需要一并卸载?  [Y/n]${Font_color_suffix}"
        read -r uninstall_stls
        case "$uninstall_stls" in
            [yY][eE][sS]|[yY]|"")
                echo -e "${Yellow_font_prefix}===============================================${Font_color_suffix}"
                uninstall_shadowtls
                ;;
            *)
                echo -e "${Yellow_font_prefix}已跳过 ShadowTLS 卸载。${Font_color_suffix}"
                ;;
        esac
    else
        echo -e "\n${Yellow_font_prefix}系统中未检测到 ShadowTLS 安装，跳过卸载步骤。${Font_color_suffix}"
    fi
    
    sleep 2s
    Start_Menu
}

# 卸载ShadowTLS
uninstall_shadowtls() {
    echo -e "${Cyan_font_prefix}正在卸载 ShadowTLS...${Font_color_suffix}"
    
    if !  confirm "确认要卸载 ShadowTLS?" "y"; then
        echo -e "${Yellow_font_prefix}已取消卸载操作${Font_color_suffix}"
        return 0
    fi
    
    echo -e "${Green_font_prefix}开始卸载... ${Font_color_suffix}"
    
    echo -e "${Cyan_font_prefix}停止并移除服务...${Font_color_suffix}"
    systemctl stop shadowtls &>/dev/null
    systemctl disable shadowtls &>/dev/null
    
    rm -f "/etc/systemd/system/shadowtls.service"
    
    echo -e "${Cyan_font_prefix}删除 ShadowTLS 程序文件...${Font_color_suffix}"
    rm -f "/usr/local/bin/shadow-tls"
    
    echo -e "${Cyan_font_prefix}删除配置文件...${Font_color_suffix}"
    if [[ -d "/etc/shadowtls" ]]; then
        rm -rf "/etc/shadowtls"
        echo -e "${Green_font_prefix}已删除配置目录${Font_color_suffix}"
    fi
    
    echo -e "${Cyan_font_prefix}检查并删除定时重启任务...${Font_color_suffix}"
    if crontab -l 2>/dev/null | grep -q "systemctl restart shadowtls"; then
        crontab -l 2>/dev/null | grep -v "systemctl restart shadowtls" | crontab -
        echo -e "${Green_font_prefix}已删除定时重启任务${Font_color_suffix}"
    fi
    
    systemctl daemon-reload
    echo -e "${Green_font_prefix}ShadowTLS 已成功卸载${Font_color_suffix}"
}

# 获取IPv4地址
getipv4(){
    log_info "正在获取公网IPv4地址..."
    local success=false
    local ip_services=("api.ipify.org" "ifconfig.me" "ip.sb")
    
    for ip_service in "${ip_services[@]}"; do
        echo -e "  尝试从 ${ip_service} 获取..."
        ipv4=$(curl -s4 --connect-timeout 3 "https://${ip_service}" 2>/dev/null)
        
        if [[ -n "${ipv4}" && "${ipv4}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "  ${Green_font_prefix}成功${Font_color_suffix} 获取到IPv4地址: ${ipv4}"
            success=true
            break
        else
            echo -e "  ${Yellow_font_prefix}失败${Font_color_suffix} 无法从 ${ip_service} 获取有效IPv4地址"
        fi
    done
    
    if [[ "$success" != "true" ]]; then
        log_error "所有IPv4地址获取服务均失败"
        ipv4="IPv4_Error"
    fi
}

# 获取IPv6地址
getipv6(){
    log_info "正在获取公网IPv6地址..."
    local success=false
    local ip_services=("api64.ipify.org" "ifconfig.co" "ipv6. icanhazip.com")
    
    for ip_service in "${ip_services[@]}"; do
        echo -e "  尝试从 ${ip_service} 获取..."
        ipv6=$(curl -s6 --connect-timeout 3 "https://${ip_service}" 2>/dev/null)
        
        if [[ -n "${ipv6}" ]]; then
            echo -e "  ${Green_font_prefix}成功${Font_color_suffix} 获取到IPv6地址: ${ipv6}"
            success=true
            break
        else
            echo -e "  ${Yellow_font_prefix}失败${Font_color_suffix} 无法从 ${ip_service} 获取有效IPv6地址"
        fi
    done
    
    if [[ "$success" != "true" ]]; then
        log_warning "所有IPv6地址获取服务均失败，您的服务器可能不支持IPv6"
        ipv6="IPv6_Error"
    fi
}

# Base64编码 (URL安全)
urlsafe_base64(){
    local data
    data=$(echo -n "$1" | base64 | sed ':a;N;s/\n/ /g;ta' | sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
    echo -e "${data}"
}

# 查看配置
View(){
    check_installed_status
    
    if !  Read_config; then
        Before_Start_Menu
        return
    fi
    
    getipv4
    getipv6
    
    echo -e "\n${Yellow_font_prefix}=== Shadowsocks Rust 配置 ===${Font_color_suffix}"
    [[ "${ipv4}" != "IPv4_Error" ]] && echo -e " IPv4 地址：${Green_font_prefix}${ipv4}${Font_color_suffix}"
    [[ "${ipv6}" != "IPv6_Error" ]] && echo -e " IPv6 地址：${Green_font_prefix}${ipv6}${Font_color_suffix}"
    echo -e " 端口：${Green_font_prefix}${port}${Font_color_suffix}"
    echo -e " 密码：${Green_font_prefix}${password}${Font_color_suffix}"
    echo -e " 加密：${Green_font_prefix}${cipher}${Font_color_suffix}"
    echo -e " TFO ：${Green_font_prefix}${tfo}${Font_color_suffix}"
    echo -e " ECN ：${Green_font_prefix}${ecn}${Font_color_suffix}"
    if [[ -n "${dns}" ]]; then
        echo -e " DNS ：${Green_font_prefix}${dns}${Font_color_suffix}"
    else
        echo -e " DNS ：${Green_font_prefix}使用系统默认${Font_color_suffix}"
    fi
    echo -e "——————————————————————————————————"

    local userinfo
    userinfo=$(echo -n "${cipher}:${password}" | base64 | tr -d '\n')
    local ss_url_ipv4=""
    local ss_url_ipv6=""
    
    [[ "${ipv4}" != "IPv4_Error" ]] && ss_url_ipv4="ss://${userinfo}@${ipv4}:${port}#ss-${ipv4}"
    [[ "${ipv6}" != "IPv6_Error" ]] && ss_url_ipv6="ss://${userinfo}@${ipv6}:${port}#ss-${ipv6}"

    local stls_listen_port=""
    local stls_password=""
    local stls_sni=""
    
    if [[ -f "/etc/systemd/system/shadowtls. service" ]]; then
        stls_listen_port=$(grep -oP '(?<=--listen \[\:\:\]\:)\d+' /etc/systemd/system/shadowtls.service 2>/dev/null)
        stls_password=$(grep -oP '(?<=--password )\S+' /etc/systemd/system/shadowtls.service 2>/dev/null)
        stls_sni=$(grep -oP '(?<=--tls )[^:]+(? =:443\b)' /etc/systemd/system/shadowtls.service 2>/dev/null)

        echo -e "\n${Yellow_font_prefix}=== ShadowTLS 配置 ===${Font_color_suffix}"
        echo -e " 监听端口：${Green_font_prefix}${stls_listen_port}${Font_color_suffix}"
        echo -e " 密码：${Green_font_prefix}${stls_password}${Font_color_suffix}"
        echo -e " SNI：${Green_font_prefix}${stls_sni}${Font_color_suffix}"
    fi

    echo -e "\n${Yellow_font_prefix}=== Shadowsocks 链接 ===${Font_color_suffix}"
    [[ -n "${ss_url_ipv4}" ]] && echo -e "${Green_font_prefix}IPv4 链接：${Font_color_suffix}${ss_url_ipv4}"
    [[ -n "${ss_url_ipv6}" ]] && echo -e "${Green_font_prefix}IPv6 链接：${Font_color_suffix}${ss_url_ipv6}"

    echo -e "\n${Yellow_font_prefix}=== Surge 配置 ===${Font_color_suffix}"
    if [[ "${ipv4}" != "IPv4_Error" ]]; then
        if [[ "${ecn}" == "true" ]]; then
            echo -e "ss-${ipv4} = ss, ${ipv4}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
        else
            echo -e "ss-${ipv4} = ss, ${ipv4}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true"
        fi
    fi
    
    if [[ "${ipv6}" != "IPv6_Error" ]]; then
        if [[ "${ecn}" == "true" ]]; then
            echo -e "ss-${ipv6} = ss, ${ipv6}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
        else
            echo -e "ss-${ipv6} = ss, ${ipv6}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true"
        fi
    fi
    
    if [[ "${ipv4}" == "IPv4_Error" && "${ipv6}" == "IPv6_Error" ]]; then
        log_error "无法获取服务器IP地址，无法生成Surge配置"
    fi

    if [[ -f "/etc/systemd/system/shadowtls.service" ]]; then
        local shadow_tls_config="{\"version\":\"3\",\"password\":\"${stls_password}\",\"host\":\"${stls_sni}\",\"port\":\"${stls_listen_port}\",\"address\":\"${ipv4}\"}"
        local shadow_tls_base64
        shadow_tls_base64=$(echo -n "${shadow_tls_config}" | base64 | tr -d '\n')
        local ss_stls_url="ss://${userinfo}@${ipv4}:${port}? shadow-tls=${shadow_tls_base64}#ss-${ipv4}"

        echo -e "\n${Yellow_font_prefix}=== SS + ShadowTLS 链接 ===${Font_color_suffix}"
        echo -e "${Green_font_prefix}合并链接：${Font_color_suffix}${ss_stls_url}"

        echo -e "\n${Yellow_font_prefix}=== Surge Shadowsocks + ShadowTLS 配置 ===${Font_color_suffix}"
        if [[ "${ipv4}" != "IPv4_Error" ]]; then
            echo -e "ss-${ipv4} = ss, ${ipv4}, ${stls_listen_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${port}"
        else
            if [[ "${ipv6}" != "IPv6_Error" ]]; then
                echo -e "ss-${ipv6} = ss, ${ipv6}, ${stls_listen_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${port}"
            else
                log_error "无法获取服务器IP地址，无法生成Surge+ShadowTLS配置"
            fi
        fi
    fi

    Before_Start_Menu
}

# 查看服务状态
Status(){
    check_installed_status
    check_status
    
    echo -e "\n${Yellow_font_prefix}=== Shadowsocks Rust 服务状态 ===${Font_color_suffix}"
    
    if [[ "$status" == "running" ]]; then
        echo -e " 运行状态：${Green_font_prefix}正在运行${Font_color_suffix}"
        
        local pid
        pid=$(systemctl show -p MainPID ss-rust | cut -d= -f2)
        if [[ "$pid" != "0" ]]; then
            echo -e " 进程 PID：${Green_font_prefix}${pid}${Font_color_suffix}"
            
            local memory_usage
            memory_usage=$(ps -o rss= -p "$pid" 2>/dev/null)
            if [[ -n "$memory_usage" ]]; then
                memory_usage=$(awk "BEGIN {printf \"%.2f\", ${memory_usage}/1024}")
                echo -e " 内存占用：${Green_font_prefix}${memory_usage} MB${Font_color_suffix}"
            fi
            
            local started_at
            started_at=$(systemctl show ss-rust -p ActiveEnterTimestamp | cut -d= -f2)
            if [[ -n "$started_at" ]]; then
                echo -e " 启动时间：${Green_font_prefix}${started_at}${Font_color_suffix}"
            fi
        fi
        
        if command -v netstat &>/dev/null || command -v ss &>/dev/null; then
            echo -e "\n${Yellow_font_prefix}=== 端口监听状态 ===${Font_color_suffix}"
            if command -v ss &>/dev/null; then
                ss -tunlp | grep -E "ss-rust|${port}" | grep -v grep
            elif command -v netstat &>/dev/null; then
                netstat -tunlp | grep -E "ss-rust|${port}" | grep -v grep
            fi
        fi
    else
        echo -e " 运行状态：${Red_font_prefix}未运行${Font_color_suffix}"
        log_tip "使用 ${Green_font_prefix}./ss22. sh${Font_color_suffix} 选择 ${Green_font_prefix}4. ${Font_color_suffix} 启动服务"
    fi
    
    echo -e "\n${Yellow_font_prefix}=== 日志查看选项 ===${Font_color_suffix}"
    echo -e " ${Green_font_prefix}1. ${Font_color_suffix} 查看最近 50 行日志"
    echo -e " ${Green_font_prefix}2.${Font_color_suffix} 查看今日错误日志"
    echo -e " ${Green_font_prefix}3.${Font_color_suffix} 实时跟踪日志"
    echo -e " ${Green_font_prefix}0.${Font_color_suffix} 返回主菜单"
    
    read -e -p "请选择 [0-3]: " log_choice
    [[ -z "${log_choice}" ]] && log_choice="0"
    
    case "$log_choice" in
        1)
            echo -e "\n${Yellow_font_prefix}=== 最近 50 行日志 ===${Font_color_suffix}"
            journalctl -u ss-rust --no-pager -n 50
            ;;
        2)
            echo -e "\n${Yellow_font_prefix}=== 今日错误日志 ===${Font_color_suffix}"
            journalctl -u ss-rust --no-pager --since today | grep -i "error\|fail\|warn"
            ;;
        3)
            log_info "按 Ctrl+C 退出日志跟踪..."
            sleep 1
            journalctl -u ss-rust -f --no-hostname
            ;;
        0|*)
            ;;
    esac
    
    Before_Start_Menu
}

# 更新脚本
Update_Shell(){
    echo -e "当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
    
    local github_url="https://raw.githubusercontent.com/tunecc/ss22-ShadowTLS/main/ss22.sh"
    local sh_new_ver
    sh_new_ver=$(wget --no-check-certificate -qO- "${github_url}" | grep 'sh_ver="' | awk -F "=" '{print $NF}' | sed 's/\"//g' | head -1)
    
    if [[ -z ${sh_new_ver} ]]; then
        log_error "检测最新版本失败！"
        Start_Menu
        return
    fi
    
    if [[ ${sh_new_ver} != "${sh_ver}" ]]; then
        echo -e "发现新版本[ ${sh_new_ver} ]，是否更新？[Y/n]"
        read -p "(默认: y): " yn
        [[ -z "${yn}" ]] && yn="y"
        
        if [[ ${yn} == [Yy] ]]; then
            log_info "开始下载最新版本脚本..."
            if !  wget -O ss22.sh --no-check-certificate "${github_url}"; then
                log_error "下载失败，请检查网络连接"
                sleep 1s
                Start_Menu
                return
            fi
            
            chmod +x ss22.sh
            log_info "脚本已更新为最新版本[ ${sh_new_ver} ]"
            log_info "3秒后将执行新脚本"
            sleep 3s
            exec bash ss22.sh
        else
            log_info "已取消更新"
            sleep 1s
            Start_Menu
        fi
    else
        log_info "当前已是最新版本[ ${sh_new_ver} ]"
        sleep 1s
        Start_Menu
    fi
}

# 暂停并按键继续
Before_Start_Menu() {
    echo && echo -n -e "${Yellow_font_prefix}* 按任意键返回主菜单 *${Font_color_suffix}" && read -n 1 -s temp
    echo
    Start_Menu
}

# 设置每日定时重启
Set_daily_restart(){
    echo -e "请输入每日定时重启执行的 小时 (0-23 整数)"
    read -e -p "(默认: 3): " RESTART_HOUR
    [[ -z "${RESTART_HOUR}" ]] && RESTART_HOUR="3"
    
    if !  [[ "${RESTART_HOUR}" =~ ^[0-9]+$ ]] || [[ "${RESTART_HOUR}" -lt 0 ]] || [[ "${RESTART_HOUR}" -gt 23 ]]; then
        log_error "小时必须是 0-23 之间的整数！"
        return
    fi

    echo -e "请输入每日定时重启执行的 分钟 (0-59 整数)"
    read -e -p "(默认: 0): " RESTART_MINUTE
    [[ -z "${RESTART_MINUTE}" ]] && RESTART_MINUTE="0"
    
    if ! [[ "${RESTART_MINUTE}" =~ ^[0-9]+$ ]] || [[ "${RESTART_MINUTE}" -lt 0 ]] || [[ "${RESTART_MINUTE}" -gt 59 ]]; then
        log_error "分钟必须是 0-59 之间的整数！"
        return
    fi

    local JOB_LINE="${RESTART_MINUTE} ${RESTART_HOUR} * * * /usr/bin/systemctl restart ss-rust"
    local CRONTAB_CONTENT
    CRONTAB_CONTENT=$(crontab -l 2>/dev/null)

    if echo "${CRONTAB_CONTENT}" | grep -q "${JOB_LINE}"; then
        log_info "已存在每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的任务，无需重复添加"
    else
        if echo "${CRONTAB_CONTENT}" | grep -q "systemctl restart ss-rust"; then
            CRONTAB_CONTENT=$(echo "${CRONTAB_CONTENT}" | grep -v "systemctl restart ss-rust")
            log_info "已删除旧的定时重启任务"
        fi
        
        (echo "${CRONTAB_CONTENT}"; echo "${JOB_LINE}") | crontab -
        log_info "已添加每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的计划任务"
    fi
    
    sleep 1s
    Start_Menu
}

# 安装ShadowTLS
install_shadowtls() {
    log_info "开始下载 ShadowTLS 安装脚本..."
    
    if ! wget -N --no-check-certificate https://raw.githubusercontent.com/tunecc/ss22-ShadowTLS/main/shadowtls.sh; then
        log_error "ShadowTLS 脚本下载失败！"
        if confirm "是否重试下载？" "y"; then
            install_shadowtls
            return
        else
            log_warning "ShadowTLS 安装已取消"
            return 1
        fi
    fi
    
    chmod +x shadowtls.sh
    log_info "开始安装 ShadowTLS..."
    bash shadowtls.sh
    
    rm -f shadowtls.sh
}

# 主菜单
Start_Menu(){
    clear
    check_root
    check_sys
    sysArch
    
    local status_text
    if [[ -e ${FILE} ]]; then
        check_status
        if [[ "$status" == "running" ]]; then
            status_text="${Green_font_prefix}已安装${Font_color_suffix} 并 ${Green_font_prefix}已启动${Font_color_suffix}"
        else
            status_text="${Green_font_prefix}已安装${Font_color_suffix} 但 ${Red_font_prefix}未启动${Font_color_suffix}"
        fi
    else
        status_text="${Red_font_prefix}未安装${Font_color_suffix}"
    fi
    
    echo -e "${Yellow_font_prefix}================== Shadowsocks Rust 管理脚本 v${sh_ver} ==================${Font_color_suffix}"
    echo -e " 当前状态: ${status_text}"
    
    echo
    echo -e "${Cyan_font_prefix}◆ 安装管理${Font_color_suffix}"
    echo -e "  ${Green_font_prefix}1. ${Font_color_suffix} 安装 Shadowsocks Rust"
    echo -e "  ${Green_font_prefix}2.${Font_color_suffix} 更新 Shadowsocks Rust"
    echo -e "  ${Green_font_prefix}3.${Font_color_suffix} 卸载 Shadowsocks Rust"
    echo
    echo -e "${Cyan_font_prefix}◆ 服务控制${Font_color_suffix}"
    echo -e "  ${Green_font_prefix}4. ${Font_color_suffix} 启动 Shadowsocks Rust"
    echo -e "  ${Green_font_prefix}5.${Font_color_suffix} 停止 Shadowsocks Rust"
    echo -e "  ${Green_font_prefix}6.${Font_color_suffix} 重启 Shadowsocks Rust"
    echo
    echo -e "${Cyan_font_prefix}◆ 配置管理${Font_color_suffix}"
    echo -e "  ${Green_font_prefix}7.${Font_color_suffix} 修改 配置信息"
    echo -e "  ${Green_font_prefix}8.${Font_color_suffix} 查看 配置信息"
    echo -e "  ${Green_font_prefix}9.${Font_color_suffix} 查看 运行状态"
    echo
    echo -e "${Cyan_font_prefix}◆ 其他选项${Font_color_suffix}"
    echo -e "  ${Green_font_prefix}10.${Font_color_suffix} 设置每日定时重启"
    echo -e "  ${Green_font_prefix}11.${Font_color_suffix} 更新脚本"
    echo -e "  ${Green_font_prefix}12.${Font_color_suffix} 管理ShadowTLS"
    echo -e "  ${Green_font_prefix}0.${Font_color_suffix}  退出脚本"
    echo -e "${Yellow_font_prefix}======================================================================${Font_color_suffix}"
    echo
    
    read -e -p " 请输入数字 [0-12]: " num
    case "$num" in
        0)
            clear
            echo -e "${Green_font_prefix}感谢使用 Shadowsocks Rust 管理脚本！${Font_color_suffix}"
            echo -e "输入 ${Yellow_font_prefix}./ss22.sh${Font_color_suffix} 即可再次运行脚本"
            exit 0
            ;;
        1)
            Install
            ;;
        2)
            Update
            ;;
        3)
            Uninstall
            ;;
        4)
            Start
            ;;
        5)
            Stop
            ;;
        6)
            Restart
            ;;
        7)
            Set
            ;;
        8)
            View
            ;;
        9)
            Status
            ;;
        10)
            Set_daily_restart
            ;;
        11)
            Update_Shell
            ;;
        12)
            install_shadowtls
            ;;
        *)
            echo -e "${Red_font_prefix}错误:${Font_color_suffix} 请输入正确数字 [0-12]"
            sleep 1
            Start_Menu
            ;;
    esac
}

# 启动主菜单
Start_Menu