#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="1.7.2"
filepath=$(cd "$(dirname "$0")"; pwd)
FOLDER="/etc/ss-rust"
FILE="/usr/local/bin/ss-rust"
CONF="/etc/ss-rust/config.json"
Now_ver_File="/etc/ss-rust/ver.txt"

# 颜色定义
Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Green_background_prefix="\033[42;37m"
Red_background_prefix="\033[41;37m"
Font_color_suffix="\033[0m"
Yellow_font_prefix="\033[0;33m"
Cyan_font_prefix="\033[36m"
Blue_font_prefix="\033[34m"
Purple_background_prefix="\033[45;37m"

# 消息类型
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Yellow_font_prefix}[注意]${Font_color_suffix}"
Warning="${Yellow_font_prefix}[警告]${Font_color_suffix}"

# 显示进度条函数
show_progress() {
    local duration=$1
    local sleep_interval=0.1
    local steps=$(echo "$duration / $sleep_interval" | bc)
    local width=50
    
    echo -n "["
    for ((i=0; i<width; i++)); do
        echo -n " "
    done
    echo -n "]"
    echo -ne "\r["
    
    for ((i=0; i<width; i++)); do
        echo -n "#"
        sleep $(echo "$duration / $width" | bc -l)
        echo -ne "\r["
        for ((j=0; j<=i; j++)); do
            echo -n "#"
        done
        for ((j=i+1; j<width; j++)); do
            echo -n " "
        done
        echo -n "]"
    done
    echo
}

# 检查是否为ROOT用户
check_root(){
    if [[ $EUID != 0 ]]; then
        echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。" 
        exit 1
    fi
}

# 检测系统类型
check_sys(){
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    else
        echo -e "${Error} 未能识别系统类型，请联系脚本作者！"
        exit 1
    fi
}

# 检测系统架构
sysArch() {
    uname=$(uname -m)
    if [[ "$uname" == "i686" ]] || [[ "$uname" == "i386" ]]; then
        arch="i686"
    elif [[ "$uname" == *"armv7"* ]] || [[ "$uname" == "armv6l" ]]; then
        arch="arm"
    elif [[ "$uname" == *"armv8"* ]] || [[ "$uname" == "aarch64" ]]; then
        arch="aarch64"
    else
        arch="x86_64"
    fi
}

# 检查是否已安装
check_installed_status(){
    if [[ ! -e ${FILE} ]]; then
        echo -e "${Error} Shadowsocks Rust 没有安装，请检查！" 
        Before_Start_Menu
    fi
}

# 检查服务状态
check_status(){
    status=$(systemctl status ss-rust 2>/dev/null | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ -z "$status" ]]; then
        status="unknown"
    fi
}

# 检查端口占用
check_port_occupied(){
    local port=$1
    local occupied=$(lsof -i:${port} -t)
    if [[ -n "$occupied" ]]; then
        return 0  # 端口已占用
    else
        return 1  # 端口未占用
    fi
}

# 获取最新版本
check_new_ver(){
    echo -e "${Info} 正在检查最新版本..."
    new_ver=$(wget -qO- --no-check-certificate https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases | jq -r '[.[] | select(.prerelease == false) | select(.draft == false) | .tag_name] | .[0]' 2>/dev/null)
    if [[ -z ${new_ver} ]]; then
        echo -e "${Error} 获取 Shadowsocks Rust 最新版本失败！"
        read -e -p "是否继续使用默认版本安装？[Y/n]" continue_install
        [[ -z "$continue_install" ]] && continue_install="y"
        if [[ "$continue_install" == [Yy] ]]; then
            new_ver="v1.15.2" # 默认版本
            echo -e "${Info} 将使用默认版本 ${new_ver} 继续安装"
        else
            echo -e "${Info} 已取消安装"
            exit 1
        fi
    else
        echo -e "${Info} 检测到 Shadowsocks Rust 最新版本为 ${Green_font_prefix}${new_ver}${Font_color_suffix}"
    fi
}

# 比较版本
check_ver_comparison(){
    now_ver=$(cat ${Now_ver_File} 2>/dev/null)
    if [[ "${now_ver}" != "${new_ver}" ]]; then
        echo -e "${Info} 发现 Shadowsocks Rust 已有新版本 ${Green_font_prefix}${new_ver}${Font_color_suffix}，旧版本 ${Red_font_prefix}${now_ver}${Font_color_suffix}"
        read -e -p "是否更新？[Y/n]：" yn
        [[ -z "${yn}" ]] && yn="y"
        if [[ $yn == [Yy] ]]; then
            check_status
            
            \cp "${CONF}" "/tmp/config.json"
            
            Download
            if [[ $? -eq 0 ]]; then
                mv -f "/tmp/config.json" "${CONF}"
                chmod 600 "${CONF}"  # 限制配置文件权限
                echo -e "${Info} 配置文件已恢复"
                Restart
            else
                echo -e "${Error} 更新失败，将恢复配置文件"
                if [[ -f "/tmp/config.json" ]]; then
                    mv -f "/tmp/config.json" "${CONF}"
                    echo -e "${Info} 已从临时备份恢复配置"
                fi
            fi
        fi
    else
        echo -e "${Info} 当前 Shadowsocks Rust 已是最新版本 ${Green_font_prefix}${new_ver}${Font_color_suffix} ！"
        exit 1
    fi
}

# 官方源下载
stable_Download() {
    echo -e "${Info} 开始下载官方源 Shadowsocks Rust..."
    download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${new_ver}/shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz"
    
    echo -e "${Info} 下载地址: ${download_url}"
    wget --no-check-certificate -N "${download_url}"
    
    if [[ $? -ne 0 ]] || [[ ! -e "shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz" ]]; then
        echo -e "${Error} Shadowsocks Rust 官方源下载失败！"
        return 1
    else
        echo -e "${Info} 下载成功，开始解压..."
        tar -xJf "shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz"
        
        if [[ $? -ne 0 ]] || [[ ! -e "ssserver" ]]; then
            echo -e "${Error} Shadowsocks Rust 解压失败！"
            return 1
        else
            echo -e "${Info} 解压成功，开始安装..."
            rm -rf "shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz"
            chmod +x ssserver
            mv -f ssserver "${FILE}"
            rm -f sslocal ssmanager ssservice ssurl 2>/dev/null
            echo "${new_ver}" > ${Now_ver_File}
            echo -e "${Info} Shadowsocks Rust 主程序安装完成！"
            return 0
        fi
    fi
}

# 备用源下载
backup_Download() {
    echo -e "${Info} 尝试使用备份源下载（旧版本）Shadowsocks Rust..."
    local backup_ver="v1.14.3"
    local backup_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${backup_ver}/shadowsocks-${backup_ver}.${arch}-unknown-linux-gnu.tar.xz"
    
    if [ ! -e "shadowsocks-${backup_ver}.${arch}-unknown-linux-gnu.tar.xz" ]; then
        wget --no-check-certificate -N "${backup_url}"
        
        if [[ $? -ne 0 ]] || [[ ! -e "shadowsocks-${backup_ver}.${arch}-unknown-linux-gnu.tar.xz" ]]; then
            echo -e "${Error} 从备份源下载 Shadowsocks Rust 失败！"
            return 1
        fi
    fi
    
    tar -xJf "shadowsocks-${backup_ver}.${arch}-unknown-linux-gnu.tar.xz"
    
    if [[ $? -ne 0 ]] || [[ ! -e "ssserver" ]]; then
        echo -e "${Error} 备份源 Shadowsocks Rust 解压失败！"
        return 1
    else
        rm -rf "shadowsocks-${backup_ver}.${arch}-unknown-linux-gnu.tar.xz"
        chmod +x ssserver
        mv -f ssserver "${FILE}"
        rm -f sslocal ssmanager ssservice ssurl 2>/dev/null
        echo "${backup_ver}" > ${Now_ver_File}
        echo -e "${Info} 备份源 Shadowsocks Rust 主程序安装完成！"
        return 0
    fi
}

# 整合下载功能
Download() {
    if [[ ! -d "${FOLDER}" ]]; then
        mkdir -p "${FOLDER}" || {
            echo -e "${Error} 创建文件夹 ${FOLDER} 失败，请检查权限！"
            exit 1
        }
        echo -e "${Info} 创建目录 ${FOLDER} 成功"
    fi
    
    # 尝试官方源下载
    stable_Download
    if [[ $? != 0 ]]; then
        echo -e "${Warning} 官方源下载失败，尝试备用源..."
        backup_Download
        if [[ $? != 0 ]]; then
            echo -e "${Error} 所有下载源均失败，无法继续安装！"
            return 1
        fi
    fi
    return 0
}

# 创建服务
Service(){
    # 检测宿主机虚拟化类型
    local virt_type
    virt_type="$(systemd-detect-virt 2>/dev/null || echo "unknown")"
    echo -e "${Info} 检测到虚拟化类型: ${Green_font_prefix}${virt_type}${Font_color_suffix}"
    
    # 准备服务文件内容
    local service_content='
[Unit]
Description=Shadowsocks Rust Service
Documentation=https://github.com/shadowsocks/shadowsocks-rust
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
LimitNOFILE=32768
Type=simple
User=root
Restart=on-failure
RestartSec=5s'
    
    # 根据虚拟化类型决定是否添加 ExecStartPre
    if [[ "$virt_type" == "kvm" ]]; then
        service_content+='
ExecStartPre=/bin/sh -c '\''ulimit -n 51200'\'''
        echo -e "${Info} 检测到KVM虚拟化环境，已添加 ExecStartPre 配置以提高性能"
    else
        echo -e "${Info} 检测到${virt_type}虚拟化环境，不添加额外的性能优化配置"
    fi
    
    # 完成服务文件内容
    service_content+='
ExecStart=/usr/local/bin/ss-rust -c /etc/ss-rust/config.json
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target'
    
    # 写入服务文件
    echo -e "${Info} 正在创建系统服务..."
    echo "$service_content" > /etc/systemd/system/ss-rust.service
    
    # 启用服务
    systemctl daemon-reload
    systemctl enable ss-rust
    
    echo -e "${Info} Shadowsocks Rust 服务配置完成！"
}

# 安装依赖
Installation_dependency(){
    echo -e "${Info} 正在安装/更新必要组件..."
    
    # 检查是否安装了必要的组件
    local packages_to_install=""
    local check_commands=("jq" "wget" "curl" "openssl" "lsof")
    
    for cmd in "${check_commands[@]}"; do
        if ! command -v $cmd &>/dev/null; then
            case $cmd in
                "jq") packages_to_install+=" jq" ;;
                "wget") packages_to_install+=" wget" ;;
                "curl") packages_to_install+=" curl" ;;
                "openssl") packages_to_install+=" openssl" ;;
                "lsof") packages_to_install+=" lsof" ;;
            esac
        fi
    done
    
    # 根据系统类型安装缺少的组件
    if [[ -n $packages_to_install ]]; then
        echo -e "${Info} 检测到缺少以下组件:${Green_font_prefix}${packages_to_install}${Font_color_suffix}"
        
        if [[ ${release} == "centos" ]]; then
            echo -e "${Info} 更新并安装组件中..."
            yum update -y
            yum install -y $packages_to_install xz unzip gzip
        else
            echo -e "${Info} 更新并安装组件中..."
            apt-get update
            apt-get install -y $packages_to_install xz-utils unzip gzip
        fi
        
        if [ $? -ne 0 ]; then
            echo -e "${Error} 安装组件失败，请手动安装后重试！"
            exit 1
        fi
    else
        echo -e "${Info} 所需组件已安装，跳过安装步骤"
    fi
    
    # 设置时区
    echo -e "${Info} 正在设置系统时区为 Asia/Shanghai..."
    if [ -f "/usr/share/zoneinfo/Asia/Shanghai" ]; then
        ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
        echo "Asia/Shanghai" > /etc/timezone
        echo -e "${Info} 时区设置完成"
    else
        echo -e "${Warning} 时区文件不存在，跳过设置"
    fi
}

# 写入配置文件
Write_config(){
    echo -e "${Info} 正在生成配置文件..."
    cat > ${CONF}<<-EOF
{
    "server": "::",
    "server_port": ${port},
    "password": "${password}",
    "method": "${cipher}",
    "fast_open": ${tfo},
    "mode": "tcp_and_udp",
    "user": "nobody",
    "timeout": 300,
    "ecn": ${ecn}${dns:+",\n    \"nameserver\":\"${dns}\""}
}
EOF
    
    # 设置配置文件权限
    chmod 600 ${CONF}
    echo -e "${Info} 配置文件已生成并设置适当权限"
}

# 读取配置文件
Read_config(){
    if [[ ! -e ${CONF} ]]; then
        echo -e "${Error} Shadowsocks Rust 配置文件不存在！" 
        return 1  # 返回错误而不是退出脚本
    fi
    
    # 读取基础配置
    port=$(cat ${CONF} | jq -r '.server_port')
    password=$(cat ${CONF} | jq -r '.password')
    cipher=$(cat ${CONF} | jq -r '.method')
    tfo=$(cat ${CONF} | jq -r '.fast_open')
    dns=$(cat ${CONF} | jq -r '.nameserver // empty')
    
    # 从配置文件中读取ecn状态，如果不存在使用默认值
    ecn=$(cat ${CONF} | jq -r '.ecn // false')
    return 0
}

# 设置端口
Set_port(){
    while true
    do
        echo -e "${Tip} 本步骤不涉及系统防火墙端口操作，请手动放行相应端口！"
        echo -e "请输入 Shadowsocks Rust 端口 [1-65535]"
        read -e -p "(回车随机生成)：" port
        
        # 如果用户未输入，随机生成端口
        if [[ -z "${port}" ]]; then
            while true; do
                port=$(shuf -i 9000-19999 -n 1)
                check_port_occupied $port || break
            done
            echo -e "${Info} 已随机生成端口: ${Green_font_prefix}${port}${Font_color_suffix}"
        else
            # 检查是否为有效数字
            if ! [[ "$port" =~ ^[0-9]+$ ]]; then
                echo -e "${Error} 请输入有效的数字!"
                continue
            fi
            
            # 检查端口范围
            if [[ ${port} -lt 1 ]] || [[ ${port} -gt 65535 ]]; then
                echo -e "${Error} 端口范围错误，请输入 1-65535 之间的数字!"
                continue
            fi
            
            # 检查端口是否被占用
            if check_port_occupied $port; then
                echo -e "${Error} 端口 ${port} 已被占用，请更换其他端口!"
                continue
            fi
        fi
        
        echo && echo "=================================="
        echo -e "端口: ${Red_background_prefix} ${port} ${Font_color_suffix}"
        echo "==================================" && echo
        break
    done
}

# 设置TCP Fast Open
Set_tfo(){
    echo -e "是否开启 TCP Fast Open ？"
    echo -e "${Tip} 开启此选项仅修改 Shadowsocks 配置，不会自动修改系统参数"
    
    # 检查系统是否支持TFO
    local tfo_available=false
    if [[ -f /proc/sys/net/ipv4/tcp_fastopen ]]; then
        local tfo_status=$(cat /proc/sys/net/ipv4/tcp_fastopen)
        if [[ $tfo_status -gt 0 ]]; then
            tfo_available=true
            echo -e "${Info} 系统已启用 TCP Fast Open，状态值: ${tfo_status}"
        else
            echo -e "${Warning} 系统未启用 TCP Fast Open，如需完全启用，请手动执行: echo 3 > /proc/sys/net/ipv4/tcp_fastopen"
        fi
    else
        echo -e "${Warning} 系统不支持 TCP Fast Open"
    fi
    
    echo "=================================="
    echo -e " ${Green_font_prefix}1.${Font_color_suffix} 启用"
    echo -e " ${Green_font_prefix}2.${Font_color_suffix} 禁用 (默认)"
    echo "=================================="
    
    read -e -p "(默认: 2): " tfo_choice
    [[ -z "${tfo_choice}" ]] && tfo_choice="2"
    
    if [[ ${tfo_choice} == "1" ]]; then
        tfo=true
        if [[ "$tfo_available" == "false" ]]; then
            echo -e "${Warning} 您已在 Shadowsocks 中启用 TCP Fast Open，但系统未开启此功能，实际效果可能受限"
            echo -e "${Tip} 建议执行以下命令开启系统 TCP Fast Open：echo 3 > /proc/sys/net/ipv4/tcp_fastopen"
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
    echo -e "${Tip} AEAD 2022 加密（须v1.15.0及以上版本且密码须经过Base64加密）"
    echo "=================================="
    echo -e " ${Green_font_prefix}13.${Font_color_suffix} 2022-blake3-aes-128-gcm ${Green_font_prefix}(推荐)${Font_color_suffix}"
    echo -e " ${Green_font_prefix}14.${Font_color_suffix} 2022-blake3-aes-256-gcm ${Green_font_prefix}(默认推荐)${Font_color_suffix}"
    echo -e " ${Green_font_prefix}15.${Font_color_suffix} 2022-blake3-chacha20-poly1305"
    echo -e " ${Green_font_prefix}16.${Font_color_suffix} 2022-blake3-chacha8-poly1305"
    echo "=================================="
    
    read -e -p "(默认: 14. 2022-blake3-aes-256-gcm): " method_choice
    [[ -z "${method_choice}" ]] && method_choice="14"
    
    case ${method_choice} in
        1) cipher="aes-128-gcm" ;;
        2) cipher="aes-256-gcm" ;;
        3) cipher="chacha20-ietf-poly1305" ;;
        4) cipher="plain" ;;
        5) cipher="none" ;;
        6) cipher="table" ;;
        7) cipher="aes-128-cfb" ;;
        8) cipher="aes-256-cfb" ;;
        9) cipher="aes-256-ctr" ;;
        10) cipher="camellia-256-cfb" ;;
        11) cipher="rc4-md5" ;;
        12) cipher="chacha20-ietf" ;;
        13) cipher="2022-blake3-aes-128-gcm" ;;
        14) cipher="2022-blake3-aes-256-gcm" ;;
        15) cipher="2022-blake3-chacha20-poly1305" ;;
        16) cipher="2022-blake3-chacha8-poly1305" ;;
        *) cipher="2022-blake3-aes-256-gcm" ;;
    esac
    
    echo && echo "=================================="
    echo -e "加密: ${Red_background_prefix} ${cipher} ${Font_color_suffix}"
    echo "==================================" && echo
}

# 设置密码
Set_password() {
    echo "请输入 Shadowsocks Rust 密码 [0-9][a-z][A-Z]"
    read -e -p "(回车随机生成): " password
    
    if [[ -z "${password}" ]]; then
        # 根据加密方式选择合适的密钥长度
        case "${cipher}" in
            "2022-blake3-aes-128-gcm")
                # 生成16字节密钥并进行base64编码
                password=$(openssl rand -base64 16)
                ;;
            "2022-blake3-aes-256-gcm"|"2022-blake3-chacha20-poly1305"|"2022-blake3-chacha8-poly1305")
                # 生成32字节密钥并进行base64编码 (对应44字符的base64编码)
                password=$(openssl rand -base64 32)
                # 确保base64编码后的长度正确
                while [[ ${#password} -ne 44 ]]; do
                    password=$(openssl rand -base64 32)
                done
                ;;
            *)
                # 其他加密方式使用16字节密钥
                password=$(openssl rand -base64 16)
                ;;
        esac
        echo -e "${Info} 已随机生成密码"
    fi
    
    # 验证密码长度对于2022系列加密方式，但不显示详细信息
    if [[ "${cipher}" =~ "2022-blake3" ]]; then
        # 解码base64并检查字节长度
        local required_bytes=32
        [[ "${cipher}" == "2022-blake3-aes-128-gcm" ]] && required_bytes=16
        
        local decoded_length=$(echo -n "${password}" | base64 -d 2>/dev/null | wc -c)
        
        if [[ ${decoded_length} -ne ${required_bytes} ]]; then
            echo -e "${Error} 密码长度不符合要求，请重新设置密码！"
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
    echo -e "${Tip} 少数客户端（如Surge等）支持此选项"
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
        
        # 验证DNS格式
        if ! echo "$dns" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(,([0-9]{1,3}\.){3}[0-9]{1,3})*$'; then
            echo -e "${Error} DNS地址格式不正确，请输入正确的IP地址格式!"
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
    
    # 备份当前配置到临时文件
    \cp "${CONF}" "/tmp/config.json" 
    
    if [[ "${modify}" == "1" ]]; then
        Read_config
        Set_port
        Write_config
        Restart
    elif [[ "${modify}" == "2" ]]; then
        Read_config
        Set_method
        Set_password  # 更改加密方式后需要重新设置密码
        Write_config
        Restart
    elif [[ "${modify}" == "3" ]]; then
        Read_config
        Set_password
        Write_config
        Restart
    elif [[ "${modify}" == "4" ]]; then
        Read_config
        Set_tfo
        Write_config
        Restart
    elif [[ "${modify}" == "5" ]]; then
        Read_config
        Set_dns
        Write_config
        Restart
    elif [[ "${modify}" == "6" ]]; then
        Read_config
        Set_ecn
        Write_config
        Restart
    elif [[ "${modify}" == "7" ]]; then
        Read_config
        Set_port
        Set_method
        Set_password
        Set_tfo
        Set_dns
        Set_ecn
        Write_config
        Restart
    else
        echo -e "${Error} 请输入正确的数字 [1-7]" && exit 1
    fi
}

# 安装
Install(){
    if [[ -e ${FILE} ]]; then
        echo -e "${Error} 检测到 Shadowsocks Rust 已安装！" 
        Before_Start_Menu
        return
    fi
    
    echo -e "\n${Yellow_font_prefix}===============================================${Font_color_suffix}"
    echo -e "${Green_font_prefix}开始 Shadowsocks Rust 安装...${Font_color_suffix}"
    echo -e "${Yellow_font_prefix}===============================================${Font_color_suffix}\n"
    
    # 创建备份目录
    if [[ ! -d "${FOLDER}" ]]; then
        mkdir -p "${FOLDER}"
    fi
    
    echo -e "${Info} 开始设置配置..."
    Set_port
    Set_method
    Set_password
    Set_tfo
    Set_dns
    Set_ecn
    echo -e "${Info} 开始安装/配置依赖..."
    Installation_dependency
    echo -e "${Info} 开始下载/安装..."
    check_new_ver
    Download || { echo -e "${Error} 下载或解压失败，退出安装！"; exit 1; }
    echo -e "${Info} 开始安装系统服务脚本..."
    Service
    echo -e "${Info} 开始写入配置文件..."
    Write_config
    echo -e "${Info} 所有步骤安装完毕，开始启动..."
    
    # 启动服务
    Start
    
    # 设置每日重启
    echo -e "${Info} 正在设置每日5:00自动重启..."
    RESTART_HOUR="5"
    RESTART_MINUTE="0"
    JOB_LINE="${RESTART_MINUTE} ${RESTART_HOUR} * * * /usr/bin/systemctl restart ss-rust"
    CRONTAB_CONTENT=$(crontab -l 2>/dev/null)
    
    if echo "${CRONTAB_CONTENT}" | grep -q "${JOB_LINE}"; then
        echo -e "${Info} 已存在每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的任务，无需重复添加"
    else
        (echo "${CRONTAB_CONTENT}"; echo "${JOB_LINE}") | crontab -
        echo -e "${Info} 已添加每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的计划任务"
    fi
    
    echo -e "${Info} 启动完成！"
    
    echo -e "\n${Yellow_font_prefix}===============================================${Font_color_suffix}"
    echo -e "${Green_font_prefix}Shadowsocks Rust 已成功安装!${Font_color_suffix}"
    echo -e "${Yellow_font_prefix}===============================================${Font_color_suffix}"
    echo -e "\n${Cyan_font_prefix}是否需要继续安装 ShadowTLS 进行流量混淆? [Y/n]${Font_color_suffix}"
    
    read -r install_stls
    case "$install_stls" in
        [yY][eE][sS]|[yY]|"")
            echo -e "${Green_font_prefix}正在准备安装 ShadowTLS...${Font_color_suffix}"
            install_shadowtls
            ;;
        *)
            echo -e "${Yellow_font_prefix}已跳过 ShadowTLS 安装，如需安装请稍后在菜单中选择安装选项${Font_color_suffix}"
            echo -e "${Info} 显示当前配置信息..."
            View
            ;;
    esac
    
    echo -e "\n${Green_font_prefix}安装过程已完成!${Font_color_suffix}"
    sleep 1s
    Before_Start_Menu
}

# 启动
Start(){
    check_installed_status
    check_status
    
    if [[ "$status" == "running" ]]; then
        echo -e "${Info} Shadowsocks Rust 已在运行！"
    else
        echo -e "${Info} 启动 Shadowsocks Rust 服务..."
        systemctl start ss-rust
        sleep 1s
        
        check_status
        if [[ "$status" == "running" ]]; then
            echo -e "${Info} Shadowsocks Rust 启动${Green_font_prefix}成功${Font_color_suffix}！"
        else
            echo -e "${Error} Shadowsocks Rust 启动${Red_font_prefix}失败${Font_color_suffix}！"
            echo -e "${Info} 可能是配置错误导致，请检查配置文件或日志: journalctl -u ss-rust"
            exit 1
        fi
    fi
}

# 停止
Stop(){
    check_installed_status
    check_status
    
    if [[ "$status" != "running" ]]; then
        echo -e "${Error} Shadowsocks Rust 未在运行，无需停止！" 
        exit 1
    fi
    
    echo -e "${Info} 正在停止 Shadowsocks Rust 服务..."
    systemctl stop ss-rust
    sleep 1s
    
    check_status
    if [[ "$status" != "running" ]]; then
        echo -e "${Info} Shadowsocks Rust 已停止运行！"
    else
        echo -e "${Error} Shadowsocks Rust 停止失败，请检查日志: journalctl -u ss-rust"
        exit 1
    fi
    Start_Menu
}

# 重启
Restart(){
    check_installed_status
    echo -e "${Info} 正在重启 Shadowsocks Rust 服务..."
    systemctl restart ss-rust
    sleep 1s
    
    check_status
    if [[ "$status" == "running" ]]; then
        echo -e "${Info} Shadowsocks Rust 重启${Green_font_prefix}成功${Font_color_suffix}！"
    else
        echo -e "${Error} Shadowsocks Rust 重启${Red_font_prefix}失败${Font_color_suffix}！"
        echo -e "${Info} 可能是配置错误导致，请检查配置文件或日志: journalctl -u ss-rust"
    fi
    sleep 1s
    Start_Menu
}

# 更新
Update(){
    check_installed_status
    check_new_ver
    check_ver_comparison
    echo -e "${Info} Shadowsocks Rust 更新完毕！"
    sleep 1s
    Start_Menu
}

# 卸载
Uninstall(){
    check_installed_status
    echo "确定要卸载 Shadowsocks Rust ? (Y/N)"
    read -e -p "(回车确认卸载): " unyn
    [[ -z ${unyn} ]] && unyn="y"
    
    if [[ ${unyn} == [Yy] ]]; then
        check_status
        [[ "$status" == "running" ]] && systemctl stop ss-rust
        systemctl disable ss-rust
        
        # 直接删除所有文件，不提示是否保留配置
        rm -rf "${FOLDER}"
        rm -f "${FILE}" "/etc/systemd/system/ss-rust.service"
        
        systemctl daemon-reload
        
        # 删除定时重启任务
        echo -e "${Info} 正在检查并删除定时重启任务..."
        crontab_content=$(crontab -l 2>/dev/null)
        if echo "${crontab_content}" | grep -q "systemctl restart ss-rust"; then
            # 删除包含ss-rust重启的行
            echo "${crontab_content}" | grep -v "systemctl restart ss-rust" | crontab -
            echo -e "${Info} 已删除 Shadowsocks Rust 的定时重启任务"
        fi
        
        echo -e "${Info} Shadowsocks Rust 卸载完成！"
        
        # 检查ShadowTLS是否安装
        if [ -f "/usr/local/bin/shadow-tls" ] && systemctl is-enabled shadowtls &>/dev/null; then
            echo -e "\n${Yellow_font_prefix}===============================================${Font_color_suffix}"
            echo -e "${Cyan_font_prefix}检测到系统中已安装 ShadowTLS，是否需要一并卸载? [Y/n]${Font_color_suffix}"
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
    else
        echo && echo "卸载已取消..." && echo
    fi
    sleep 2s
    Start_Menu
}

# 卸载ShadowTLS
uninstall_shadowtls() {
    echo -e "${Cyan_font_prefix}正在卸载 ShadowTLS...${Font_color_suffix}"
    
    read -rp "确认要卸载 ShadowTLS? (y/回车确认，其他键取消): " confirm
    
    if [[ "${confirm,,}" =~ ^y(es)?$ || -z "$confirm" ]]; then
        echo -e "${Green_font_prefix}开始卸载...${Font_color_suffix}"
    else
        echo -e "${Yellow_font_prefix}已取消卸载操作${Font_color_suffix}"
        return 0
    fi
    
    # 停止并禁用服务
    echo -e "${Cyan_font_prefix}停止并移除服务...${Font_color_suffix}"
    systemctl stop shadowtls &>/dev/null
    systemctl disable shadowtls &>/dev/null
    
    # 删除服务文件
    rm -f "/etc/systemd/system/shadowtls.service"
    
    # 删除二进制文件
    echo -e "${Cyan_font_prefix}删除 ShadowTLS 程序文件...${Font_color_suffix}"
    rm -f "/usr/local/bin/shadow-tls"
    
    # 删除配置目录（不提示是否备份）
    echo -e "${Cyan_font_prefix}删除配置文件...${Font_color_suffix}"
    if [ -d "/etc/shadowtls" ]; then
        rm -rf "/etc/shadowtls"
        echo -e "${Green_font_prefix}已删除配置目录${Font_color_suffix}"
    fi
    
    # 删除定时重启任务
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
    echo -e "${Info} 正在获取公网IPv4地址..."
    local success=false
    
    for ip_service in "api.ipify.org" "ifconfig.me" "ip.sb"; do
        echo -e "  尝试从 ${ip_service} 获取..."
        ipv4=$(curl -s4 --connect-timeout 3 https://$ip_service)
        
        if [[ -n "${ipv4}" && "${ipv4}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "  ${Green_font_prefix}成功${Font_color_suffix} 获取到IPv4地址: ${ipv4}"
            success=true
            break
        else
            echo -e "  ${Yellow_font_prefix}失败${Font_color_suffix} 无法从 ${ip_service} 获取有效IPv4地址"
        fi
    done
    
    if [[ "$success" != "true" ]]; then
        echo -e "${Error} 所有IPv4地址获取服务均失败"
        ipv4="IPv4_Error"
    fi
}

# 获取IPv6地址
getipv6(){
    echo -e "${Info} 正在获取公网IPv6地址..."
    local success=false
    
    for ip_service in "api64.ipify.org" "ifconfig.co" "ipv6.icanhazip.com"; do
        echo -e "  尝试从 ${ip_service} 获取..."
        ipv6=$(curl -s6 --connect-timeout 3 https://$ip_service)
        
        if [[ -n "${ipv6}" ]]; then
            echo -e "  ${Green_font_prefix}成功${Font_color_suffix} 获取到IPv6地址: ${ipv6}"
            success=true
            break
        else
            echo -e "  ${Yellow_font_prefix}失败${Font_color_suffix} 无法从 ${ip_service} 获取有效IPv6地址"
        fi
    done
    
    if [[ "$success" != "true" ]]; then
        echo -e "${Warning} 所有IPv6地址获取服务均失败，您的服务器可能不支持IPv6"
        ipv6="IPv6_Error"
    fi
}

# Base64编码 (URL安全)
urlsafe_base64(){
    date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
    echo -e "${date}"
}

# 查看配置
View(){
    check_installed_status
    Read_config
    
    # 获取公网IP地址
    getipv4
    getipv6
    
    echo -e "\n${Yellow_font_prefix}=== Shadowsocks Rust 配置 ===${Font_color_suffix}"
    [[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv4}${Font_color_suffix}"
    [[ "${ipv6}" != "IPv6_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv6}${Font_color_suffix}"
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

    # 生成 SS 链接
    local userinfo=$(echo -n "${cipher}:${password}" | base64 | tr -d '\n')
    local ss_url_ipv4=""
    local ss_url_ipv6=""
    
    if [[ "${ipv4}" != "IPv4_Error" ]]; then
        ss_url_ipv4="ss://${userinfo}@${ipv4}:${port}#ss-${ipv4}"
    fi
    if [[ "${ipv6}" != "IPv6_Error" ]]; then
        ss_url_ipv6="ss://${userinfo}@${ipv6}:${port}#ss-${ipv6}"
    fi

    # 检查 ShadowTLS 是否安装并获取配置
    local stls_listen_port=""
    local stls_password=""
    local stls_sni=""
    
    if [ -f "/etc/systemd/system/shadowtls.service" ]; then
        stls_listen_port=$(grep -oP '(?<=--listen \[\:\:\]\:)\d+' /etc/systemd/system/shadowtls.service 2>/dev/null)
        stls_password=$(grep -oP '(?<=--password )\S+' /etc/systemd/system/shadowtls.service 2>/dev/null)
        stls_sni=$(grep -oP '(?<=--tls )[^:]+(?=:443\b)' /etc/systemd/system/shadowtls.service 2>/dev/null)

        echo -e "\n${Yellow_font_prefix}=== ShadowTLS 配置 ===${Font_color_suffix}"
        echo -e " 监听端口：${Green_font_prefix}${stls_listen_port}${Font_color_suffix}"
        echo -e " 密码：${Green_font_prefix}${stls_password}${Font_color_suffix}"
        echo -e " SNI：${Green_font_prefix}${stls_sni}${Font_color_suffix}"
    fi

    echo -e "\n${Yellow_font_prefix}=== Shadowsocks 链接 ===${Font_color_suffix}"
    [[ ! -z "${ss_url_ipv4}" ]] && echo -e "${Green_font_prefix}IPv4 链接：${Font_color_suffix}${ss_url_ipv4}"
    [[ ! -z "${ss_url_ipv6}" ]] && echo -e "${Green_font_prefix}IPv6 链接：${Font_color_suffix}${ss_url_ipv6}"

    echo -e "\n${Yellow_font_prefix}=== Surge 配置 ===${Font_color_suffix}"
    if [[ "${ipv4}" != "IPv4_Error" ]]; then
        # 根据ecn值决定是否包含ecn参数
        if [[ "${ecn}" == "true" ]]; then
            echo -e "ss-${ipv4} = ss, ${ipv4}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
        else
            echo -e "ss-${ipv4} = ss, ${ipv4}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true"
        fi
    else
        # IPv6 版本配置
        if [[ "${ipv6}" != "IPv6_Error" ]]; then
            if [[ "${ecn}" == "true" ]]; then
                echo -e "ss-${ipv6} = ss, ${ipv6}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
            else
                echo -e "ss-${ipv6} = ss, ${ipv6}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true"
            fi
        else
            echo -e "${Error} 无法获取服务器IP地址，无法生成Surge配置"
        fi
    fi

    # 检查 ShadowTLS 是否安装并生成配置
    if [ -f "/etc/systemd/system/shadowtls.service" ]; then
        # 生成 SS + ShadowTLS 合并链接
        local shadow_tls_config="{\"version\":\"3\",\"password\":\"${stls_password}\",\"host\":\"${stls_sni}\",\"port\":\"${stls_listen_port}\",\"address\":\"${ipv4}\"}"
        local shadow_tls_base64=$(echo -n "${shadow_tls_config}" | base64 | tr -d '\n')
        local ss_stls_url="ss://${userinfo}@${ipv4}:${port}?shadow-tls=${shadow_tls_base64}#ss-${ipv4}"

        echo -e "\n${Yellow_font_prefix}=== SS + ShadowTLS 链接 ===${Font_color_suffix}"
        echo -e "${Green_font_prefix}合并链接：${Font_color_suffix}${ss_stls_url}"

        echo -e "\n${Yellow_font_prefix}=== Surge Shadowsocks + ShadowTLS 配置 ===${Font_color_suffix}"
        if [[ "${ipv4}" != "IPv4_Error" ]]; then
            echo -e "ss-${ipv4} = ss, ${ipv4}, ${stls_listen_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${port}"
        else
            # IPv6版本
            if [[ "${ipv6}" != "IPv6_Error" ]]; then
                echo -e "ss-${ipv6} = ss, ${ipv6}, ${stls_listen_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${port}"
            else
                echo -e "${Error} 无法获取服务器IP地址，无法生成Surge+ShadowTLS配置"
            fi
        fi
    fi

    Before_Start_Menu
}

# 查看服务状态
Status(){
    echo -e "${Info} 获取 Shadowsocks Rust 活动日志..."
    systemctl status ss-rust
    
    echo -e "\n${Info} 查看近期日志? [Y/n]"
    read -e -p "(默认: Y): " show_logs
    [[ -z "${show_logs}" ]] && show_logs="y"
    
    if [[ "${show_logs}" == [Yy] ]]; then
        echo -e "\n${Yellow_font_prefix}=== 最近50行日志 ===${Font_color_suffix}"
        journalctl -u ss-rust --no-pager -n 50
    fi
    
    Before_Start_Menu
}

# 更新脚本
Update_Shell(){
    echo -e "当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
    
    local github_url="https://raw.githubusercontent.com/tunecc/ss22-ShadowTLS/main/ss22.sh"
    sh_new_ver=$(wget --no-check-certificate -qO- "${github_url}"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
    
    if [[ -z ${sh_new_ver} ]]; then
        echo -e "${Error} 检测最新版本失败！" 
        Start_Menu
    fi
    
    if [[ ${sh_new_ver} != ${sh_ver} ]]; then
        echo -e "发现新版本[ ${sh_new_ver} ]，是否更新？[Y/n]"
        read -p "(默认: y): " yn
        [[ -z "${yn}" ]] && yn="y"
        
        if [[ ${yn} == [Yy] ]]; then
            echo -e "${Info} 开始下载最新版本脚本..."
            wget -O ss22.sh --no-check-certificate "${github_url}"
            
            if [ $? -ne 0 ]; then
                echo -e "${Error} 下载失败，请检查网络连接"
                sleep 1s
                Start_Menu
                return
            fi
            
            chmod +x ss22.sh
            echo -e "${Info} 脚本已更新为最新版本[ ${sh_new_ver} ]"
            echo -e "${Info} 3秒后将执行新脚本"
            sleep 3s
            bash ss22.sh
        else
            echo -e "${Info} 已取消更新"
            sleep 1s
            Start_Menu
        fi
    else
        echo -e "${Info} 当前已是最新版本[ ${sh_new_ver} ]"
        sleep 1s
        Start_Menu
    fi
    
    sleep 1s
    bash ss22.sh
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
    
    if ! [[ "${RESTART_HOUR}" =~ ^[0-9]+$ ]] || [ "${RESTART_HOUR}" -lt 0 ] || [ "${RESTART_HOUR}" -gt 23 ]; then
        echo -e "${Error} 小时必须是 0-23 之间的整数！"
        return
    fi

    echo -e "请输入每日定时重启执行的 分钟 (0-59 整数)"
    read -e -p "(默认: 0): " RESTART_MINUTE
    [[ -z "${RESTART_MINUTE}" ]] && RESTART_MINUTE="0"
    
    if ! [[ "${RESTART_MINUTE}" =~ ^[0-9]+$ ]] || [ "${RESTART_MINUTE}" -lt 0 ] || [ "${RESTART_MINUTE}" -gt 59 ]; then
        echo -e "${Error} 分钟必须是 0-59 之间的整数！"
        return
    fi

    JOB_LINE="${RESTART_MINUTE} ${RESTART_HOUR} * * * /usr/bin/systemctl restart ss-rust"
    CRONTAB_CONTENT=$(crontab -l 2>/dev/null)

    # 检查是否已存在相同任务
    if echo "${CRONTAB_CONTENT}" | grep -q "${JOB_LINE}"; then
        echo -e "${Info} 已存在每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的任务，无需重复添加"
    else
        # 删除任何已存在的ss-rust定时重启任务
        if echo "${CRONTAB_CONTENT}" | grep -q "systemctl restart ss-rust"; then
            CRONTAB_CONTENT=$(echo "${CRONTAB_CONTENT}" | grep -v "systemctl restart ss-rust")
            echo -e "${Info} 已删除旧的定时重启任务"
        fi
        
        # 添加新任务
        (echo "${CRONTAB_CONTENT}"; echo "${JOB_LINE}") | crontab -
        echo -e "${Info} 已添加每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的计划任务"
    fi
    
    sleep 1s
    Start_Menu
}

# 安装ShadowTLS
install_shadowtls() {
    echo -e "${Info} 开始下载 ShadowTLS 安装脚本..."
    
    wget -N --no-check-certificate https://raw.githubusercontent.com/tunecc/ss22-ShadowTLS/main/shadowtls.sh
    
    if [ $? -ne 0 ]; then
        echo -e "${Error} ShadowTLS 脚本下载失败！"
        read -e -p "是否重试下载？[Y/n]" retry_download
        [[ -z "${retry_download}" ]] && retry_download="y"
        
        if [[ ${retry_download} == [Yy] ]]; then
            install_shadowtls
            return
        else
            echo -e "${Warning} ShadowTLS 安装已取消"
            return 1
        fi
    fi
    
    chmod +x shadowtls.sh
    echo -e "${Info} 开始安装 ShadowTLS..."
    bash shadowtls.sh
    
    # 安装完成后清理脚本文件
    rm -f shadowtls.sh
}

# 主菜单
Start_Menu(){
    clear
    check_root
    check_sys
    sysArch
    action=$1
    
    # 检查安装和运行状态
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
    echo -e "  ${Green_font_prefix}1.${Font_color_suffix} 安装 Shadowsocks Rust"
    echo -e "  ${Green_font_prefix}2.${Font_color_suffix} 更新 Shadowsocks Rust"
    echo -e "  ${Green_font_prefix}3.${Font_color_suffix} 卸载 Shadowsocks Rust"
    echo
    echo -e "${Cyan_font_prefix}◆ 服务控制${Font_color_suffix}"
    echo -e "  ${Green_font_prefix}4.${Font_color_suffix} 启动 Shadowsocks Rust"
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
Start_Menu