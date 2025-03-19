#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="1.5.0"
filepath=$(cd "$(dirname "$0")"; pwd)
file_1=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
FOLDER="/etc/ss-rust"
FILE="/usr/local/bin/ss-rust"
CONF="/etc/ss-rust/config.json"
Now_ver_File="/etc/ss-rust/ver.txt"
Local="/etc/sysctl.d/local.conf"

Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Green_background_prefix="\033[42;37m"
Red_background_prefix="\033[41;37m"
Font_color_suffix="\033[0m"
Yellow_font_prefix="\033[0;33m"
Cyan_font_prefix="\033[36m"
Blue_font_prefix="\033[34m"
Purple_background_prefix="\033[45;37m"

Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Yellow_font_prefix}[注意]${Font_color_suffix}"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。" && exit 1
}

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
    fi
}

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

#开启系统 TCP Fast Open
enable_systfo() {
	kernel=$(uname -r | awk -F . '{print $1}')
	if [ "$kernel" -ge 3 ]; then
		echo 3 >/proc/sys/net/ipv4/tcp_fastopen
		[[ ! -e $Local ]] && echo "fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_ecn=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.d/local.conf && sysctl --system >/dev/null 2>&1
	else
		echo -e "$Error 系统内核版本过低，无法支持 TCP Fast Open ！"
	fi
}

check_installed_status(){
	[[ ! -e ${FILE} ]] && echo -e "${Error} Shadowsocks Rust 没有安装，请检查！" && Before_Start_Menu
}

check_status(){
	status=$(systemctl status ss-rust | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
}

check_new_ver(){
	new_ver=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases| jq -r '[.[] | select(.prerelease == false) | select(.draft == false) | .tag_name] | .[0]')
	[[ -z ${new_ver} ]] && echo -e "${Error} Shadowsocks Rust 最新版本获取失败！" && exit 1
	echo -e "${Info} 检测到 Shadowsocks Rust 最新版本为 [ ${new_ver} ]"
}

check_ver_comparison(){
	now_ver=$(cat ${Now_ver_File} 2>/dev/null)
	if [[ "${now_ver}" != "${new_ver}" ]]; then
		echo -e "${Info} 发现 Shadowsocks Rust 已有新版本 [ ${new_ver} ]，旧版本 [ ${now_ver} ]"
		read -e -p "是否更新 ？ [Y/n]：" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ $yn == [Yy] ]]; then
			check_status
			\cp "${CONF}" "/tmp/config.json"
			Download
			mv -f "/tmp/config.json" "${CONF}"
			Restart
		fi
	else
		echo -e "${Info} 当前 Shadowsocks Rust 已是最新版本 [ ${new_ver} ] ！" && exit 1
	fi
}

# 官方源
stable_Download() {
	echo -e "${Info} 默认开始下载官方源 Shadowsocks Rust ……"
	wget --no-check-certificate -N "https://github.com/shadowsocks/shadowsocks-rust/releases/download/${new_ver}/shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz"
	if [[ ! -e "shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz" ]]; then
		echo -e "${Error} Shadowsocks Rust 官方源下载失败！"
		return 1 && exit 1
	else
		tar -xvf "shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz"
	fi
	if [[ ! -e "ssserver" ]]; then
		echo -e "${Error} Shadowsocks Rust 解压失败！"
		echo -e "${Error} Shadowsocks Rust 安装失败 !"
		return 1 && exit 1
	else
		rm -rf "shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz"
        chmod +x ssserver
	    mv -f ssserver "${FILE}"
	    rm sslocal ssmanager ssservice ssurl 2>/dev/null
	    echo "${new_ver}" > ${Now_ver_File}
        echo -e "${Info} Shadowsocks Rust 主程序下载安装完毕！"
		return 0
	fi
}

# 备用源
backup_Download() {
	echo -e "${Info} 试图请求 备份源(旧版本) Shadowsocks Rust ……"
	wget --no-check-certificate -N "https://raw.githubusercontent.com/xOS/Others/master/shadowsocks-rust/v1.14.1/shadowsocks-v1.14.1.${arch}-unknown-linux-gnu.tar.xz"
	if [[ ! -e "shadowsocks-v1.14.1.${arch}-unknown-linux-gnu.tar.xz" ]]; then
		echo -e "${Error} Shadowsocks Rust 备份源(旧版本) 下载失败！"
		return 1
	else
		tar -xvf "shadowsocks-v1.14.1.${arch}-unknown-linux-gnu.tar.xz"
	fi
	if [[ ! -e "ssserver" ]]; then
		echo -e "${Error} Shadowsocks Rust 备份源(旧版本) 解压失败 !"
		echo -e "${Error} Shadowsocks Rust 备份源(旧版本) 安装失败 !"
		return 1
	else
		rm -rf "shadowsocks-v1.14.1.${arch}-unknown-linux-gnu.tar.xz"
		chmod +x ssserver
	    mv -f ssserver "${FILE}"
	    rm sslocal ssmanager ssservice ssurl 2>/dev/null
		echo "v1.14.1" > ${Now_ver_File}
		echo -e "${Info} Shadowsocks Rust 备份源(旧版本) 主程序下载安装完毕！"
		return 0
	fi
}

Download() {
	if [[ ! -e "${FOLDER}" ]]; then
		mkdir "${FOLDER}"
	fi
	stable_Download
	if [[ $? != 0 ]]; then
		backup_Download || return 1
	fi
}

Service(){
    # 检测宿主机虚拟化类型
    local virt_type
    virt_type="$(systemd-detect-virt 2>/dev/null || echo "unknown")"
    
    # 准备服务文件内容
    local service_content='
[Unit]
Description= Shadowsocks Rust Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
[Service]
LimitNOFILE=32767 
Type=simple
User=root
Restart=on-failure
RestartSec=5s
DynamicUser=true'
    
    # 根据虚拟化类型决定是否添加 ExecStartPre
    if [[ "$virt_type" == "kvm" ]]; then
        service_content+='
ExecStartPre=/bin/sh -c '\''ulimit -n 51200'\'''
        echo -e "${Info} 检测到KVM虚拟化环境，已添加 ExecStartPre 配置以提高性能"
    else
        echo -e "${Info} 检测到${virt_type}虚拟化环境，不添加 ExecStartPre 配置"
    fi
    
    # 完成服务文件内容
    service_content+='
ExecStart=/usr/local/bin/ss-rust -c /etc/ss-rust/config.json
[Install]
WantedBy=multi-user.target'
    
    # 写入服务文件
    echo "$service_content" > /etc/systemd/system/ss-rust.service
    
    # 启用并立即启动服务
    systemctl enable --now ss-rust
    echo -e "${Info} Shadowsocks Rust 服务配置完成！"
}

Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		yum update -y
		yum install jq gzip wget curl unzip xz openssl -y
	else
		apt-get update
		apt-get install jq gzip wget curl unzip xz-utils openssl -y
	fi
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime 2>/dev/null
}

Write_config(){
	cat > ${CONF}<<-EOF
{
    "server": "::",
    "server_port": ${port},
    "password": "${password}",
    "method": "${cipher}",
    "fast_open": ${tfo},
    "mode": "tcp_and_udp",
    "user":"nobody",
    "timeout":300,
    "nameserver":"1.1.1.1"
}
EOF
}

Read_config(){
	[[ ! -e ${CONF} ]] && echo -e "${Error} Shadowsocks Rust 配置文件不存在！" && exit 1
	port=$(cat ${CONF} | jq -r '.server_port')
	password=$(cat ${CONF} | jq -r '.password')
	cipher=$(cat ${CONF} | jq -r '.method')
	tfo=$(cat ${CONF} | jq -r '.fast_open')
}

Set_port(){
	while true
	do
	  echo -e "${Tip} 本步骤不涉及系统防火墙端口操作，请手动放行相应端口！"
	  echo -e "请输入 Shadowsocks Rust 端口 [1-65535]"
	  read -e -p "(默认随机生成)：" port
	  
	  if [[ -z "${port}" ]]; then
	    port=$(shuf -i 1025-65535 -n 1)
	  fi
	  
	  # 检查是否为有效数字
	  echo $((${port}+0)) &>/dev/null
	  if [[ $? -eq 0 ]]; then
	    # 检查端口范围
	    if [[ ${port} -ge 1 ]] && [[ ${port} -le 65535 ]]; then
	      echo && echo "=================================="
	      echo -e "端口：${Red_background_prefix} ${port} ${Font_color_suffix}"
	      echo "==================================" && echo
	      break
	    else
	      echo "输入错误, 请输入正确的端口。"
	    fi
	  else
	    echo "输入错误, 请输入正确的端口。"
	  fi
	done
}

Set_tfo(){
	echo -e "是否开启 TCP Fast Open ？
==================================
 1. 启用
 2. 禁用 (默认)
=================================="
	read -e -p "(默认:2)：" tfo
	[[ -z "${tfo}" ]] && tfo="2"
	if [[ ${tfo} == "1" ]]; then
		tfo=true
		enable_systfo
	else
		tfo=false
	fi
	echo && echo "=================================="
	echo -e "TCP Fast Open 开启状态：${Red_background_prefix} ${tfo} ${Font_color_suffix}"
	echo "==================================" && echo
}

Set_password(){
	echo "请输入 Shadowsocks Rust 密码 [0-9][a-z][A-Z]"
	read -e -p "(默认自动生成)：" password
	if [[ ${cipher} == "2022-blake3-aes-256-gcm" ]]; then
		[[ -z "${password}" ]] && password=$(openssl rand -base64 32)
	else
		[[ -z "${password}" ]] && password=$(openssl rand -base64 16)
	fi
	echo && echo "=================================="
	echo -e "密码：${Red_background_prefix} ${password} ${Font_color_suffix}"
	echo "==================================" && echo
}

Set_cipher(){
	echo -e "请选择 Shadowsocks Rust 加密方式
==================================	
 ${Green_font_prefix} 1.${Font_color_suffix} aes-128-gcm ${Green_font_prefix}
 ${Green_font_prefix} 2.${Font_color_suffix} aes-256-gcm ${Green_font_prefix}
 ${Green_font_prefix} 3.${Font_color_suffix} chacha20-ietf-poly1305 ${Green_font_prefix}${Font_color_suffix}
 ${Green_font_prefix} 4.${Font_color_suffix} plain ${Red_font_prefix}(不推荐)${Font_color_suffix}
 ${Green_font_prefix} 5.${Font_color_suffix} none ${Red_font_prefix}(不推荐)${Font_color_suffix}
 ${Green_font_prefix} 6.${Font_color_suffix} table
 ${Green_font_prefix} 7.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 8.${Font_color_suffix} aes-256-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-256-ctr 
 ${Green_font_prefix}10.${Font_color_suffix} camellia-256-cfb
 ${Green_font_prefix}11.${Font_color_suffix} rc4-md5
 ${Green_font_prefix}12.${Font_color_suffix} chacha20-ietf
==================================
 ${Tip} AEAD 2022 加密（须v1.15.0及以上版本且密码须经过Base64加密）
==================================	
 ${Green_font_prefix}13.${Font_color_suffix} 2022-blake3-aes-128-gcm ${Green_font_prefix}(推荐)${Font_color_suffix}
 ${Green_font_prefix}14.${Font_color_suffix} 2022-blake3-aes-256-gcm ${Green_font_prefix}(默认)${Font_color_suffix}
 ${Green_font_prefix}15.${Font_color_suffix} 2022-blake3-chacha20-poly1305
 ==================================
 ${Tip} 如需其它加密方式请手动修改配置文件 !" && echo

	read -e -p "(默认: 14. 2022-blake3-aes-256-gcm)：" cipher
	[[ -z "${cipher}" ]] && cipher="14"
	if [[ ${cipher} == "1" ]]; then
		cipher="aes-128-gcm"
	elif [[ ${cipher} == "2" ]]; then
		cipher="aes-256-gcm"
	elif [[ ${cipher} == "3" ]]; then
		cipher="chacha20-ietf-poly1305"
	elif [[ ${cipher} == "4" ]]; then
		cipher="plain"
	elif [[ ${cipher} == "5" ]]; then
		cipher="none"
	elif [[ ${cipher} == "6" ]]; then
		cipher="table"
	elif [[ ${cipher} == "7" ]]; then
		cipher="aes-128-cfb"
	elif [[ ${cipher} == "8" ]]; then
		cipher="aes-256-cfb"
	elif [[ ${cipher} == "9" ]]; then
		cipher="aes-256-ctr"
	elif [[ ${cipher} == "10" ]]; then
		cipher="camellia-256-cfb"
	elif [[ ${cipher} == "11" ]]; then
		cipher="arc4-md5"
	elif [[ ${cipher} == "12" ]]; then
		cipher="chacha20-ietf"
	elif [[ ${cipher} == "13" ]]; then
		cipher="2022-blake3-aes-128-gcm"
	elif [[ ${cipher} == "14" ]]; then
		cipher="2022-blake3-aes-256-gcm"
	elif [[ ${cipher} == "15" ]]; then
		cipher="2022-blake3-chacha20-poly1305"
	else
		cipher="aes-128-gcm"
	fi

	echo && echo "=================================="
	echo -e "加密：${Red_background_prefix} ${cipher} ${Font_color_suffix}"
	echo "==================================" && echo
}

Set(){
	check_installed_status
	echo && echo -e "请选择要修改的配置：
==================================
 ${Green_font_prefix}1.${Font_color_suffix}  修改 端口配置
 ${Green_font_prefix}2.${Font_color_suffix}  修改 加密配置
 ${Green_font_prefix}3.${Font_color_suffix}  修改 密码配置
 ${Green_font_prefix}4.${Font_color_suffix}  修改 TFO 配置
==================================
 ${Green_font_prefix}5.${Font_color_suffix}  修改 全部配置" && echo
	read -e -p "(默认取消)：" modify
	[[ -z "${modify}" ]] && echo "已取消..." && exit 1
	if [[ "${modify}" == "1" ]]; then
		Read_config
		Set_port
		cipher=${cipher}
		password=${password}
		tfo=${tfo}
		Write_config
		Restart
	elif [[ "${modify}" == "2" ]]; then
		Read_config
		Set_cipher
		port=${port}
		password=${password}
		tfo=${tfo}
		Write_config
		Restart
	elif [[ "${modify}" == "3" ]]; then
		Read_config
		cipher=${cipher}
		Set_password
		port=${port}
		tfo=${tfo}
		Write_config
		Restart
	elif [[ "${modify}" == "4" ]]; then
		Read_config
		Set_tfo
		cipher=${cipher}
		port=${port}
		password=${password}
		Write_config
		Restart
	elif [[ "${modify}" == "5" ]]; then
		Read_config
		Set_port
		Set_cipher
		Set_password
		Set_tfo
		Write_config
		Restart
	else
		echo -e "${Error} 请输入正确的数字(1-5)" && exit 1
	fi
}

Install(){
	[[ -e ${FILE} ]] && echo -e "${Error} 检测到 Shadowsocks Rust 已安装！" && Before_Start_Menu
	echo -e "${Info} 开始设置 配置..."
	Set_port
	Set_cipher
	Set_password
	Set_tfo
	echo -e "${Info} 开始安装/配置 依赖..."
	Installation_dependency
	echo -e "${Info} 开始下载/安装..."
	check_new_ver
	Download || { echo -e "${Error} 下载或解压失败，退出安装！"; exit 1; }
	echo -e "${Info} 开始安装系统服务脚本..."
	Service
	echo -e "${Info} 开始写入 配置文件..."
	Write_config
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	Start
	
	echo -e "${Info} 正在设置每日5:00自动重启..."
	RESTART_HOUR="5"
	RESTART_MINUTE="0"
	JOB_LINE="${RESTART_MINUTE} ${RESTART_HOUR} * * * /usr/bin/systemctl restart ss-rust"
	CRONTAB_CONTENT=$(crontab -l 2>/dev/null)

	if echo "${CRONTAB_CONTENT}" | grep -q "${JOB_LINE}"; then
		echo -e "${Info} 已存在每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的任务，无需重复添加。"
	else
		(echo "${CRONTAB_CONTENT}"; echo "${JOB_LINE}") | crontab -
		echo -e "${Info} 已添加每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的计划任务。"
	fi
	
	echo -e "${Info} 启动完成！"
	
	echo -e "\n${YELLOW}===============================================${RESET}"
	echo -e "${GREEN}Shadowsocks Rust 已成功安装!${RESET}"
	echo -e "${YELLOW}===============================================${RESET}"
	echo -e "\n${CYAN}是否需要继续安装 ShadowTLS 进行流量混淆? [Y/n]${RESET}"
	read -r install_stls
	case "$install_stls" in
		[yY][eE][sS]|[yY]|"")
			echo -e "${GREEN}正在准备安装 ShadowTLS...${RESET}"
			install_shadowtls
			;;
		*)
			echo -e "${YELLOW}已跳过 ShadowTLS 安装，如需安装请稍后在菜单中选择安装选项。${RESET}"
			echo -e "${Info} 显示当前配置信息..."
			View
			;;
	esac
	
	echo -e "\n${GREEN}安装过程已完成!${RESET}"
	sleep 2
	Before_Start_Menu
}

Start(){
    check_installed_status
    check_status
    if [[ "$status" == "running" ]]; then
        echo -e "${Info} Shadowsocks Rust 已在运行！"
    else
        systemctl start ss-rust
        check_status
        if [[ "$status" == "running" ]]; then
            echo -e "${Info} Shadowsocks Rust 启动成功！"
        else
            echo -e "${Error} Shadowsocks Rust 启动失败！"
            exit 1
        fi
    fi
    sleep 3s
}

Stop(){
	check_installed_status
	check_status
	[[ "$status" != "running" ]] && echo -e "${Error} Shadowsocks Rust 没有运行，请检查！" && exit 1
	systemctl stop ss-rust
    sleep 3s
    Start_Menu
}

Restart(){
	check_installed_status
	systemctl restart ss-rust
	echo -e "${Info} Shadowsocks Rust 重启完毕 ！"
	sleep 3s
    Start_Menu
}

Update(){
	check_installed_status
	check_new_ver
	check_ver_comparison
	echo -e "${Info} Shadowsocks Rust 更新完毕！"
    sleep 3s
    Start_Menu
}

Uninstall(){
	check_installed_status
	echo "确定要卸载 Shadowsocks Rust ? (Y/N)"
	read -e -p "(回车确认卸载)：" unyn
	[[ -z ${unyn} ]] && unyn="y"
	if [[ ${unyn} == [Yy] ]]; then
		check_status
		[[ "$status" == "running" ]] && systemctl stop ss-rust
        systemctl disable ss-rust
		rm -rf "${FOLDER}"
		rm -rf "${FILE}"
		rm -f /etc/systemd/system/ss-rust.service
        
        # 删除定时重启任务
        echo -e "${Info} 正在检查并删除定时重启任务..."
        crontab_content=$(crontab -l 2>/dev/null)
        if echo "${crontab_content}" | grep -q "systemctl restart ss-rust"; then
            # 删除包含ss-rust重启的行
            echo "${crontab_content}" | grep -v "systemctl restart ss-rust" | crontab -
            echo -e "${Info} 已删除 Shadowsocks Rust 的定时重启任务"
        fi
        
		echo -e "${Info} Shadowsocks Rust 卸载完成！"
        
        if [ -f "/usr/local/bin/shadow-tls" ] && systemctl is-enabled shadowtls &>/dev/null; then

            echo -e "\n${YELLOW}===============================================${RESET}"
            echo -e "${CYAN}检测到系统中已安装 ShadowTLS，是否需要一并卸载? [Y/n]${RESET}"
            read -r uninstall_stls
            case "$uninstall_stls" in
                [yY][eE][sS]|[yY]|"")
                    echo -e "${YELLOW}===============================================${RESET}"
                    uninstall_shadowtls
                    ;;
                *)
                    echo -e "${YELLOW}已跳过 ShadowTLS 卸载。${RESET}"
                    ;;
            esac
        else
            echo -e "\n${YELLOW}系统中未检测到 ShadowTLS 安装，跳过卸载步骤。${RESET}"
        fi
	else
		echo && echo "卸载已取消..." && echo
	fi
    sleep 3s
    Start_Menu
}

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
    rm -f "/usr/local/bin/shadow-tls"
    
    # 删除配置目录
    echo -e "${CYAN}删除配置文件...${RESET}"
    if [ -d "/etc/shadowtls" ]; then
        rm -rf "/etc/shadowtls"
        echo -e "${GREEN}已删除配置目录${RESET}"
    fi
    
    # 删除定时重启任务
    echo -e "${CYAN}检查并删除定时重启任务...${RESET}"
    if crontab -l 2>/dev/null | grep -q "systemctl restart shadowtls"; then
        crontab -l 2>/dev/null | grep -v "systemctl restart shadowtls" | crontab -
        echo -e "${GREEN}已删除定时重启任务${RESET}"
    fi

    systemctl daemon-reload
    
    echo -e "${GREEN}ShadowTLS 已成功卸载${RESET}"
}

getipv4(){
	ipv4=$(wget -qO- -4 -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ipv4}" ]]; then
		ipv4=$(wget -qO- -4 -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ipv4}" ]]; then
			ipv4=$(wget -qO- -4 -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ipv4}" ]]; then
				ipv4="IPv4_Error"
			fi
		fi
	fi
}
getipv6(){
	ipv6=$(wget -qO- -6 -t1 -T2 ifconfig.co)
	if [[ -z "${ipv6}" ]]; then
		ipv6="IPv6_Error"
	fi
}

urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}


View(){
	check_installed_status
	Read_config
	
	# 原始配置显示
	getipv4
	getipv6
	echo -e "\n${Yellow_font_prefix}=== Shadowsocks Rust 配置 ===${Font_color_suffix}"
	[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv4}${Font_color_suffix}"
	[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv6}${Font_color_suffix}"
	echo -e " 端口：${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " 密码：${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " 加密：${Green_font_prefix}${cipher}${Font_color_suffix}"
	echo -e " TFO ：${Green_font_prefix}${tfo}${Font_color_suffix}"
	
	# 检查 ShadowTLS 是否安装并获取配置
	local has_shadowtls=false
	local stls_listen_port=""
	local stls_password=""
	local stls_sni=""
	
	if [ -f "/etc/systemd/system/shadowtls.service" ]; then
		has_shadowtls=true
		echo -e "\n${Yellow_font_prefix}=== ShadowTLS 配置 ===${Font_color_suffix}"
		
		# 从 shadowtls.service 文件中获取配置信息
        stls_listen_port=$(grep -oP '(?<=--listen \[\:\:\]\:)\d+' /etc/systemd/system/shadowtls.service)
		stls_password=$(grep -oP '(?<=--password )\S+' /etc/systemd/system/shadowtls.service)
		stls_sni=$(grep -oP '(?<=--tls )[^:]+(?=:443\b)' /etc/systemd/system/shadowtls.service)

		echo -e " 监听端口：${Green_font_prefix}${stls_listen_port}${Font_color_suffix}"
		echo -e " 密码：${Green_font_prefix}${stls_password}${Font_color_suffix}"
		echo -e " SNI：${Green_font_prefix}${stls_sni}${Font_color_suffix}"
	fi
	
	[[ ! -z "${link_ipv4}" ]] && echo -e "${link_ipv4}"
	[[ ! -z "${link_ipv6}" ]] && echo -e "${link_ipv6}"
	echo -e "\n${Yellow_font_prefix}=== Surge 配置 ===${Font_color_suffix}"
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
		echo -e "$(uname -n) = ss,${ipv4},${port},encrypt-method=${cipher},password=${password},tfo=${tfo},udp-relay=true,ecn=true"
	else
		echo -e "$(uname -n) = ss,${ipv6},${port},encrypt-method=${cipher},password=${password},tfo=${tfo},udp-relay=true,ecn=true"
	fi
	
	# 如果安装了 ShadowTLS，生成合并链接和配置
	if [ "$has_shadowtls" = true ]; then
		# 生成 SS + ShadowTLS 合并链接
		local ss_userinfo=$(echo -n "${cipher}:${password}" | base64 | tr -d '\n')
		local shadow_tls_config="{\"version\":\"3\",\"password\":\"${stls_password}\",\"host\":\"${stls_sni}\",\"port\":\"${stls_listen_port}\",\"address\":\"${ipv4}\"}"
		local shadow_tls_base64=$(echo -n "${shadow_tls_config}" | base64 | tr -d '\n')
		local ss_stls_url="ss://${ss_userinfo}@${ipv4}:${port}?shadow-tls=${shadow_tls_base64}#SS-${ipv4}"

		echo -e "\n${Yellow_font_prefix}=== SS + ShadowTLS 链接 ===${Font_color_suffix}"
		echo -e "${ss_stls_url}"

		echo -e "\n${Yellow_font_prefix}=== Surge Shadowsocks + ShadowTLS 配置 ===${Font_color_suffix}"
		if [[ "${ipv4}" != "IPv4_Error" ]]; then
			echo -e "$(uname -n) = ss, ${ipv4}, ${stls_listen_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=true, udp-port=${port}"
		else
			echo -e "$(uname -n) = ss, ${ipv6}, ${stls_listen_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, udp-relay=tru, udp-port=${port}"
		fi
	fi

	Before_Start_Menu
}

Status(){
	echo -e "${Info} 获取 Shadowsocks Rust 活动日志 ……"
	systemctl status ss-rust
	Before_Start_Menu
}

Update_Shell(){
	echo -e "当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
	sh_new_ver=$(wget --no-check-certificate -qO- "https://raw.githubusercontent.com/tunecc/ss22-ShadowTLS/refs/heads/main/ss22.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 检测最新版本失败 !" && Start_Menu
	if [[ ${sh_new_ver} != ${sh_ver} ]]; then
		echo -e "发现新版本[ ${sh_new_ver} ]，是否更新？[Y/n]"
		read -p "(默认：y)：" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ ${yn} == [Yy] ]]; then
			wget -O ss22.sh --no-check-certificate https://raw.githubusercontent.com/tunecc/ss22-ShadowTLS/refs/heads/main/ss22.sh && chmod +x ss22.sh
			echo -e "脚本已更新为最新版本[ ${sh_new_ver} ]！"
			echo -e "3s后执行新脚本"
            sleep 3s
            bash ss.sh
		else
			echo && echo "	已取消..." && echo
            sleep 3s
            Start_Menu
		fi
	else
		echo -e "当前已是最新版本[ ${sh_new_ver} ] ！"
		sleep 3s
        Start_Menu
	fi
	sleep 3s
    bash ss.sh
}

Before_Start_Menu() {
    echo && echo -n -e "${Yellow_font_prefix}* 按任意键返回主菜单 *${Font_color_suffix}" && read -n 1 -s temp
    echo
    Start_Menu
}

# 设置每日定时重启
Set_daily_restart(){
  echo -e "请输入每日定时重启执行的 小时（0-23 整数）"
  read -e -p "(默认：3)：" RESTART_HOUR
  [[ -z "${RESTART_HOUR}" ]] && RESTART_HOUR="3"
  if ! [[ "${RESTART_HOUR}" =~ ^[0-9]+$ ]] || [ "${RESTART_HOUR}" -lt 0 ] || [ "${RESTART_HOUR}" -gt 23 ]; then
    echo -e "${Error} 小时必须是 0-23 之间的整数！"
    return
  fi

  echo -e "请输入每日定时重启执行的 分钟（0-59 整数）"
  read -e -p "(默认：0)：" RESTART_MINUTE
  [[ -z "${RESTART_MINUTE}" ]] && RESTART_MINUTE="0"
  if ! [[ "${RESTART_MINUTE}" =~ ^[0-9]+$ ]] || [ "${RESTART_MINUTE}" -lt 0 ] || [ "${RESTART_MINUTE}" -gt 59 ]; then
    echo -e "${Error} 分钟必须是 0-59 之间的整数！"
    return
  fi

  JOB_LINE="${RESTART_MINUTE} ${RESTART_HOUR} * * * /usr/bin/systemctl restart ss-rust"
  CRONTAB_CONTENT=$(crontab -l 2>/dev/null)

  # 如果已存在相同任务，则不重复添加
  if echo "${CRONTAB_CONTENT}" | grep -q "${JOB_LINE}"; then
    echo -e "${Info} 已存在每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的任务，无需重复添加。"
  else
    (echo "${CRONTAB_CONTENT}"; echo "${JOB_LINE}") | crontab -
    echo -e "${Info} 已添加每日 ${RESTART_HOUR}:${RESTART_MINUTE} 重启 Shadowsocks-Rust 的计划任务。"
  fi
  sleep 3s
  Start_Menu
}

install_shadowtls() {
    echo -e "${INFO} 开始下载 ShadowTLS 安装脚本..."
    wget -N --no-check-certificate https://raw.githubusercontent.com/tunecc/ss22-ShadowTLS/refs/heads/main/shadowtls.sh
    if [ $? -ne 0 ]; then
        echo -e "${ERROR} ShadowTLS 脚本下载失败！"
        exit 1
    fi
    chmod +x shadowtls.sh
    echo -e "${INFO} 开始安装 ShadowTLS..."
    bash shadowtls.sh
    rm -f shadowtls.sh
    echo -e "${SUCCESS} ShadowTLS 安装完成！"
}

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

    echo -e "${Yellow_font_prefix}================= Shadowsocks Rust 管理脚本 v${sh_ver} =================${Font_color_suffix}"
    echo -e " 当前状态: $status_text"
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
    echo -e "${Yellow_font_prefix}=============================================================${Font_color_suffix}"
    echo
    read -e -p " 请输入数字 [0-11]：" num
    case "$num" in
        0)
            clear
            echo -e "输入 ./ss22.sh 即可运行脚本"
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
