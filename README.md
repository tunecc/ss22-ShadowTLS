# 使用

```bash
wget -N --no-check-certificate https://raw.githubusercontent.com/tunecc/ss22-ShadowTLS/refs/heads/main/ss22.sh && chmod +x ss22.sh && ./ss22.sh
```

# 特点

## 自动根据系统架构添加来判断是否添加 ` ExecStartPre=/bin/sh -c "ulimit -n 51200"`

` ExecStartPre=/bin/sh -c "ulimit -n 51200"`的作用（大模型的回答）

```txt
ExecStartPre=/bin/sh -c "ulimit -n 51200" 是在 systemd 服务单元文件中用于在启动主服务进程前设置资源限制的命令。其核心作用是通过 ulimit -n 51200 将进程的最大可打开文件描述符数量（nofile）临时设置为 51200。以下是具体作用分析：

1. 解决文件描述符不足问题
当服务需要处理高并发连接（如 Web 服务器、数据库等）时，系统默认的文件描述符限制（通常为 1024）可能导致 Too many open files 错误，进而引发服务崩溃或性能下降 。
通过 ulimit -n 51200，在服务启动前临时调高限制，确保进程能处理更多文件或网络连接 。
2. 临时性资源限制调整
ulimit 命令默认仅对当前 Shell 会话生效。在 ExecStartPre 中执行该命令，可确保仅在服务启动时应用此设置，而不会影响系统全局或其他进程这种设置方式适用于需要动态调整的场景，但重启服务后需重新执行。
3. 与 systemd 资源管理的配合
systemd 服务默认不继承用户的 ulimit 设置。即使通过 /etc/security/limits.conf 全局配置了资源限制，某些服务（尤其是以守护进程方式运行的）仍需在服务文件中显式设置 。
直接通过 ExecStartPre 设置 ulimit 是一种快速生效的临时方案，但更推荐在 [Service] 段使用 LimitNOFILE=51200 等参数进行永久配置

总结
该命令主要用于临时提升服务进程的文件描述符上限，适用于快速解决高并发场景下的资源限制问题。但长期稳定的方案应结合系统级配置（如 sysctl）和服务文件中的 LimitNOFILE 参数
```

## 高版本内核安装ShadowTLS，CPU占用100%

见这个[issue](https://github.com/ihciah/shadow-tls/issues/109)，我不知道多低的内核才不会导致：高版本内核加上使用 io_uring 导致的 iowait 高，所以没有做判断，直接添加 `Environment=MONOIO_FORCE_LEGACY_DRIVER=1` 了

## 定时重启

安装脚本自动设置了 5:00 和 5:05 重启服务，可修改为其他时间，避免奇奇怪怪的bug

## 鸣谢

我的脚本是基于下面的大佬开发的修改的，感谢他们的贡献
https://github.com/xOS/Shadowsocks-Rust （安装Shadowsocks-Rust）
https://github.com/Kismet0123/ShadowTLS-Manager （安装ShadowTLS-Manager）
https://github.com/jinqians/ss-2022.sh （Shadowsocks Rust 和 ShadowTLS结合）

全程用学生包白嫖的 GitHub Copilot（Claude 3.7 Sonnet Thinking）写出的脚本

感谢各位佬