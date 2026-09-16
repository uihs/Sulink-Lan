# Sulink Lan

把分散在各地的电脑连成一张私有局域网。一个世界，一个网络。

## 功能

- 零配置：无需账号、无需注册码，安装即连
- P2P 直连：设备之间优先 UDP 打洞直连，失败自动走中继
- 固定虚拟 IP：每台设备绑定 10.x.x.x，重连不变
- 端到端加密：信令 HMAC-SHA256 认证，数据面 AES-GCM 加密
- 公网访问：内置 NPS 隧道，把本机端口暴露到公网
- Web 管理：浏览器管理在线设备、隧道、公告

## 下载

Windows 客户端：[sulink-lan-client.exe](https://oss.sulink.ltd/sulink-lan-client.exe)

单文件 exe，解压即用，删除文件夹即卸载。

## 使用

1. 下载并运行 `sulink-lan-client.exe`
2. 点「连接」
3. 自动获得虚拟 IP，和其他设备互访

## 构建

需要 Go 1.24+：

```bash
go build -trimpath -ldflags "-H windowsgui -s -w" -o sulink-lan-client.exe ./cmd/sulink-gui
```

## 技术栈

- Go
- Wintun（虚拟网卡）
- NPS（内网穿透）
