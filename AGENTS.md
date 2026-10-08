# AGENTS.md — SoftEtherVPN（含自研 IKEv2 响应端）

SoftEther VPN fork（dev 分支）。本仓库的活跃工作集中在 `src/Cedar/Proto_IKEv2.c/h`——**自研的 IKEv2 (RFC 7296) 响应端**，替换了上游的半成品；已完成 PSK + EAP-MSCHAPv2 + IPC 进 Hub + 虚拟 IP + ESP 数据面 + RFC 7383 分片，经 strongSwan 5.9/6.1、Apple（macOS 系统客户端）、Android 14（平台 IKE）三方实测。

## 关键文件

```
src/Cedar/Proto_IKEv2.c/h     IKEv2 状态机（单线程，IKE_SERVER 驱动）
src/Cedar/Proto_IkePacket.c/h IKEv1/v2 共用编解码（SA/KE/Notify/TS/CP/EAP/SK…）
src/Cedar/Proto_IKE.c/h       分流入口 + IKE_SA 生命周期 + 中断
src/Cedar/Proto_IPsec.c       ESP 数据面 / UDP 500/4500 listener
src/Cedar/Proto_PPP.c         MSCHAPv2 原语（MsChapV2_* / NtLmSecureHash）
src/bin/hamcore/strtable_en.stb  日志词条（LI2_*）
```

## 构建与部署（Windows 本机）

```bat
cd out\build\x64-native
build_vpnserver.bat                :: vcvars64 + cmake --build（ninja）
:: 改过 strtable_*.stb 后【必须】在构建之后重跑（绝对路径，相对路径 tinydir 报错）：
src\hamcorebuilder\hamcorebuilder.exe hamcore.se2 C:\...\SoftEtherVPN\src\bin\hamcore
```

- **CMake 每次构建会重新生成 hamcore.se2**，覆盖手工产物——hamcorebuilder 永远最后跑。
- 运行：`vpnserver.exe /usermode_hidetray`（工作目录 = out\build\x64-native；非提权可跑，但历史上偶发"必须提权"，卡死无日志时先怀疑权限）。链接前先 `taskkill /IM vpnserver.exe /F`（运行中锁 exe）。
- **部署依赖**：工作目录需有 `ikev2_cert_chain.pem`（服务端证书的中间证书链，随 CERT 载荷下发；Android 不做 AIA 抓取，缺链即拒）。证书本体（ServerX/ServerK）经管理端口 ServerCertSet 设置，须 RSA 2048 + SAN=客户端所拨域名（当前 LE `vpn.xeecn.com`）。

## IKEv2 实现要点（改动前必读）

- 用户路由：EAP 身份 `user@hub`（PPParseUsername；bare 用户名走 L2TP_DefaultHub 回退）。MSCHAPv2 校验直读 hub 用户库；IPC 登录用 tagged password；MSK 是 64 字节 strongSwan 布局。
- **请求载荷解析要用 `pr`（IkeParse 重解析那份），不能用 `header`——header 的 PayloadList 已被前序消费**（N(16430) 检测曾栽在这里）。
- IDr：有证书时发 ID_FQDN(证书CN)，否则回退地址 ID（Android 严格校验 IDr==期望身份）。
- EAP 模式：有证书一律签名 AUTH + CERT 链（Android 不发 CERTREQ，不能拿它当开关）。
- AUTH 的 ASN.1 是**签名算法 OID**（sha256WithRSAEncryption+NULL），不是哈希 OID（Android 拒）。
- RFC 7383 分片：明文 >300B 即分片（块 700B，防 IP 分片在 NAT 路径被丢）；SKF 头 FragNum/Total 各 2 字节 BE；每片独立 IV/加密/整包 ICV；分片响应缓存在 V2FragSendBuffers 供重发。重组按 MessageId，首片重置状态。
- SK 载荷不能走通用链解析器（NextPayload 指向内部载荷）；ICV 覆盖整包。Notify 的 ProtocolId/SPI Size=0（errata 6940）。
- 更多踩坑清单见 Proto_IKEv2.c 内注释与提交历史（阶段1: 8f0effe8，阶段2: 7f8de7d0，Android 兼容五项: 4c6cfae6）。

## 日志

`out\build\x64-native\server_log\vpn_YYYYMMDD.log`（IPsec 日志也在其中，GBK 编码；新日志词条必须进 strtable **并重建 hamcore**，否则打印空行；IPsecLog 需传 c/sa 否则不落盘）。

## 测试环境

- strongSwan 容器 `ikev2test`（ubuntu:24.04）：`testpub`（EAP+pubkey+ISRG root，LAN）、`testpubf`（同但 right=vpn.xeecn.com 走公网）；secrets 需 `eaptest@VPN : EAP "eaptest123"`。容器 hosts/resolv.conf 易失效——`host.docker.internal` 解析失败时往 /etc/hosts 追加宿主机当前 IP 并 `ipsec restart`（charon 会缓存解析结果）。
- 公网路径：`vpn.xeecn.com` → 云服务器 frps(7000) → 本机 frpc（`out\build\x64-native\frp_win\frpc.toml`）→ UDP 500/4500。云侧需 frps 运行 + **安全组 UDP 500/4500 入站**（已加）。
- IKEEXT 系统服务已 disable（否则占 500/4500）。

## 上游关系

dev 分支为主开发线（已含上游合并）；提交信息英文、注明 RFC 章节；GPL 源码（CycloneIPSEC 等）只可参考不可复制。
