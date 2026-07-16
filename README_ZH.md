[English](/README.md) | [فارسی](/README_FA.md) | [العربية](/README_AR.md) | [中文](/README_ZH.md) | [Español](/README_ES.md) | [Русский](/README_RU.md) | [Türkçe](/README_TR.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/media/logo.png" alt="VPN-UI Logo" width="260">
</p>

本项目是 **[3X-UI](https://github.com/MHSanaei/3x-ui)** 面板（2.9.3 版本）的增强版。本项目旨在添加多种协议，并将其打造成一个支持 **Xray-core** 各项功能的综合性面板。

## 新增协议

- PPTP
- L2TP (RAW)
- L2TP/IPsec
- OpenVPN
- OpenConnect (cisco)
- SSTP
- IKEv2
- WireGuard (C)
- MTProto Proxy (Telegram)

## 新增功能

- 支持 **Client to Client** 功能，甚至可以实现 **Cross Inbound**（L2TP 用户与 OpenVPN 用户之间的内部互联）
- 为 **Shadowsocks** 协议新增了 **AES-256-GCM** 和 **AES-128-GCM** 两种 **Encryption**
- 在 **Outbound** 中支持 **XHTTP Object**
- **[WARP-CLI](https://github.com/Sir-MmD/warp-cli)**（Cloudflare 官方版本）自动安装脚本
- 经过[补丁修复的 **Xray-core**](https://github.com/Sir-MmD/Xray-core) 内核，用于修复 **Shadowsocks** 协议中的「Unsupported Cipher」错误
- 将所有文件（Geofile、Xray-core 以及 Backend 内核）打包进单个二进制文件中
- 以 **TXT** 和 **PDF** 格式导出账户链接
- 支持**冻结（Freeze）**账户
- 为客户端和 Inbound 新增 **checkbox**
- **Bulk Operation** 功能：
    * 批量修改账户流量
    * 批量修改账户时长
    * 批量启用/禁用账户
    * 批量删除账户
    * 批量删除 Inbound
    * 批量**冻结/解冻**账户

## 已测试的操作系统


| | 发行版 |版本 |版本 |版本 |
|:---:|:---|:---:|:---:|:---:|
| <img src="https://cdn.simpleicons.org/ubuntu" width="32" height="32" alt="Ubuntu"> | **Ubuntu** | `22.04` | `24.04` | `26.04` |
| <img src="https://cdn.simpleicons.org/debian" width="32" height="32" alt="Debian"> | **Debian** | `12` | `13` | |
| <img src="https://cdn.simpleicons.org/fedora" width="32" height="32" alt="Fedora"> | **Fedora** | `43` | `44` | |
| <img src="https://cdn.simpleicons.org/almalinux/2F80ED" width="32" height="32" alt="AlmaLinux"> | **AlmaLinux** | `9` | `10` | |
| <img src="https://cdn.simpleicons.org/rockylinux" width="32" height="32" alt="Rocky Linux"> | **Rocky Linux** | `9` | `10` | |
| <img src="https://cdn.simpleicons.org/archlinux" width="32" height="32" alt="Arch Linux"> | **Arch Linux** | `Rolling` | | |


> [!IMPORTANT]
> 强烈建议务必将面板安装在已测试的操作系统上；因为新内核在其他操作系统上无法正常工作的可能性很高！

## 安装面板

```bash
curl -Ls https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/deploy.sh | sudo bash
```

## 卸载面板

```bash
sudo /opt/vpn-ui/vpn-ui-amd64 --uninstall
```

> [!NOTE]
> 数据库路径、systemd 服务以及所有默认端口均已更改，因此您可以将本面板与您的其他面板并存安装，而不会产生任何问题。

## 截图

![总览](https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/media/overview.png)
![内核设置](https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/media/core_Settings.png)


## 新增协议与 Xray-core 内核的交互方式

```mermaid
flowchart TB
  Client["VPN Client<br/>(L2TP/IPsec · PPTP · OpenVPN · OpenConnect · SSTP · IKEv2 · WireGuard (C))"]
  TGC["Telegram Client<br/>(MTProto Proxy)"]

  subgraph PANEL["vpn-ui panel — root process"]
    PROC["procmgr<br/>supervises the daemons"]
    RAD["in-binary RADIUS<br/>127.0.0.1:1812 auth · :1813 acct"]
    HOOK["OpenVPN hooks<br/>auth / connect / disconnect / evict"]
    CONF["writes Xray config:<br/>dokodemo-door inbound +<br/>per-account source-IP routing"]
    STAT["reads Xray stats (gRPC)<br/>enforces traffic / device limits"]
  end

  subgraph DAEMON["Bundled VPN daemons (panel children)"]
    D["xl2tpd + strongSwan/charon · pptpd · openvpn · ocserv · accel-ppp<br/>(pppd for L2TP/PPTP · accel-ppp for SSTP · charon for IKEv2)"]
    MT["telemt (MTProto Proxy)<br/>userspace relay: no tunnel, no pool IP"]
  end

  subgraph KERNEL["Linux kernel data plane"]
    IFACE["ppp0 / tun0 / wgc0<br/>client is assigned a pool IP"]
    NFT["nftables mark:<br/>UDP → TPROXY · TCP → REDIRECT"]
    RULE["ip rule fwmark 1 → table 100"]
  end

  subgraph XRAY["Xray-core (bundled, panel-managed)"]
    DOKO["dokodemo-door inbound<br/>sockopt tproxy, mark 255"]
    SOCKS["socks inbound (loopback)<br/>tag = MTProto inbound<br/>username = account"]
    ROUTE{"routing:<br/>match source IP → account<br/>or socks username → account"}
    OUT["outbound<br/>freedom / proxy / WARP"]
  end

  NET["Internet"]

  %% control plane
  Client -->|"tunnel + credentials"| D
  Client -.->|"WireGuard (C): in-kernel wgc, no daemon"| IFACE
  TGC -->|"obfuscated2 / dd / FakeTLS secret"| MT
  D -.->|"MS-CHAPv2 Access-Request"| RAD
  RAD -.->|"Accept + pool IP"| D
  D -.->|"user-pass / client-connect"| HOOK
  HOOK -.->|"lease per-account IP"| D
  PROC --- D
  CONF --> DOKO
  CONF --> ROUTE

  %% data plane
  D -->|"decapsulated packets"| IFACE
  IFACE --> NFT --> RULE --> DOKO
  DOKO --> ROUTE --> OUT --> NET
  MT -->|"relayed TCP, socks user = account"| SOCKS
  SOCKS --> ROUTE

  %% accounting + return
  OUT -.->|"per-account counters"| STAT
  MT -.->|"per-account octets (Prometheus scrape)"| STAT
  STAT -.->|"disconnect over-limit"| RAD
  NET -.->|"replies (symmetric path back)"| OUT
```

## RBridge 如何整合非 RADIUS 协议

WireGuard (C) 以及 IKEv2 的 **PSK** / **EAP-TLS** 模式使用公钥或证书进行认证，因此不会与 RADIUS 进行往返交互；若不加处理，它们将没有会话记录、没有流量计费，也没有 **User Limit** 限制。**RBridge**（Radius Bridge）正好弥补了这一空缺：在每个流量统计周期里，它的 **Sweeper** 会轮询（poll）每个协议的活动隧道，执行配额（quota）、禁用以及每账户的 **User Limit** K（并将多余者用 evict 驱逐），然后把存活的会话汇入 RADIUS 协议本就在用的同一套内置 **RADIUS** 会话注册表与 **nftables** 计费之中。如此一来，基于密钥的协议在用量、配额和设备数限制上表现完全一致，并通过同一个 Xray **dokodemo-door** 数据平面出网。

```mermaid
flowchart TB
  subgraph SRC["Non-RADIUS protocols (public-key / certificate auth, no RADIUS round-trip)"]
    WG["WireGuard (C)<br/>in-kernel, wgctrl-managed"]
    IKE["IKEv2 PSK / EAP-TLS<br/>strongSwan charon"]
  end

  subgraph BRIDGE["RBridge, the Radius Bridge (one pass per traffic tick)"]
    SWEEP["Sweeper.Tick()"]
    P1["1 · Poll live tunnels via each Adapter"]
    P2["2 · Enforce quota + disable<br/>+ User-Limit K + strategy"]
    P3["3 · Reconcile survivors into the Sink"]
  end

  subgraph SINK["Sink, the existing RADIUS session model"]
    REG["in-binary RADIUS<br/>session registry"]
    ACCT["nftables per-account counters<br/>→ client_traffics (usage / quota)"]
  end

  XRAY["Xray-core<br/>source-IP routing → outbound → Internet"]

  %% control plane
  WG -.->|"peers + last-handshake"| P1
  IKE -.->|"active SAs + Framed-IP"| P1
  SWEEP --> P1 --> P2 --> P3
  P2 -.->|"evict: remove peer / terminate SA"| WG
  P2 -.->|"evict: terminate SA"| IKE
  P3 -->|"tunnel IP → account"| REG
  P3 -->|"add / remove counters"| ACCT
  ACCT -.->|"disabled / over-quota"| P2

  %% data plane
  WG ==> XRAY
  IKE ==> XRAY
  ACCT -.- XRAY
```

## 从源码编译

```bash
git clone https://github.com/Sir-MmD/vpn-ui.git && cd vpn-ui
./build.sh
```

## E2E 测试

![E2E 测试](https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/media/test_unit.png)

本项目在 `test_unit` 文件夹中设计了一套完整的、使用 Python 编写的 **E2E** 测试，您可以直接使用它。步骤如下：

1. 进入 `test_unit` 文件夹，在 `config.toml` 中填写您想要的配置。
2. 运行 `setup.sh` 脚本。
3. 将编译好的二进制文件放入 `test_subject` 文件夹中。
4. 以 `sudo` 权限运行 `run.sh`。

> [!IMPORTANT]
> 完整的 E2E 测试非常耗时；如果您只对项目做了一处小改动，最好使用 `--tests` 开关只测试相应的那一部分：

| Test ID | Description |
| :--- | :--- |
| `core-init` | provision kernel modules + packages + xray core |
| `server-setup` | create inbounds + accounts + source-IP routing rules |
| `openvpn` | connect variants + checks + peer reachability (OpenVPN) |
| `l2tp` | connect variants + checks + peer reachability (L2TP/IPsec) |
| `pptp` | connect variants + checks + peer reachability (PPTP) |
| `openconnect` | connect variants + checks + peer reachability + same-NAT user-limit (OpenConnect/ocserv) |
| `sstp` | connect variants + checks + peer reachability (SSTP/accel-ppp, PPP-over-TLS) |
| `ikev2` | connect + checks + peer reachability (IKEv2/IPsec, strongSwan charon; eap-mschapv2 + psk + eap-tls) |
| `wg-c` | connect + checks + peer reachability + per-account usage/termination (WireGuard C, in-kernel wgctrl, gateway /29, + preshared-key mode) |
| `mtproto` | alias: runs every MTProto phase below (MTProto Proxy, telemt) |
| `mtproto-classic` | handshake + relay to a real Telegram DC + wrong-secret control + usage (obfuscated2) |
| `mtproto-secure` | same, "dd" random-padding secret |
| `mtproto-tls` | same + FakeTLS ServerHello HMAC verified, "ee" secret |
| `mtproto-toggle` | editing an account's modes takes effect on the RUNNING daemon (no restart) |
| `bulk-ops` | bulk client add/sub/enable/disable + TXT/PDF export via API |
| `backup-restore` | DB export + import round-trip |
| `warp-socks` | Cloudflare warp-cli SOCKS install + egress |
| `random-cfg` | `--random` switch: randomize port + creds + webpath, then restore |
| `systemd` | `--systemd` switch: install + run the panel as a systemd unit |
| `uninstall` | `--uninstall` switch: install everything, tear down, assert clean host |
| `export-js` | host-side Node TXT/PDF export test (no VM) |

如果只想在某一个特定的操作系统上进行测试，也可以使用 `--only` 开关：

```bash
sudo ./run.sh --only ubuntu-24
```

## 捐赠

🔹USDC-Polygon: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-BEP20: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-TRC20: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹TRX: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹LTC: ```ltc1qmapmnuf6cq9x679nmu0k4uyq779mxxcwnkgdll```

🔹BTC: ```bc1q62w7lyndzndsp74vj4dsayvun8xnapzq6hx5ea```

🔹ETH: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```
