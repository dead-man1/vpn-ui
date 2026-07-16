[English](/README.md) | [فارسی](/README_FA.md) | [العربية](/README_AR.md) | [中文](/README_ZH.md) | [Español](/README_ES.md) | [Русский](/README_RU.md) | [Türkçe](/README_TR.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/media/logo.png" alt="VPN-UI Logo" width="260">
</p>

Este proyecto es una versión mejorada del panel **[3X-UI](https://github.com/MHSanaei/3x-ui)** (versión 2.9.3). El objetivo de este proyecto es agregar diversos protocolos y ofrecerlo como un panel integral con soporte para las funciones de **Xray-core**.

## Nuevos protocolos

- PPTP
- L2TP (RAW)
- L2TP/IPsec
- OpenVPN
- OpenConnect (cisco)
- SSTP
- IKEv2
- WireGuard (C)
- MTProto Proxy (Telegram)

## Nuevas funcionalidades

- Función **Client to Client**, incluso como **Cross Inbound** (conexión interna de un usuario L2TP con un usuario OpenVPN)
- Incorporación de los **Encryption** **AES-256-GCM** y **AES-128-GCM** al protocolo **Shadowsocks**
- Soporte para **XHTTP Object** en el **Outbound**
- Script de instalación automática de **[WARP-CLI](https://github.com/Sir-MmD/warp-cli)** (la versión oficial de Cloudflare)
- Núcleo [**Xray-core** parcheado](https://github.com/Sir-MmD/Xray-core) para solucionar el error «Unsupported Cipher» en el protocolo **Shadowsocks**
- Empaquetado de todos los archivos (Geofile, Xray-core y los núcleos del Backend) dentro de un único archivo binario
- Exportación de los enlaces de las cuentas en formato **TXT** y **PDF**
- Posibilidad de **congelar (Freeze)** cuentas
- Incorporación de **checkbox** a los clientes y a los Inbound
- Función **Bulk Operation**:
    * Cambio grupal del volumen de datos de las cuentas
    * Cambio grupal de los días de las cuentas
    * Activación/desactivación grupal de cuentas
    * Eliminación grupal de cuentas
    * Eliminación grupal de Inbounds
    * **Congelar/Descongelar** cuentas de forma grupal

## Sistemas operativos probados


| | Distribución |Versión |Versión |Versión |
|:---:|:---|:---:|:---:|:---:|
| <img src="https://cdn.simpleicons.org/ubuntu" width="32" height="32" alt="Ubuntu"> | **Ubuntu** | `22.04` | `24.04` | `26.04` |
| <img src="https://cdn.simpleicons.org/debian" width="32" height="32" alt="Debian"> | **Debian** | `12` | `13` | |
| <img src="https://cdn.simpleicons.org/fedora" width="32" height="32" alt="Fedora"> | **Fedora** | `43` | `44` | |
| <img src="https://cdn.simpleicons.org/almalinux/2F80ED" width="32" height="32" alt="AlmaLinux"> | **AlmaLinux** | `9` | `10` | |
| <img src="https://cdn.simpleicons.org/rockylinux" width="32" height="32" alt="Rocky Linux"> | **Rocky Linux** | `9` | `10` | |
| <img src="https://cdn.simpleicons.org/archlinux" width="32" height="32" alt="Arch Linux"> | **Arch Linux** | `Rolling` | | |


> [!IMPORTANT]
> Se recomienda instalar el panel siempre en los sistemas operativos probados, ya que es muy probable que los nuevos núcleos no funcionen correctamente en los demás sistemas operativos.

## Instalación del panel

```bash
curl -Ls https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/deploy.sh | sudo bash
```

## Desinstalación del panel

```bash
sudo /opt/vpn-ui/vpn-ui-amd64 --uninstall
```

> [!NOTE]
> La ruta de la base de datos, el servicio **systemd** y todos los puertos predeterminados han cambiado, así que puedes instalar este panel junto a tus otros paneles sin ningún problema.

## Capturas de pantalla

![Vista general](https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/media/overview.png)
![Configuración del núcleo](https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/media/core_Settings.png)


## Cómo interactúan los nuevos protocolos con el núcleo de Xray-core

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

## Cómo RBridge integra los protocolos sin RADIUS

WireGuard (C) y los modos **PSK** / **EAP-TLS** de IKEv2 se autentican con una clave pública o un certificado, por lo que nunca hacen un intercambio con RADIUS y, de otro modo, no tendrían registro de sesión, ni contabilidad de tráfico, ni aplicación del **User Limit**. **RBridge** (Radius Bridge) cubre ese hueco: una vez por cada ciclo de tráfico, su **Sweeper** sondea (poll) los túneles activos de cada protocolo, aplica la cuota (quota), la desactivación y el **User Limit** K por cuenta (expulsando a los sobrantes con evict) y luego reconcilia a los supervivientes en el mismo registro de sesiones **RADIUS** integrado y la misma contabilidad basada en **nftables** que ya usan los protocolos RADIUS. Así, un protocolo basado en claves se comporta igual en uso, cuota y límite de dispositivos, y sale a Internet por el mismo plano de datos **dokodemo-door** de Xray.

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

## Compilación desde el código fuente

```bash
git clone https://github.com/Sir-MmD/vpn-ui.git && cd vpn-ui
./build.sh
```

## Prueba E2E

![Prueba E2E](https://raw.githubusercontent.com/Sir-MmD/vpn-ui/refs/heads/main/media/test_unit.png)

Se ha diseñado para este proyecto una prueba **E2E** completa en Python dentro de la carpeta `test_unit`, que puedes utilizar. Los pasos son los siguientes:

1. Entra en la carpeta `test_unit` e introduce la configuración que desees en `config.toml`.
2. Ejecuta el script `setup.sh`.
3. Coloca el archivo binario compilado dentro de la carpeta `test_subject`.
4. Ejecuta `run.sh` con permisos de `sudo`.

> [!IMPORTANT]
> La prueba E2E completa consume muchísimo tiempo; si solo hiciste un cambio pequeño en el proyecto, es mejor que pruebes únicamente esa parte con el switch `--tests`:

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

Para probar solo en un sistema operativo específico, también puedes usar el switch `--only`:

```bash
sudo ./run.sh --only ubuntu-24
```

## Donaciones

🔹USDC-Polygon: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-BEP20: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-TRC20: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹TRX: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹LTC: ```ltc1qmapmnuf6cq9x679nmu0k4uyq779mxxcwnkgdll```

🔹BTC: ```bc1q62w7lyndzndsp74vj4dsayvun8xnapzq6hx5ea```

🔹ETH: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```
