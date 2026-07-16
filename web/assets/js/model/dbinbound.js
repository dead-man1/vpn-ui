class DBInbound {

    constructor(data) {
        this.id = 0;
        this.userId = 0;
        this.up = 0;
        this.down = 0;
        this.total = 0;
        this.allTime = 0;
        this.remark = "";
        this.enable = true;
        this.expiryTime = 0;
        this.trafficReset = "never";
        this.lastTrafficResetTime = 0;

        this.listen = "";
        this.port = 0;
        this.protocol = "";
        this.settings = "";
        this.streamSettings = "";
        this.tag = "";
        this.sniffing = "";
        this.clientStats = ""
        if (data == null) {
            return;
        }
        ObjectUtil.cloneProps(this, data);
    }

    get totalGB() {
        return NumberFormatter.toFixed(this.total / SizeFormatter.ONE_GB, 2);
    }

    set totalGB(gb) {
        this.total = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
    }

    get isVMess() {
        return this.protocol === Protocols.VMESS;
    }

    get isVLess() {
        return this.protocol === Protocols.VLESS;
    }

    get isTrojan() {
        return this.protocol === Protocols.TROJAN;
    }

    get isSS() {
        return this.protocol === Protocols.SHADOWSOCKS;
    }

    get isMixed() {
        return this.protocol === Protocols.MIXED;
    }

    get isHTTP() {
        return this.protocol === Protocols.HTTP;
    }

    get isWireguard() {
        return this.protocol === Protocols.WIREGUARD;
    }

    get isL2tp() {
        return this.protocol === Protocols.L2TP;
    }

    get isPptp() {
        return this.protocol === Protocols.PPTP;
    }

    get isOpenvpn() {
        return this.protocol === Protocols.OPENVPN;
    }

    get address() {
        let address = location.hostname;
        if (!ObjectUtil.isEmpty(this.listen) && this.listen !== "0.0.0.0") {
            address = this.listen;
        }
        return address;
    }

    get _expiryTime() {
        if (this.expiryTime === 0) {
            return null;
        }
        return moment(this.expiryTime);
    }

    set _expiryTime(t) {
        if (t == null) {
            this.expiryTime = 0;
        } else {
            this.expiryTime = t.valueOf();
        }
    }

    get isExpiry() {
        return this.expiryTime < new Date().getTime();
    }

    invalidateCache() {
        this._cachedInbound = null;
        this._clientStatsMap = null;
    }

    toInbound() {
        if (this._cachedInbound) {
            return this._cachedInbound;
        }

        let settings = {};
        if (!ObjectUtil.isEmpty(this.settings)) {
            settings = JSON.parse(this.settings);
        }

        let streamSettings = {};
        if (!ObjectUtil.isEmpty(this.streamSettings)) {
            streamSettings = JSON.parse(this.streamSettings);
        }

        let sniffing = {};
        if (!ObjectUtil.isEmpty(this.sniffing)) {
            sniffing = JSON.parse(this.sniffing);
        }

        const config = {
            port: this.port,
            listen: this.listen,
            protocol: this.protocol,
            settings: settings,
            streamSettings: streamSettings,
            tag: this.tag,
            sniffing: sniffing,
            clientStats: this.clientStats,
        };

        this._cachedInbound = Inbound.fromJson(config);
        return this._cachedInbound;
    }

    getClientStats(email) {
        if (!this._clientStatsMap) {
            this._clientStatsMap = new Map();
            if (this.clientStats && Array.isArray(this.clientStats)) {
                for (const stats of this.clientStats) {
                    this._clientStatsMap.set(stats.email, stats);
                }
            }
        }
        return this._clientStatsMap.get(email);
    }

    isMultiUser() {
        switch (this.protocol) {
            case Protocols.VMESS:
            case Protocols.VLESS:
            case Protocols.TROJAN:
            case Protocols.HYSTERIA:
            case Protocols.L2TP:
            case Protocols.PPTP:
            case Protocols.OPENVPN:
            case Protocols.OPENCONNECT:
            case Protocols.SSTP:
                return true;
            case Protocols.IKEV2:
                // Every ikev2 mode is account-based. eap-mschapv2 = many accounts;
                // psk and eap-tls = one email-only account (routing, usage, quota,
                // and User-Limit attribution). Single-client gating lives in the UI.
                return true;
            case Protocols.WGC:
                // WireGuard (C) is account-based (email identity, one keypair per account).
                return true;
            case Protocols.MTPROTO:
                // MTProto Proxy is account-based: one secret per account, many
                // accounts per inbound (the proxy matches the presented secret).
                return true;
            case Protocols.SHADOWSOCKS:
                return this.toInbound().isSSMultiUser;
            default:
                return false;
        }
    }

    // ikev2 auth-mode helpers used to gate per-account UI. The protocol check
    // short-circuits so toInbound() is only parsed for ikev2 rows.
    isIkev2Psk() {
        return this.protocol === Protocols.IKEV2 &&
            this.toInbound().settings.authMode === 'psk';
    }

    isIkev2EapTls() {
        return this.protocol === Protocols.IKEV2 &&
            this.toInbound().settings.authMode === 'eap-tls';
    }

    // psk and eap-tls are both single-account modes (one email-only client).
    isIkev2SingleClient() {
        return this.isIkev2Psk() || this.isIkev2EapTls();
    }

    hasLink() {
        switch (this.protocol) {
            case Protocols.VMESS:
            case Protocols.VLESS:
            case Protocols.TROJAN:
            case Protocols.SHADOWSOCKS:
            case Protocols.HYSTERIA:
                return true;
            case Protocols.MTPROTO:
                // MTProto accounts have real tg:// links (one per enabled mode), so
                // they use the shared QR modal. Whether a GIVEN account has any is a
                // per-client question the caller gates on, see aClientTable.
                return true;
            default:
                return false;
        }
    }

    genInboundLinks(remarkModel) {
        const inbound = this.toInbound();
        return inbound.genInboundLinks(this.remark, remarkModel);
    }
}