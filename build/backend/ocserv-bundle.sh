#!/bin/sh
#
# build/backend/ocserv-bundle.sh — build a static musl ocserv (OpenConnect server).
#
# Runs INSIDE an Alpine (musl) container. ocserv is NOT packaged by Alpine (any
# repo), so it is built from source (autotools; 1.3.0 ships ./configure, not
# meson). The goal is a single, fully statically-linked binary (like
# openvpn/xl2tpd/pptpd) that drops into
# backend/bin/<arch>/ocserv and is embedded via //go:embed — no host libc / no
# per-distro package.
#
# Dep strategy (musl-static):
#   - radcli (RADIUS)          -> Alpine radcli-dev ships libradcli.a         (apk)
#   - libev                    -> Alpine libev-dev  ships libev.a             (apk)
#   - nettle, gmp, lz4,        -> Alpine *-static packages                    (apk)
#     libseccomp, unistring
#   - talloc, protobuf-c, pcl  -> ocserv's own bundled copies (-Dlocal-*)     (source)
#   - GnuTLS                   -> NOT packaged static  -> built from source,   (source)
#       self-contained via --with-included-libtasn1 --with-included-unistring
#       and --without-p11-kit (drops the dlopen'd PKCS#11 module).
#
# Output: /out/ocserv (verified `statically linked`). Consumed by backend.go's
# Daemons list once {Name:"ocserv"} is added there.
#
# NOTE: this is the Phase-0 build spike for the OpenConnect feature. If static
# GnuTLS proves unworkable, the fallback is a relocatable musl tree (like
# pppd-bundle.sh / libreswan-bundle.sh) shipping ocserv + its .so deps + loader.
set -eu

ARCH="${ARCH:-x86_64}"
GNUTLS_VER="${GNUTLS_VER:-3.8.13}"     # matches Alpine 3.22's gnutls; source build for the .a
OCSERV_VER="${OCSERV_VER:-1.3.0}"

echo "== ocserv-bundle: arch=$ARCH gnutls=$GNUTLS_VER ocserv=$OCSERV_VER =="

# --- toolchain + static deps from Alpine ---------------------------------------
apk add --no-cache \
    build-base linux-headers pkgconf git wget file xz \
    meson ninja samurai gperf \
    nettle-dev nettle-static gmp-dev gmp-static \
    libidn2-static libunistring-static \
    lz4-dev lz4-static \
    libseccomp-dev libseccomp-static \
    libev-dev radcli-dev \
    readline-dev readline-static ncurses-dev ncurses-static \
    zlib-dev zlib-static >/dev/null

# --- GnuTLS (static, self-contained) -------------------------------------------
# --with-included-{libtasn1,unistring} pulls those into libgnutls.a so we don't
# need their (missing) -static apk packages. --without-p11-kit drops the only
# dlopen'd dep. nettle/gmp come from the static apk archives above.
if [ -f /usr/local/lib/pkgconfig/gnutls.pc ]; then
  echo "== gnutls static already present (cached /usr/local) — skipping build =="
else
cd /tmp
wget -q "https://www.gnupg.org/ftp/gcrypt/gnutls/v${GNUTLS_VER%.*}/gnutls-${GNUTLS_VER}.tar.xz"
tar xf "gnutls-${GNUTLS_VER}.tar.xz"
cd "gnutls-${GNUTLS_VER}"
./configure --prefix=/usr/local \
    --enable-static --disable-shared \
    --without-p11-kit \
    --with-included-libtasn1 --with-included-unistring \
    --disable-doc --disable-tests --disable-tools --disable-nls \
    --disable-guile --disable-libdane --disable-cxx \
    --without-tpm --without-tpm2 --disable-full-test-suite >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
echo "== gnutls static installed =="
fi

# --- ocserv (autotools, fully static) ------------------------------------------
# ocserv 1.3.0 is autotools (NOT meson). RADIUS is auto-enabled when radcli is
# found (radcli-dev ships libradcli.a + radcli.pc); --without-radius would drop
# it. Use ocserv's bundled talloc/protobuf-c/PCL so we don't need their static
# apk archives. Point pkg-config at our static GnuTLS in /usr/local and force
# --static so gnutls.pc emits its whole transitive static graph (nettle/gmp/…).
cd /tmp
wget -q "https://www.infradead.org/ocserv/download/ocserv-${OCSERV_VER}.tar.xz" \
  || wget -q "https://ftp.infradead.org/pub/ocserv/ocserv-${OCSERV_VER}.tar.xz"
tar xf "ocserv-${OCSERV_VER}.tar.xz"
cd "ocserv-${OCSERV_VER}"

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
export PKG_CONFIG="pkgconf --static"

# --disable-seccomp: static libseccomp.a carries a gperf-generated `in_word_set`
# that clashes ("multiple definition") with ocserv's own gperf HTTP-header parser
# under static link. seccomp only powers the optional isolate-workers syscall
# sandbox; dropping it keeps parity with our other bundled daemons (openvpn/pppd
# have no such sandbox). Re-add later via a libseccomp source-rebuild that renames
# the symbol if per-worker seccomp is wanted.
./configure \
    --sysconfdir=/etc \
    --with-local-talloc \
    --without-protobuf \
    --without-pcl-lib \
    --without-maxmind \
    --without-libwrap \
    --without-gssapi \
    --disable-seccomp \
    LDFLAGS="-static -s" \
    LIBS="-Wl,--start-group -lreadline -lncurses -Wl,--end-group"
echo "== ocserv ./configure summary =="
grep -iE "radius|gnutls|seccomp|lz4|talloc|protobuf|pcl|compat" config.log | grep -iE "yes|no|enabled|disabled|found" | head -20 || true
make -j"$(nproc)"

mkdir -p /out
cp src/ocserv /out/ocserv
cp src/occtl/occtl /out/occtl 2>/dev/null || cp src/occtl /out/occtl 2>/dev/null || true
strip /out/ocserv /out/occtl 2>/dev/null || true

echo "== ocserv built =="
file /out/ocserv
ldd /out/ocserv 2>&1 || echo "  (ldd: not a dynamic executable — good)"
/out/ocserv --version 2>&1 | head -12 || true
ls -lh /out/ocserv
