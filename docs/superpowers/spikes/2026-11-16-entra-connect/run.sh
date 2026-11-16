#!/bin/bash
# Task 0 spike (#6649): vendored Connector/C 3.3.8 + Entra token against Azure MySQL.
# Runs inside ubuntu:24.04. /src = repo (ro), /stepb = this dir (ro), /t = token + CA (ro).
# Usage, from the repo root ($T = private dir, chmod 700; ca.pem = a CA bundle with DigiCert Global Root G2):
#   umask 077; az account get-access-token --resource-type oss-rdbms --query accessToken -o tsv > $T/token
#   docker run --rm -v "$PWD":/src:ro -v "$PWD/docs/superpowers/spikes/2026-11-16-entra-connect":/stepb:ro \
#     -v $T:/t:ro ubuntu:24.04 bash /stepb/run.sh <server>.mysql.database.azure.com <entra-user-or-group>; rm -f $T/token
# Expected: "CURRENT_USER ..." on success; 9106 means the token arrived but the principal is not mapped.
set -euo pipefail
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential cmake patch perl python3 util-linux zlib1g-dev ca-certificates >/dev/null

B=/build
mkdir -p $B/src $B/include $B/deps
touch $B/src/proxysql_global.cpp
cp /src/include/makefiles_*.mk $B/include/
cp -a /src/common_mk $B/
cp /src/deps/Makefile $B/deps/
cp -a /src/deps/libssl /src/deps/mariadb-client-library /src/deps/artifacts $B/deps/
mkdir -p $B/deps/duckdb && cp /src/deps/duckdb/build.mk $B/deps/duckdb/
# Drop anything a macOS build left behind; build from the tarballs only.
rm -rf $B/deps/mariadb-client-library/mariadb-connector-c-*/ $B/deps/libssl/openssl-*/

make -C $B/deps -j"$(nproc)" DEPS_MODE=source mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a > /tmp/build.log 2>&1 \
	|| { tail -40 /tmp/build.log; exit 1; }

MC=$B/deps/mariadb-client-library/mariadb_client
SSL=$B/deps/libssl/openssl
gcc -o /tmp/entra_connect /stepb/entra_connect.c \
	-I$MC/include -I$SSL/include \
	$MC/libmariadb/libmariadbclient.a $SSL/libssl.a $SSL/libcrypto.a -lz -lpthread -ldl

/tmp/entra_connect "$1" "$2" /t/token /t/ca.pem
