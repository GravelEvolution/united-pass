#!/usr/bin/env bash

set -euo pipefail

secret_file="${1:?local secret file is required}"
db_name="zitadel_dreamup_e2e"
db_role="zitadel_dreamup_e2e"
legacy_admin_role="zitadel_dreamup_e2e_admin"
pg_port="15433"

db_password="$(python3 - "$secret_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    value = json.load(handle)["databasePassword"]
if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
    raise SystemExit("invalid local database password")
print(value, end="")
PY
)"

server_port="$(runuser -u postgres -- psql -p "$pg_port" -Atqc "SHOW port")"
server_addresses="$(runuser -u postgres -- psql -p "$pg_port" -Atqc "SHOW listen_addresses")"
if [ "$server_port" != "$pg_port" ] || [ "$server_addresses" != "localhost" ]; then
    echo "local PostgreSQL boundary check failed" >&2
    exit 41
fi

role_exists="$(runuser -u postgres -- psql -p "$pg_port" -Atqc "SELECT 1 FROM pg_roles WHERE rolname = '$db_role'")"
if [ "$role_exists" = "1" ]; then
    runuser -u postgres -- psql -p "$pg_port" -v ON_ERROR_STOP=1 >/dev/null <<SQL
ALTER ROLE $db_role WITH LOGIN PASSWORD '$db_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20;
SQL
else
    runuser -u postgres -- psql -p "$pg_port" -v ON_ERROR_STOP=1 >/dev/null <<SQL
CREATE ROLE $db_role WITH LOGIN PASSWORD '$db_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20;
SQL
fi

database_exists="$(runuser -u postgres -- psql -p "$pg_port" -Atqc "SELECT 1 FROM pg_database WHERE datname = '$db_name'")"
if [ "$database_exists" != "1" ]; then
    runuser -u postgres -- createdb -p "$pg_port" --owner "$db_role" --encoding UTF8 --template template0 "$db_name"
else
    runuser -u postgres -- psql -p "$pg_port" -v ON_ERROR_STOP=1 -c "ALTER DATABASE $db_name OWNER TO $db_role" >/dev/null
fi

legacy_admin_exists="$(runuser -u postgres -- psql -p "$pg_port" -Atqc "SELECT 1 FROM pg_roles WHERE rolname = '$legacy_admin_role'")"
if [ "$legacy_admin_exists" = "1" ]; then
    legacy_admin_attributes="$(runuser -u postgres -- psql -p "$pg_port" -Atqc "SELECT rolsuper::int::text || rolcreatedb::int::text || rolcreaterole::int::text || rolreplication::int::text || rolbypassrls::int::text || rolconnlimit::text FROM pg_roles WHERE rolname = '$legacy_admin_role'")"
    if [ "$legacy_admin_attributes" != "011002" ]; then
        echo "unexpected legacy bootstrap role attributes" >&2
        exit 43
    fi
    runuser -u postgres -- dropuser -p "$pg_port" "$legacy_admin_role"
fi

owner="$(runuser -u postgres -- psql -p "$pg_port" -Atqc "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '$db_name'")"
attributes="$(runuser -u postgres -- psql -p "$pg_port" -Atqc "SELECT rolsuper::int::text || rolcreatedb::int::text || rolcreaterole::int::text || rolreplication::int::text || rolbypassrls::int::text FROM pg_roles WHERE rolname = '$db_role'")"
if [ "$owner" != "$db_role" ] || [ "$attributes" != "00000" ]; then
    echo "isolated database ownership check failed" >&2
    exit 42
fi

echo ZITADEL_DB_READY
