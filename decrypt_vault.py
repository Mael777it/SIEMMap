#!/usr/bin/env python3
# SIEMMap
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
# SPDX-License-Identifier: MIT
# https://github.com/mael777it/SIEMMap
"""Awaryjne odszyfrowanie kopii sejfu SIEMMap (siemmap-sejf-RRRR-MM-DD.json) bez przeglądarki.
Obsługuje sejf z kontami (v2, opcjonalny plik klucza) i starszy sejf z jednym hasłem (v1).

Użycie:
    pip install cryptography
    python3 decrypt_vault.py siemmap-sejf-2026-09-20.json                       # podsumowanie
    python3 decrypt_vault.py siemmap-sejf-2026-09-20.json -k SIEMMap-klucz-marcin.json
    python3 decrypt_vault.py siemmap-sejf-2026-09-20.json -o dane.json          # zapis JAWNEGO JSON-a (dane wrażliwe!)
    python3 decrypt_vault.py siemmap-sejf-2026-09-20.json --csv hosty.csv       # lista hostów z pokryciem
"""
import argparse, base64, csv, getpass, gzip, hashlib, json, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

b = base64.b64decode
ap = argparse.ArgumentParser(description="Odszyfrowanie kopii sejfu SIEMMap")
ap.add_argument("vault", help="plik siemmap-sejf-*.json z przycisku Eksport")
ap.add_argument("-u", "--login", help="login konta (sejf v2)")
ap.add_argument("-k", "--keyfile", help="plik klucza SIEMMap-klucz-*.json, jeśli konto ma go włączony")
ap.add_argument("-o", "--out", help="zapisz odszyfrowane dane jako JSON (JAWNE, wrażliwe)")
ap.add_argument("--csv", help="zapisz listę hostów do CSV (separator ;)")
a = ap.parse_args()

env = json.load(open(a.vault, encoding="utf-8"))
if env.get("format") != "siem-map-vault":
    sys.exit("To nie jest plik sejfu SIEMMap (brak format=siem-map-vault).")

def kek(material, salt, iters):
    return hashlib.pbkdf2_hmac("sha256", material, salt, iters, 32)

try:
    if (env.get("v") or 1) < 2:
        pw = getpass.getpass("Hasło sejfu: ")
        dk = kek(pw.encode(), b(env["salt"]), env["iter"])
    else:
        login = a.login or input("Login: ")
        u = next((x for x in env["users"] if x["u"].lower() == login.lower()), None)
        if not u:
            sys.exit("Nie ma takiego konta w sejfie.")
        pw = getpass.getpass("Hasło: ")
        mat = pw.encode()
        if u.get("kf"):
            if not a.keyfile:
                sys.exit("To konto wymaga pliku klucza: dodaj -k SIEMMap-klucz-<login>.json")
            raw = open(a.keyfile, encoding="utf-8").read().strip()
            try:
                raw = json.loads(raw)["k"]
            except (ValueError, KeyError, TypeError):
                pass
            mat += b"\x00" + b("".join(raw.split()))
        dk = AESGCM(kek(mat, b(u["salt"]), u["iter"])).decrypt(b(u["wiv"]), b(u["wk"]), None)
    pt = AESGCM(dk).decrypt(b(env["iv"]), b(env["ct"]), None)
except InvalidTag:
    sys.exit("Nieprawidłowy login, hasło lub plik klucza.")

data = json.loads(gzip.decompress(pt) if env.get("gz") else pt)
hosts = data.get("hosts", [])
print(f"Hosty: {len(hosts)} · konta: {len(data.get('users', []))} · wpisy dziennika: {len(data.get('audit', []))}")
types = {}
for h in hosts:
    types[h.get("t", "?")] = types.get(h.get("t", "?"), 0) + 1
for t, n in sorted(types.items(), key=lambda x: -x[1]):
    print(f"  {t:<10} {n}")

if a.out:
    json.dump(data, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"Zapisano JAWNE dane: {a.out}. Usuń plik po użyciu.")
if a.csv:
    with open(a.csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["hostname", "ip", "type", "roles", "tier", "env", "owner", "siem", "ok", "partial", "missing", "verified"])
        for h in hosts:
            st = list((h.get("st") or {}).values())
            w.writerow([h.get("n", ""), h.get("ip", ""), h.get("t", ""), "|".join(h.get("r", [])), h.get("tier", ""), h.get("env", ""),
                        h.get("own", ""), h.get("siem", ""), st.count("ok"), st.count("part"), st.count("no"), h.get("ver", "")])
    print(f"Zapisano listę hostów: {a.csv}")
