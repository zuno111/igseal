# -*- coding: utf-8 -*-
import os, sys, datetime, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import igseal_core as c

TMP = "/tmp/igseal_test"
os.makedirs(TMP, exist_ok=True)
ok = True
def check(name, cond):
    global ok
    print(("[PASS] " if cond else "[FAIL] ") + name)
    if not cond: ok = False

# 1. 봉인 -> 해제 정상
files = [("안내문.txt", "납품물입니다. 복사 금지.".encode("utf-8")),
         ("data.json", b'{"a":1,"b":2}'),
         ("logo.bin", os.urandom(2048))]
payload = c.build_payload(files, "pass1234", expiry="2026-12-31", title="테스트납품")
title, exp, got = c.unlock(payload, "pass1234")
check("봉인/해제 라운드트립 파일수", len(got) == 3)
check("원본 일치 txt", got[0][1] == files[0][1])
check("원본 일치 bin", dict(got)["logo.bin"] == dict(files)["logo.bin"])
check("제목/만료 보존", title == "테스트납품" and exp == "2026-12-31")

# 2. 틀린 비번
try:
    c.unlock(payload, "wrong")
    check("틀린 비번 거부", False)
except ValueError:
    check("틀린 비번 거부", True)

# 3. 스텁 append -> 자기 파일에서 읽기
stub = b"MZ" + os.urandom(50000)  # 가짜 PE
exe = c.append_to_stub(stub, payload)
p = os.path.join(TMP, "sealed.exe")
open(p, "wb").write(exe)
read = c.read_payload_from_file(p)
check("append 후 payload 재추출", read == payload)
t2, e2, g2 = c.unlock(read, "pass1234")
check("추출 payload 해제", len(g2) == 3)

# 4. payload 없는 일반 exe
open(os.path.join(TMP, "plain.exe"), "wb").write(stub)
check("payload 없으면 None", c.read_payload_from_file(os.path.join(TMP, "plain.exe")) is None)

# 5. 만료 판정
hdr, _ = c.parse_header(payload)
check("만료 전 not expired", not c.is_expired(hdr, datetime.date(2026, 6, 1)))
check("만료 후 expired", c.is_expired(hdr, datetime.date(2027, 1, 1)))
check("만료일 당일 not expired", not c.is_expired(hdr, datetime.date(2026, 12, 31)))

# 6. 만료 없음(null)
pay2 = c.build_payload([("x.txt", b"hi")], "pw", expiry=None)
h2, _ = c.parse_header(pay2)
check("만료없음 never expired", not c.is_expired(h2, datetime.date(2099, 1, 1)))

# 7. 헤더 변조 탐지
check("정상 헤더 무변조", not c.header_tampered(hdr))
hdr_bad = dict(hdr); hdr_bad["expiry"] = "2099-01-01"
check("만료일 변조 탐지", c.header_tampered(hdr_bad))

# 8. 자기삭제(비윈도우 = 즉시 unlink)
dp = os.path.join(TMP, "todelete.exe")
open(dp, "wb").write(b"x")
c.self_destruct(dp)
check("자기삭제 동작", not os.path.exists(dp))

# 9. 시계 되돌림 탐지
import shutil
cfgbak = os.path.join(TMP, "cfg"); os.makedirs(cfgbak, exist_ok=True)
os.environ["APPDATA"] = cfgbak
pid = c.pkg_id_of(hdr)
# 첫 실행: 미래날짜 기록
c.clock_rolled_back(hdr, datetime.date(2026, 10, 26))
# 되돌림: 과거날짜
rolled = c.clock_rolled_back(hdr, datetime.date(2026, 10, 20))
check("시계 되돌림 탐지", rolled)

print("\n" + ("ALL PASS" if ok else "SOME FAILED"))
sys.exit(0 if ok else 1)
