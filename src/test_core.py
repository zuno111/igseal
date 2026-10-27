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
payload = c.build_payload(files, "pass1234", expiry="2026-12-31", title="테스트납품",
                          watermark="거래처A 2026-10-26", max_opens=5,
                          revoke_url="file:///tmp/igseal_test/revoke.json", pkg_id="PKGTEST01")
r = c.unlock(payload, "pass1234")
got = r["files"]
check("봉인/해제 라운드트립 파일수", len(got) == 3)
check("원본 일치 txt", got[0][1] == files[0][1])
check("원본 일치 bin", dict(got)["logo.bin"] == dict(files)["logo.bin"])
check("제목/만료 보존", r["title"] == "테스트납품" and r["expiry"] == "2026-12-31")
check("워터마크/열람제한 보존", r["watermark"] == "거래처A 2026-10-26" and r["max_opens"] == 5)

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
r2 = c.unlock(read, "pass1234")
check("추출 payload 해제", len(r2["files"]) == 3)

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

# 10. 열람 횟수 제한
hdr10, _ = c.parse_header(payload)   # max_opens=5, pkg_id=PKGTEST01
# state 초기화
import glob
for f in glob.glob(os.path.join(cfgbak, "igSeal", "*.dat")):
    os.remove(f)
check("초기 열람수 0", c.open_count(hdr10) == 0)
for i in range(5):
    c.record_open(hdr10)
check("5회 열람 후 exceeded", c.opens_exceeded(hdr10))
check("열람수 5 기록", c.open_count(hdr10) == 5)
# max_opens 없으면 무제한
hdr_no = dict(hdr10); hdr_no["max_opens"] = None
check("무제한이면 not exceeded", not c.opens_exceeded(hdr_no))

# 11. 원격 폐기(킬스위치) — 로컬 file:// JSON
rj = os.path.join(TMP, "revoke.json")
open(rj, "w").write('{"revoked":["PKGTEST01"],"extend":{}}')
st, val, on = c.remote_status(hdr10)
check("원격 폐기 감지", st == "revoke" and on is True)
# 연장
open(rj, "w").write('{"revoked":[],"extend":{"PKGTEST01":"2027-06-30"}}')
st2, val2, on2 = c.remote_status(hdr10)
check("원격 만료연장 감지", st2 == "extend" and val2 == "2027-06-30" and on2 is True)
# 정상(조회 성공, 폐기 아님) -> online True
open(rj, "w").write('{"revoked":[],"extend":{}}')
st3, val3, on3 = c.remote_status(hdr10)
check("정상이면 online True", st3 is None and on3 is True)
# URL 없으면 조회 안함, online False
hdr_nourl = dict(hdr10); hdr_nourl["revoke_url"] = ""
check("revoke_url 없으면 offline", c.remote_status(hdr_nourl) == (None, None, False))
# 조회 실패시 fallback, online False
hdr_bad = dict(hdr10); hdr_bad["revoke_url"] = "file:///tmp/igseal_test/nonexist.json"
check("조회 실패시 offline", c.remote_status(hdr_bad) == (None, None, False))

# 11b. 최초 활성화 + 오프라인 리스
hdr_a = c.build_payload([("x", b"y")], "pw", pkg_id="ACTTEST01",
                        require_activation=True, lease_days=2,
                        revoke_url="file:///tmp/igseal_test/revoke.json")
ha, _ = c.parse_header(hdr_a)
for f in glob.glob(os.path.join(cfgbak, "igSeal", "ACTTEST01.dat")):
    os.remove(f)
check("활성화 필요 플래그", c.needs_activation(ha))
check("초기 미활성", not c.is_activated(ha))
check("리스 일수 2", c.lease_days_of(ha) == 2)
check("미갱신시 lease_ok False", not c.lease_ok(ha))
# 온라인 활성화 가정: mark + renew
c.mark_activated(ha); c.renew_lease(ha, datetime.date(2026, 10, 26))
check("활성화 기록됨", c.is_activated(ha))
check("리스 갱신 후 당일 ok", c.lease_ok(ha, datetime.date(2026, 10, 27)))
check("리스 2일 경계 ok", c.lease_ok(ha, datetime.date(2026, 10, 28)))
check("리스 만료 후 거부", not c.lease_ok(ha, datetime.date(2026, 10, 29)))
# 리스 미사용이면 항상 ok
hdr_nl = dict(ha); hdr_nl["lease_days"] = None
check("리스 미사용 항상 ok", c.lease_ok(hdr_nl, datetime.date(2099, 1, 1)))

# 12. 제작자 대장 + revoke.json 생성
import json as _json
lf = os.path.join(cfgbak, "igSeal", "ledger.json")
if os.path.exists(lf):
    os.remove(lf)
c.ledger_add({"pkg_id": "A1", "title": "A납품", "client": "갑", "expiry": "2026-12-31", "status": "active", "extend": ""})
c.ledger_add({"pkg_id": "B2", "title": "B납품", "client": "을", "expiry": "2026-11-30", "status": "active", "extend": ""})
check("대장 2건 기록", len(c.ledger_all()) == 2)
c.ledger_update("A1", status="revoked")
c.ledger_update("B2", extend="2027-06-30")
rj2 = os.path.join(TMP, "revoke_export.json")
nrev, next_ = c.ledger_export_revoke(rj2)
check("폐기 1건 연장 1건 집계", nrev == 1 and next_ == 1)
exp = _json.load(open(rj2, encoding="utf-8"))
check("revoke.json 내용", exp["revoked"] == ["A1"] and exp["extend"] == {"B2": "2027-06-30"})
# 같은 pkg_id 재봉인시 중복 방지
c.ledger_add({"pkg_id": "A1", "title": "A재봉인", "client": "갑", "expiry": "2027-01-01", "status": "active", "extend": ""})
check("중복 pkg_id 갱신", len(c.ledger_all()) == 2)

# 13. 오디오 워터마크 (WAV)
import wave as _wave, array as _arr, math as _m, io as _io
fr = 44100
sm = _arr.array("h")
for i in range(fr * 12):
    v = int(8000 * _m.sin(2 * _m.pi * 440 * i / fr))
    sm.append(v); sm.append(v)
b = _io.BytesIO(); w = _wave.open(b, "wb"); w.setnchannels(2); w.setsampwidth(2); w.setframerate(fr)
w.writeframes(sm.tobytes()); w.close()
orig_wav = b.getvalue()
wmd = c.audio_watermark_wav(orig_wav, "TAG12345", every_sec=8.0)
check("오디오 워터마크 길이 보존", len(wmd) == len(orig_wav))
check("오디오 워터마크 변경됨", wmd != orig_wav)

def _goertzel(sig, f, fr):
    w0 = 2 * _m.pi * f / fr; coeff = 2 * _m.cos(w0); p1 = p2 = 0.0
    for x in sig:
        s = x + coeff * p1 - p2; p2 = p1; p1 = s
    return p2 * p2 + p1 * p1 - coeff * p1 * p2
w2 = _wave.open(_io.BytesIO(wmd), "rb"); raw = w2.readframes(w2.getnframes()); w2.close()
s2 = _arr.array("h"); s2.frombytes(raw)
mono = [s2[i * 2] for i in range(len(s2) // 2)]
# 원본에도 1500Hz 에너지가 있으므로, 워터마크 삽입 전/후 같은 구간을 비교
o2 = _arr.array("h"); o2.frombytes(orig_wav[44:])
omono = [o2[i * 2] for i in range(len(o2) // 2)]
seg_before = omono[fr:fr + 1764]
seg_after = mono[fr:fr + 1764]
e_before = _goertzel(seg_before, 1500, fr) + _goertzel(seg_before, 2200, fr)
e_after = _goertzel(seg_after, 1500, fr) + _goertzel(seg_after, 2200, fr)
check("워터마크 삽입으로 신호 에너지 증가", e_after > e_before * 5)
# 비WAV/손상은 원본 반환
check("비WAV는 원본 반환", c.audio_watermark_wav(b"not a wav", "T") == b"not a wav")

print("\n" + ("ALL PASS" if ok else "SOME FAILED"))
sys.exit(0 if ok else 1)
