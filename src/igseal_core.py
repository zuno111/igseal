# -*- coding: utf-8 -*-
"""
igSeal 봉인 코어 — 암호화 패키지 생성/해제, 만료 자동삭제 로직.
OS 무관(순수 파이썬 + cryptography). 윈도우 전용 동작(자기삭제)만 분기.

패키지 레이아웃 (뷰어 스텁 exe 끝에 append):
  [ ...스텁 exe... ][ payload(N) ][ MAGIC(16) ][ N:uint64 LE(8) ]
payload 구조:
  [ header_json_len:uint32 LE(4) ][ header_json(utf-8) ][ ciphertext ]
header_json:
  { v, created, expiry(null 또는 YYYY-MM-DD), title, file_count, total_size,
    kdf, salt(hex), n, r, p, nonce(hex), hmac(hex) }
  - ciphertext = AES-256-GCM( key, nonce, plaintext_json )
  - key = scrypt(password, salt, n, r, p, 32)
  - plaintext_json = { files: [ {name, size, data(b64)} ], expiry, title }
  - hmac = HMAC-SHA256(stub_secret, header의 hmac 제외 필드 canonical) — 평문 헤더 casual 변조 탐지용
"""
import os, sys, json, base64, struct, hmac, hashlib, datetime, subprocess, uuid
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"IGSEAL\x00\x00PKGv1\x00\x00\x00"   # 정확히 16바이트
assert len(MAGIC) == 16, len(MAGIC)
FOOTER_LEN = 16 + 8

# 평문 헤더 변조 탐지용 공유 비밀(스텁에 내장). 암호학적 보호의 핵심은 아니고
# hex 에디터로 만료일만 슬쩍 바꾸는 수준을 막는 용도.
STUB_SECRET = b"igSeal/STUDIO-ig/stub-hmac-secret/2026"

SCRYPT_N = 2 ** 16   # 65536 — 상향(무차별 대입 비용 증가)
SCRYPT_R = 8
SCRYPT_P = 1


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def _canon_for_hmac(hdr: dict) -> bytes:
    h = {k: v for k, v in hdr.items() if k != "hmac"}
    return json.dumps(h, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _sign_header(hdr: dict) -> str:
    return hmac.new(STUB_SECRET, _canon_for_hmac(hdr), hashlib.sha256).hexdigest()


def build_payload(files, password, expiry=None, title="봉인 패키지",
                  watermark="", max_opens=None, revoke_url="", pkg_id=None):
    """files: [(name, bytes)]. expiry: 'YYYY-MM-DD' 또는 None. -> payload bytes
    watermark: 열람/임시파일에 찍을 문구. max_opens: 최대 열람 횟수(None=무제한).
    revoke_url: 원격 폐기 목록 JSON URL(평문 헤더, HMAC 보호). pkg_id: 패키지 식별자."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    if not pkg_id:
        pkg_id = uuid.uuid4().hex[:12]

    total = sum(len(b) for _, b in files)
    plain = {
        "title": title,
        "expiry": expiry,
        "watermark": watermark or "",
        "max_opens": max_opens,
        "pkg_id": pkg_id,
        "files": [
            {"name": n, "size": len(b), "data": base64.b64encode(b).decode("ascii")}
            for n, b in files
        ],
    }
    plaintext = json.dumps(plain, ensure_ascii=False).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plaintext, None)

    hdr = {
        "v": 2,
        "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "expiry": expiry,
        "title": title,
        "pkg_id": pkg_id,
        "revoke_url": revoke_url or "",
        "max_opens": max_opens,
        "file_count": len(files),
        "total_size": total,
        "kdf": "scrypt",
        "salt": salt.hex(),
        "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "nonce": nonce.hex(),
    }
    hdr["hmac"] = _sign_header(hdr)
    hjson = json.dumps(hdr, ensure_ascii=False).encode("utf-8")
    return struct.pack("<I", len(hjson)) + hjson + ct


def append_to_stub(stub_bytes: bytes, payload: bytes) -> bytes:
    """스텁 exe 뒤에 payload + footer 를 붙여 단일 뷰어 exe 생성."""
    return stub_bytes + payload + MAGIC + struct.pack("<Q", len(payload))


def read_payload_from_file(path: str):
    """exe 자기 자신에서 payload 추출. 없으면 None."""
    size = os.path.getsize(path)
    if size < FOOTER_LEN:
        return None
    with open(path, "rb") as f:
        f.seek(size - FOOTER_LEN)
        footer = f.read(FOOTER_LEN)
        magic, n = footer[:16], struct.unpack("<Q", footer[16:24])[0]
        if magic != MAGIC:
            return None
        if n <= 0 or n > size - FOOTER_LEN:
            return None
        f.seek(size - FOOTER_LEN - n)
        return f.read(n)


def parse_header(payload: bytes):
    hlen = struct.unpack("<I", payload[:4])[0]
    hdr = json.loads(payload[4:4 + hlen].decode("utf-8"))
    ct = payload[4 + hlen:]
    return hdr, ct


def header_tampered(hdr: dict) -> bool:
    try:
        return _sign_header(hdr) != hdr.get("hmac")
    except Exception:
        return True


def is_expired(hdr: dict, today=None) -> bool:
    exp = hdr.get("expiry")
    if not exp:
        return False
    if today is None:
        today = datetime.date.today()
    try:
        d = datetime.datetime.strptime(exp, "%Y-%m-%d").date()
    except Exception:
        return False
    return today > d


def unlock(payload: bytes, password: str):
    """성공 시 dict(title, expiry, watermark, max_opens, pkg_id, files=[(name,bytes)]).
    비번 오류/손상 시 ValueError."""
    hdr, ct = parse_header(payload)
    salt = bytes.fromhex(hdr["salt"])
    nonce = bytes.fromhex(hdr["nonce"])
    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("비밀번호가 올바르지 않거나 파일이 손상되었습니다.")
    plain = json.loads(plaintext.decode("utf-8"))
    return {
        "title": plain.get("title", ""),
        "expiry": plain.get("expiry"),
        "watermark": plain.get("watermark", ""),
        "max_opens": plain.get("max_opens"),
        "pkg_id": plain.get("pkg_id", ""),
        "files": [(f["name"], base64.b64decode(f["data"])) for f in plain["files"]],
    }


# ----- 시계 되돌림 탐지 (best-effort) -----
def _state_path(pkg_id: str) -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~/.config")
    d = os.path.join(base, "igSeal")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return os.path.join(d, pkg_id + ".dat")


def pkg_id_of(hdr: dict) -> str:
    if hdr.get("pkg_id"):
        return hdr["pkg_id"]
    return hashlib.sha256((hdr.get("salt", "") + hdr.get("nonce", "")).encode()).hexdigest()[:16]


def _load_state(hdr):
    p = _state_path(pkg_id_of(hdr))
    try:
        with open(p, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(hdr, st):
    try:
        with open(_state_path(pkg_id_of(hdr)), "w") as f:
            json.dump(st, f)
    except Exception:
        pass


def clock_rolled_back(hdr: dict, today=None) -> bool:
    if today is None:
        today = datetime.date.today()
    st = _load_state(hdr)
    seen = None
    try:
        seen = datetime.datetime.strptime(st.get("seen", ""), "%Y-%m-%d").date()
    except Exception:
        seen = None
    rolled = seen is not None and today < seen
    newest = today if seen is None or today > seen else seen
    st["seen"] = newest.strftime("%Y-%m-%d")
    _save_state(hdr, st)
    return rolled


def open_count(hdr) -> int:
    return int(_load_state(hdr).get("opens", 0))


def record_open(hdr) -> int:
    st = _load_state(hdr)
    st["opens"] = int(st.get("opens", 0)) + 1
    _save_state(hdr, st)
    return st["opens"]


def opens_exceeded(hdr) -> bool:
    mx = hdr.get("max_opens")
    if not mx:
        return False
    try:
        return open_count(hdr) >= int(mx)
    except Exception:
        return False


# ----- 원격 폐기(킬스위치) -----
def remote_status(hdr, timeout=3):
    """revoke_url(JSON)을 조회. 반환:
       ('revoke', None)  -> 폐기됨(자동삭제)
       ('extend', 'YYYY-MM-DD') -> 만료일 연장
       (None, None) -> 조회 실패/해당 없음(오프라인 fallback)
    JSON 형식: {"revoked":["pkgid",...], "extend":{"pkgid":"YYYY-MM-DD"}}"""
    url = hdr.get("revoke_url") or ""
    if not url:
        return (None, None)
    pid = pkg_id_of(hdr)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "igSeal"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception:
        return (None, None)
    try:
        if pid in (data.get("revoked") or []):
            return ("revoke", None)
        ext = (data.get("extend") or {}).get(pid)
        if ext:
            datetime.datetime.strptime(ext, "%Y-%m-%d")
            return ("extend", ext)
    except Exception:
        pass
    return (None, None)


# ----- 자기삭제 -----
def self_destruct(path: str):
    """만료 시 뷰어 exe 자신을 삭제. 윈도우는 분리된 cmd로 지연삭제."""
    try:
        if sys.platform.startswith("win"):
            flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            subprocess.Popen(
                'cmd /c ping 127.0.0.1 -n 2 >nul & del /f /q "%s"' % path,
                shell=True, creationflags=flags,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            try:
                os.remove(path)
            except Exception:
                pass
    except Exception:
        pass
