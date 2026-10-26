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
import os, sys, json, base64, struct, hmac, hashlib, datetime, subprocess

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"IGSEAL\x00\x00PKGv1\x00\x00\x00"   # 정확히 16바이트
assert len(MAGIC) == 16, len(MAGIC)
FOOTER_LEN = 16 + 8

# 평문 헤더 변조 탐지용 공유 비밀(스텁에 내장). 암호학적 보호의 핵심은 아니고
# hex 에디터로 만료일만 슬쩍 바꾸는 수준을 막는 용도.
STUB_SECRET = b"igSeal/STUDIO-ig/stub-hmac-secret/2026"

SCRYPT_N = 2 ** 15   # 32768
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


def build_payload(files, password, expiry=None, title="봉인 패키지"):
    """files: [(name, bytes)]. expiry: 'YYYY-MM-DD' 또는 None. -> payload bytes"""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)

    total = sum(len(b) for _, b in files)
    plain = {
        "title": title,
        "expiry": expiry,
        "files": [
            {"name": n, "size": len(b), "data": base64.b64encode(b).decode("ascii")}
            for n, b in files
        ],
    }
    plaintext = json.dumps(plain, ensure_ascii=False).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plaintext, None)

    hdr = {
        "v": 1,
        "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "expiry": expiry,
        "title": title,
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
    """성공 시 (title, expiry, [(name, bytes)]). 비번 오류/손상 시 ValueError."""
    hdr, ct = parse_header(payload)
    salt = bytes.fromhex(hdr["salt"])
    nonce = bytes.fromhex(hdr["nonce"])
    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("비밀번호가 올바르지 않거나 파일이 손상되었습니다.")
    plain = json.loads(plaintext.decode("utf-8"))
    files = [(f["name"], base64.b64decode(f["data"])) for f in plain["files"]]
    return plain.get("title", ""), plain.get("expiry"), files


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
    return hashlib.sha256((hdr.get("salt", "") + hdr.get("nonce", "")).encode()).hexdigest()[:16]


def clock_rolled_back(hdr: dict, today=None) -> bool:
    if today is None:
        today = datetime.date.today()
    p = _state_path(pkg_id_of(hdr))
    seen = None
    try:
        with open(p, "r") as f:
            seen = datetime.datetime.strptime(f.read().strip(), "%Y-%m-%d").date()
    except Exception:
        seen = None
    rolled = seen is not None and today < seen
    newest = today if seen is None or today > seen else seen
    try:
        with open(p, "w") as f:
            f.write(newest.strftime("%Y-%m-%d"))
    except Exception:
        pass
    return rolled


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
