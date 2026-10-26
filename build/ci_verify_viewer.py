# -*- coding: utf-8 -*-
"""CI 하드 게이트 1: 빌드된 뷰어 onefile exe 뒤에 payload 를 붙여도
실제로 실행되고 복호화되는지(= PyInstaller 단일exe append 가능 여부)를 윈도우에서 검증."""
import os, sys, subprocess, tempfile, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")
sys.path.insert(0, SRC)
import igseal_core as core

viewer = os.path.join(HERE, "dist", "igSeal-Viewer.exe")
assert os.path.isfile(viewer), "뷰어 exe 없음: " + viewer

stub = open(viewer, "rb").read()
files = [("probe.txt", "APPEND-PROBE-CONTENT-납품물".encode("utf-8")),
         ("d.json", b'{"probe":true}')]
payload = core.build_payload(files, "probepw123", expiry="2099-12-31", title="CI probe")
probe = os.path.join(HERE, "dist", "_probe_sealed.exe")
open(probe, "wb").write(core.append_to_stub(stub, payload))
print("probe exe 생성:", probe, os.path.getsize(probe), "bytes")

res = os.path.join(HERE, "dist", "probe_result.txt")
if os.path.exists(res):
    os.remove(res)
env = dict(os.environ)
env.update({
    "IGSEAL_SELFTEST": "1",
    "IGSEAL_SELFTEST_FILE": probe,
    "IGSEAL_SELFTEST_PW": "probepw123",
    "IGSEAL_SELFTEST_OUT": res,
})
p = subprocess.run([probe], env=env, timeout=120)
out = ""
if os.path.exists(res):
    out = open(res, encoding="utf-8").read().strip()
print("exit=%d result=%r" % (p.returncode, out))
if p.returncode != 0 or "SELFTEST PASS" not in out:
    print("::error::APPEND 검증 실패 — PyInstaller 단일exe 뒤 append 가 이 버전에서 동작하지 않음")
    sys.exit(1)
print("APPEND 검증 통과: PyInstaller onefile + 붙인 payload 정상 실행/복호화")
