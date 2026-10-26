# -*- coding: utf-8 -*-
"""CI 하드 게이트 2: 제작기 exe(내장 스텁)로 실제 봉인 -> 생성된 exe 실행/복호화까지
전체 파이프라인을 윈도우에서 end-to-end 검증."""
import os, sys, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
packager = os.path.join(HERE, "dist", "igSeal-Packager.exe")
assert os.path.isfile(packager), "제작기 exe 없음: " + packager

d = tempfile.mkdtemp()
src = os.path.join(d, "납품소스.txt")
open(src, "w", encoding="utf-8").write("실제 납품물 end-to-end 검증\nline2")
out_exe = os.path.join(HERE, "dist", "_pipeline_sealed.exe")

# 제작기 CLI 봉인 (내장 스텁 사용)
p1 = subprocess.run([packager, "--seal", src, out_exe, "pipepw456", "2099-12-31"],
                    capture_output=True, text=True, timeout=180)
print("packager out:", (p1.stdout or "").strip(), (p1.stderr or "").strip(), "exit", p1.returncode)
if p1.returncode != 0 or not os.path.isfile(out_exe):
    print("::error::제작기 봉인 실패"); sys.exit(1)

# 생성된 봉인 exe 실행 검증
res = os.path.join(HERE, "dist", "pipeline_result.txt")
env = dict(os.environ)
env.update({"IGSEAL_SELFTEST": "1", "IGSEAL_SELFTEST_FILE": out_exe,
            "IGSEAL_SELFTEST_PW": "pipepw456", "IGSEAL_SELFTEST_OUT": res})
p2 = subprocess.run([out_exe], env=env, timeout=120)
out = open(res, encoding="utf-8").read().strip() if os.path.exists(res) else ""
print("sealed exit=%d result=%r" % (p2.returncode, out))
if p2.returncode != 0 or "SELFTEST PASS" not in out:
    print("::error::생성된 봉인 exe 실행/복호화 실패"); sys.exit(1)
print("전체 파이프라인 검증 통과: 제작기 -> 단일 봉인 exe -> 실행/복호화 OK")
