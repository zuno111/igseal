# -*- coding: utf-8 -*-
"""CI 하드 게이트: 제작기 exe 로 .igs 를 만들고, 뷰어 exe 가 그 .igs 를 읽어
복호화되는지 end-to-end 검증(append 없음). 윈도우에서 실제 실행."""
import os, sys, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
packager = os.path.join(DIST, "igSeal-Packager.exe")
viewer = os.path.join(DIST, "igSeal-Viewer.exe")
assert os.path.isfile(packager), "제작기 exe 없음: " + packager
assert os.path.isfile(viewer), "뷰어 exe 없음: " + viewer

d = tempfile.mkdtemp()
src = os.path.join(d, "납품소스.txt")
open(src, "w", encoding="utf-8").write("CI end-to-end .igs 검증\nline2")
out_igs = os.path.join(DIST, "_ci.igs")

# 1) 제작기 CLI 로 .igs 봉인 (머신바인딩 + 48h 타이머)
p1 = subprocess.run([packager, "--seal-igs", src, out_igs, "cipw1234", "2099-12-31"],
                    capture_output=True, text=True, timeout=180)
print("packager:", (p1.stdout or "").strip(), (p1.stderr or "").strip(), "exit", p1.returncode)
if p1.returncode != 0 or not os.path.isfile(out_igs):
    print("::error::제작기 .igs 봉인 실패"); sys.exit(1)

# 2) 뷰어 exe 가 .igs 를 열어 복호화 (헤드리스 selftest)
res = os.path.join(DIST, "igs_result.txt")
if os.path.exists(res):
    os.remove(res)
env = dict(os.environ)
env.update({"IGSEAL_SELFTEST": "1", "IGSEAL_SELFTEST_FILE": out_igs,
            "IGSEAL_SELFTEST_PW": "cipw1234", "IGSEAL_SELFTEST_OUT": res})
p2 = subprocess.run([viewer], env=env, timeout=120)
out = open(res, encoding="utf-8").read().strip() if os.path.exists(res) else ""
print("viewer selftest exit=%d result=%r" % (p2.returncode, out))
if p2.returncode != 0 or "SELFTEST PASS" not in out:
    print("::error::뷰어가 .igs 를 열지 못함"); sys.exit(1)

print("OK: 제작기 -> .igs -> 뷰어 복호화 end-to-end 통과")
