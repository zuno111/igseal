# -*- coding: utf-8 -*-
"""CI 하드 게이트: 제작기 exe 로 .igs 를 만들고, 뷰어 exe 가 그 .igs 를 읽어
복호화되는지 end-to-end 검증(append 없음). 실패 원인은 ::error:: 로 전부 노출."""
import os, sys, subprocess, tempfile, traceback

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


_DIAG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "diag.txt")


def diag(msg):
    try:
        with open(_DIAG, "a", encoding="utf-8") as f:
            f.write(str(msg) + "\n")
    except Exception:
        pass


def err(msg):
    print("::error::" + str(msg).replace("\n", " ")[:400])
    diag("ERROR: " + str(msg))


def main():
    HERE = os.path.dirname(os.path.abspath(__file__))
    DIST = os.path.join(HERE, "dist")
    try:
        open(_DIAG, "w").close()
    except Exception:
        pass
    diag("dist 목록: " + ", ".join(sorted(os.listdir(DIST))))
    packager = os.path.join(DIST, "igSeal-Packager.exe")
    viewer = os.path.join(DIST, "igSeal-Viewer.exe")
    if not os.path.isfile(packager):
        err("제작기 exe 없음: " + packager); return 1
    if not os.path.isfile(viewer):
        err("뷰어 exe 없음: " + viewer); return 1

    d = tempfile.mkdtemp()
    src = os.path.join(d, "src.txt")
    open(src, "w", encoding="utf-8").write("CI end-to-end .igs")
    out_igs = os.path.join(DIST, "_ci.igs")

    # 1) 제작기 .igs 봉인
    try:
        p1 = subprocess.run([packager, "--seal-igs", src, out_igs, "cipw1234", "2099-12-31"],
                            capture_output=True, text=True, timeout=180)
    except Exception as e:
        err("제작기 실행 예외: " + repr(e)); return 1
    if p1.returncode != 0:
        err("제작기 exit=%d stdout=%r stderr=%r" % (p1.returncode, p1.stdout, p1.stderr)); return 1
    if not os.path.isfile(out_igs):
        err("제작기가 .igs 를 만들지 못함. stdout=%r stderr=%r" % (p1.stdout, p1.stderr)); return 1

    # 2) 뷰어 exe 가 .igs 열기 (selftest, 결과는 파일로)
    res = os.path.join(DIST, "igs_result.txt")
    if os.path.exists(res):
        os.remove(res)
    env = dict(os.environ)
    env.update({"IGSEAL_SELFTEST": "1", "IGSEAL_SELFTEST_FILE": out_igs,
                "IGSEAL_SELFTEST_PW": "cipw1234", "IGSEAL_SELFTEST_OUT": res})
    try:
        p2 = subprocess.run([viewer], env=env, capture_output=True, text=True, timeout=120)
    except Exception as e:
        err("뷰어 실행 예외: " + repr(e)); return 1
    out = open(res, encoding="utf-8").read().strip() if os.path.exists(res) else ""
    diag("뷰어 exit=%d result=%r stdout=%r stderr=%r" % (p2.returncode, out, (p2.stdout or ""), (p2.stderr or "")))
    if p2.returncode != 0 or "SELFTEST PASS" not in out:
        err("뷰어 selftest 실패 exit=%d result=%r stdout=%r stderr=%r"
            % (p2.returncode, out, (p2.stdout or "")[:200], (p2.stderr or "")[:200])); return 1

    diag("OK PASS")
    print("OK: 제작기 -> .igs -> 뷰어 복호화 통과:", out)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        err("예외: " + traceback.format_exc().replace("\n", " ")[:400])
        sys.exit(1)
