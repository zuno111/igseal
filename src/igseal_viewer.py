# -*- coding: utf-8 -*-
"""
igSeal 뷰어 스텁 — 봉인된 단일 exe. 거래처가 받는 파일.
- 실행 시 자기 exe 뒤에 붙은 암호화 payload 를 읽음
- 만료일 지나면 자기삭제 / 시계되돌림·변조 탐지
- 비밀번호로 복호화, 내부에서만 미리보기. 저장/복사/이동/편집 불가
고딕(산세리프) 폰트, 다크 테마. console=False (GUI).
"""
import os, sys, io, datetime, traceback

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import igseal_core as core

APP_NAME = "igSeal 봉인 뷰어"
# 고딕 계열만. 윈도우에 기본 탑재된 산세리프.
FONT = "Malgun Gothic"
BG = "#14161c"; FG = "#e8eaf0"; SUB = "#9aa3b2"
ACCENT = "#4a8cff"; CARD = "#1d212b"; LINE = "#2a2f3a"; DANGER = "#ff5d5d"

TEXT_EXT = {".txt", ".md", ".csv", ".json", ".log", ".ini", ".cfg", ".xml",
            ".html", ".htm", ".css", ".js", ".py", ".java", ".c", ".cpp",
            ".cs", ".go", ".rs", ".ts", ".sql", ".yml", ".yaml", ".bat", ".sh", ".srt", ".smi"}
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tiff"}


def _self_path():
    return sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)


# ---------------- selftest (헤드리스, GUI 없이 CI 검증용) ----------------
def _report(msg, code):
    print(msg)
    out = os.environ.get("IGSEAL_SELFTEST_OUT")
    if out:
        try:
            open(out, "w", encoding="utf-8").write(msg + "\n")
        except Exception:
            pass
    return code


def selftest():
    path = os.environ.get("IGSEAL_SELFTEST_FILE") or _self_path()
    pw = os.environ.get("IGSEAL_SELFTEST_PW", "")
    if path.lower().endswith(core.IGS_EXT) or core.is_igs_file(path):
        payload = core.read_igs(path)
    else:
        payload = core.read_payload_from_file(path)
    if payload is None:
        return _report("SELFTEST FAIL: payload 없음 (file=%s)" % path, 1)
    hdr, _ = core.parse_header(payload)
    if core.header_tampered(hdr):
        return _report("SELFTEST FAIL: 헤더 변조 탐지됨", 1)
    try:
        r = core.unlock(payload, pw)
    except Exception as e:
        return _report("SELFTEST FAIL: unlock 실패: %s" % e, 1)
    return _report("SELFTEST PASS title=%r expiry=%r files=%d wm=%r" % (
        r["title"], r["expiry"], len(r["files"]), r["watermark"]), 0)


# ---------------- GUI ----------------
def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox
    try:
        from PIL import Image, ImageTk
        HAVE_PIL = True
    except Exception:
        HAVE_PIL = False
    try:
        import fitz  # PyMuPDF (PDF 렌더)
        HAVE_PDF = True
    except Exception:
        HAVE_PDF = False
    try:
        import imageio.v3 as iio3
        import imageio_ffmpeg  # 정적 ffmpeg 내장
        HAVE_VIDEO = True
    except Exception:
        HAVE_VIDEO = False
    try:
        import trimesh  # noqa
        import numpy as _np  # noqa
        HAVE_MESH = True
    except Exception:
        HAVE_MESH = False

    # 소스 결정: 인자로 .igs 가 오면(확장자 연결) 그 파일을, 아니면 자기 exe 꼬리 payload.
    igs_arg = None
    for a in sys.argv[1:]:
        if a and not a.startswith("-") and a.lower().endswith(core.IGS_EXT) and os.path.isfile(a):
            igs_arg = os.path.abspath(a); break
    if igs_arg is None:
        for a in sys.argv[1:]:
            if a and os.path.isfile(a) and core.is_igs_file(a):
                igs_arg = os.path.abspath(a); break

    if igs_arg:
        target_path = igs_arg           # 만료 시 삭제 대상 = .igs 파일
        payload = core.read_igs(igs_arg)
        is_igs = True
    else:
        target_path = _self_path()
        payload = core.read_payload_from_file(target_path)
        is_igs = False
    self_path = target_path

    # 전문 포맷을 외부 프로그램으로 열 때 쓰는 임시 작업폴더. 닫을 때 전량 삭제.
    import tempfile, shutil, atexit, subprocess as _sp, stat as _stat
    ws = {"dir": None, "opened": []}

    def workspace():
        if ws["dir"] is None:
            ws["dir"] = tempfile.mkdtemp(prefix=".igseal_")
            try:
                if sys.platform.startswith("win"):
                    _sp.call('attrib +h "%s"' % ws["dir"], shell=True)
            except Exception:
                pass
        return ws["dir"]

    def wipe_workspace():
        d = ws["dir"]
        if not d:
            return
        try:
            for p in ws["opened"]:
                try:
                    os.chmod(p, _stat.S_IWRITE)
                except Exception:
                    pass
            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass
        if os.path.isdir(d) and sys.platform.startswith("win"):
            # 외부 앱이 파일을 잡고 있으면 지연 삭제
            try:
                _sp.Popen('cmd /c ping 127.0.0.1 -n 3 >nul & rmdir /s /q "%s"' % d,
                          shell=True, creationflags=0x00000008)
            except Exception:
                pass

    atexit.register(wipe_workspace)

    root = tk.Tk()
    root.withdraw()
    root.title(APP_NAME)
    try:
        root.configure(bg=BG)
    except Exception:
        pass

    def die(msg, destruct=False):
        messagebox.showinfo(APP_NAME, msg)
        if destruct:
            core.self_destruct(self_path)
        try:
            root.destroy()
        except Exception:
            pass
        os._exit(0)

    if payload is None:
        die("봉인 데이터가 없는 파일입니다.\n제작기(igSeal 제작기)에서 봉인한 파일을 실행하세요.")
        return

    hdr, _ct = core.parse_header(payload)

    if core.header_tampered(hdr):
        die("파일이 변조되었습니다. 열 수 없습니다.\n제작자에게 다시 받아주세요.")
        return

    # 원격 폐기(킬스위치) / 만료 연장 조회 — 인터넷 연결 시에만, 실패하면 무시
    eff_expiry = hdr.get("expiry")
    rstat, rval, online = core.remote_status(hdr)
    if rstat == "revoke":
        die("제작자에 의해 사용이 중지되어 파일이 삭제되었습니다.", destruct=True)
        return
    if rstat == "extend" and rval:
        try:
            a = datetime.datetime.strptime(rval, "%Y-%m-%d").date()
            b = datetime.datetime.strptime(eff_expiry, "%Y-%m-%d").date() if eff_expiry else None
            if b is None or a > b:
                eff_expiry = rval
        except Exception:
            pass

    # 최초 온라인 활성화 필수
    if core.needs_activation(hdr) and not core.is_activated(hdr):
        if online:
            core.mark_activated(hdr)
            core.renew_lease(hdr)
        else:
            die("최초 1회 인터넷 연결이 필요합니다.\n인터넷에 연결한 뒤 다시 실행하세요.")
            return

    # ---- 키-분리 바인딩: pkg_secret 획득(캐시 → 서버). 없으면 못 엶 ----
    bound_secret = None
    if hdr.get("bound_key"):
        bound_secret = core.load_cached_pkg_secret(hdr)
        if bound_secret is None:
            sec, st = core.request_pkg_secret(hdr)
            if st == "ok":
                bound_secret = sec
                core.cache_pkg_secret(hdr, sec)   # 이 PC에만 DPAPI 로 묶어 저장
            elif st == "bound_other":
                die("이 파일은 다른 PC에서 이미 활성화되어,\n이 컴퓨터에서는 열 수 없습니다.")
                return
            elif st == "revoked":
                die("제작자에 의해 사용이 중지되어 파일이 삭제되었습니다.", destruct=True)
                return
            else:  # offline / error
                die("최초 1회 인터넷 연결이 필요합니다(키 활성화).\n"
                    "인터넷에 연결한 뒤 다시 실행하세요.")
                return

    # 오프라인 리스(임대) — 온라인이면 기한 갱신, 기한 지나면 재연결 요구
    if core.lease_days_of(hdr):
        if online:
            core.renew_lease(hdr)
        if not core.lease_ok(hdr):
            die("오프라인 사용 기간이 지났습니다.\n인터넷에 연결한 뒤 다시 실행하면 갱신됩니다.")
            return

    if core.clock_rolled_back(hdr):
        die("시스템 시계가 과거로 변경된 것이 감지되었습니다.\n날짜를 올바르게 맞춘 뒤 다시 실행하세요.")
        return
    if core.is_expired({"expiry": eff_expiry}):
        die("사용 기간이 만료되어 파일이 삭제되었습니다.", destruct=True)
        return

    # ---- 위치/PC 바인딩 (다른 데로 옮기면 거부) — .igs 파일만 ----
    if is_igs:
        reason, newbind = core.binding_check(hdr, target_path)
        if reason == "machine":
            die("이 파일은 처음 연 PC에서만 열 수 있습니다.\n다른 컴퓨터로 복사된 파일은 열 수 없습니다.")
            return
        if reason == "path":
            die("이 파일은 처음 연 위치에서만 열 수 있습니다.\n다른 폴더·USB로 옮긴 파일은 열 수 없습니다.")
            return
        if reason == "tamper":
            die("파일 바인딩 정보가 손상되었습니다. 제작자에게 다시 받아주세요.")
            return
        if newbind:
            core.write_igs_bind(target_path, newbind)   # 최초 개봉 시 PC·위치 고정

    # ---- 오픈 타이머 (처음 연 뒤 N시간 후 자동 삭제) ----
    if core.open_timer_expired(hdr):
        die("개봉 후 허용 시간이 지나 파일이 삭제되었습니다.", destruct=True)
        return

    # ---- 열람 횟수 제한 ----
    if core.opens_exceeded(hdr):
        die("허용된 열람 횟수를 모두 사용했습니다.\n제작자에게 문의하세요.")
        return

    # ---- 비밀번호 입력 ----
    state = {"data": None}

    def ask_password():
        dlg = tk.Toplevel(root); dlg.title(APP_NAME); dlg.configure(bg=BG)
        dlg.resizable(False, False); dlg.grab_set()
        w, h = 380, 220
        x = (dlg.winfo_screenwidth() - w) // 2; y = (dlg.winfo_screenheight() - h) // 2
        dlg.geometry("%dx%d+%d+%d" % (w, h, x, y))
        tk.Label(dlg, text="🔒", font=(FONT, 28), bg=BG, fg=ACCENT).pack(pady=(22, 4))
        tk.Label(dlg, text=hdr.get("title", "봉인 패키지"), font=(FONT, 13, "bold"),
                 bg=BG, fg=FG).pack()
        exp = eff_expiry
        if exp:
            d = datetime.datetime.strptime(exp, "%Y-%m-%d").date()
            left = (d - datetime.date.today()).days
            tk.Label(dlg, text="사용기한 %s (%d일 남음)" % (exp, left),
                     font=(FONT, 9), bg=BG, fg=SUB).pack(pady=(2, 10))
        else:
            tk.Label(dlg, text="사용기한 없음", font=(FONT, 9), bg=BG, fg=SUB).pack(pady=(2, 10))
        ent = tk.Entry(dlg, show="●", font=(FONT, 12), width=24, justify="center",
                       bg=CARD, fg=FG, insertbackground=FG, relief="flat")
        ent.pack(ipady=6); ent.focus_set()
        tries = {"n": 0}

        def submit(*_):
            try:
                if hdr.get("bound_key"):
                    r = core.unlock_bound(payload, ent.get(), bound_secret)
                else:
                    r = core.unlock(payload, ent.get())
            except ValueError:
                tries["n"] += 1
                ent.delete(0, "end")
                if tries["n"] >= 10:
                    messagebox.showerror(APP_NAME, "비밀번호 시도 횟수를 초과했습니다.")
                    os._exit(0)
                messagebox.showwarning(APP_NAME, "비밀번호가 올바르지 않습니다. (%d/10회)" % tries["n"])
                return
            state["data"] = r
            dlg.destroy()

        tk.Button(dlg, text="열기", font=(FONT, 11, "bold"), bg=ACCENT, fg="white",
                  relief="flat", width=10, command=submit, cursor="hand2").pack(pady=10)
        ent.bind("<Return>", submit)
        dlg.protocol("WM_DELETE_WINDOW", lambda: (dlg.destroy(), os._exit(0)))
        dlg.wait_window()

    ask_password()
    if state["data"] is None:
        os._exit(0)

    # 열람 1회 기록 + 오픈 타이머 최초 개봉 시각 기록
    core.record_open(hdr)
    core.mark_first_open(hdr)

    # ---- 메인 뷰어 ----
    data = state["data"]
    data_pkg_id = data.get("pkg_id") or ""
    files = data["files"]
    watermark = data.get("watermark") or ""
    state["title"] = data["title"]
    state["expiry"] = eff_expiry
    root.deiconify()

    # 화면 캡처/녹화 차단 (윈도우). 스크린샷·화면녹화에 검게 나옴.
    def apply_capture_block():
        if not sys.platform.startswith("win"):
            return
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            if not hwnd:
                hwnd = root.winfo_id()
            # WDA_EXCLUDEFROMCAPTURE=0x11 (Win10 2004+), 실패시 WDA_MONITOR=0x01
            if not ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x11):
                ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x01)
        except Exception:
            pass
    root.after(300, apply_capture_block)
    W, H = 980, 640
    x = (root.winfo_screenwidth() - W) // 2; y = (root.winfo_screenheight() - H) // 2
    root.geometry("%dx%d+%d+%d" % (W, H, x, y))
    root.minsize(760, 480)

    # 상단 바
    top = tk.Frame(root, bg=CARD, height=52); top.pack(fill="x"); top.pack_propagate(False)
    tk.Label(top, text=state["title"] or "봉인 패키지", font=(FONT, 13, "bold"),
             bg=CARD, fg=FG).pack(side="left", padx=16)
    exp = state["expiry"]
    if exp:
        d = datetime.datetime.strptime(exp, "%Y-%m-%d").date()
        left = (d - datetime.date.today()).days
        txt = "사용기한 %s · %d일 남음" % (exp, left)
        col = DANGER if left <= 3 else SUB
    else:
        txt, col = "사용기한 없음", SUB
    tk.Label(top, text=txt, font=(FONT, 10), bg=CARD, fg=col).pack(side="right", padx=16)
    tk.Label(top, text="⚠ 보기 전용 · 저장/복사/이동/편집 불가", font=(FONT, 9),
             bg=CARD, fg=SUB).pack(side="right", padx=8)

    body = tk.Frame(root, bg=BG); body.pack(fill="both", expand=True)

    # 좌: 파일 목록
    left = tk.Frame(body, bg=BG, width=260); left.pack(side="left", fill="y"); left.pack_propagate(False)
    tk.Label(left, text="파일 %d개" % len(files), font=(FONT, 10, "bold"),
             bg=BG, fg=SUB, anchor="w").pack(fill="x", padx=14, pady=(12, 6))
    lb = tk.Listbox(left, font=(FONT, 10), bg=CARD, fg=FG, selectbackground=ACCENT,
                    selectforeground="white", relief="flat", highlightthickness=0,
                    activestyle="none", borderwidth=0)
    lb.pack(fill="both", expand=True, padx=10, pady=(0, 12))
    for n, _b in files:
        lb.insert("end", "  " + n)

    # 우: 미리보기
    right = tk.Frame(body, bg=BG); right.pack(side="left", fill="both", expand=True)
    head = tk.Frame(right, bg=BG); head.pack(fill="x", padx=16, pady=(12, 6))
    name_lbl = tk.Label(head, text="파일을 선택하세요", font=(FONT, 12, "bold"), bg=BG, fg=FG, anchor="w")
    name_lbl.pack(side="left")
    meta_lbl = tk.Label(head, text="", font=(FONT, 9), bg=BG, fg=SUB, anchor="e")
    meta_lbl.pack(side="right")
    prev = tk.Frame(right, bg=CARD); prev.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    img_ref = {"img": None}
    play = {"stop": False}   # 영상 재생 루프 중단 플래그

    def clear_prev():
        play["stop"] = True
        for w in prev.winfo_children():
            w.destroy()
        img_ref["img"] = None

    def block(*_):
        return "break"

    def _wm(im):
        """PIL 이미지에 반투명 대각선 반복 워터마크 합성."""
        if not watermark or not HAVE_PIL:
            return im
        try:
            from PIL import ImageDraw, ImageFont
            base = im.convert("RGBA")
            W_, H_ = base.size
            layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
            dr = ImageDraw.Draw(layer)
            fsize = max(16, W_ // 28)
            font = None
            for fp in ("malgun.ttf", "C:/Windows/Fonts/malgun.ttf", "arial.ttf",
                       "DejaVuSans.ttf"):
                try:
                    font = ImageFont.truetype(fp, fsize); break
                except Exception:
                    continue
            if font is None:
                font = ImageFont.load_default()
            step_x = max(220, W_ // 3)
            step_y = max(140, H_ // 4)
            for yy in range(0, H_ + step_y, step_y):
                for xx in range(-step_x, W_ + step_x, step_x):
                    dr.text((xx, yy), watermark, font=font, fill=(255, 255, 255, 60))
            layer = layer.rotate(30, expand=0)
            out = Image.alpha_composite(base, layer)
            return out.convert("RGB")
        except Exception:
            return im

    def show_text(data):
        clear_prev()
        try:
            txt = data.decode("utf-8")
        except Exception:
            try:
                txt = data.decode("cp949")
            except Exception:
                txt = data.decode("latin-1", "replace")
        t = tk.Text(prev, font=(FONT, 10), bg=CARD, fg=FG, relief="flat",
                    insertbackground=CARD, wrap="word", padx=14, pady=12,
                    highlightthickness=0, borderwidth=0)
        sb = tk.Scrollbar(prev, command=t.yview); t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); t.pack(side="left", fill="both", expand=True)
        t.insert("1.0", txt)
        t.configure(state="disabled")
        # 복사/저장/우클릭 차단
        for seq in ("<Control-c>", "<Control-C>", "<Control-s>", "<Control-S>",
                    "<Control-x>", "<Control-X>", "<Button-3>", "<<Copy>>", "<<Cut>>"):
            t.bind(seq, block)

    def show_image(data, name):
        clear_prev()
        if not HAVE_PIL:
            tk.Label(prev, text="이미지 미리보기 모듈 없음", font=(FONT, 11),
                     bg=CARD, fg=SUB).pack(expand=True)
            return
        try:
            im = Image.open(io.BytesIO(data)); im.load()
            im = _wm(im)
        except Exception:
            tk.Label(prev, text="이미지를 열 수 없습니다", font=(FONT, 11),
                     bg=CARD, fg=SUB).pack(expand=True)
            return
        cw = max(prev.winfo_width(), 400) - 24
        ch = max(prev.winfo_height(), 300) - 24
        im.thumbnail((cw, ch))
        ph = ImageTk.PhotoImage(im)
        img_ref["img"] = ph
        lbl = tk.Label(prev, image=ph, bg=CARD); lbl.pack(expand=True)
        lbl.bind("<Button-3>", block)

    def show_pdf(data):
        clear_prev()
        if not HAVE_PDF:
            tk.Label(prev, text="PDF 미리보기 모듈이 없습니다 (추출 차단)",
                     font=(FONT, 11), bg=CARD, fg=SUB).pack(expand=True)
            return
        cv = tk.Canvas(prev, bg=CARD, highlightthickness=0)
        sb = tk.Scrollbar(prev, command=cv.yview); cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); cv.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(cv, bg=CARD); cv.create_window((0, 0), window=inner, anchor="nw")
        try:
            doc = fitz.open(stream=data, filetype="pdf")
            keep = []
            for pg in doc:
                pix = pg.get_pixmap(dpi=110)
                from PIL import Image as _I
                im = _I.frombytes("RGB", [pix.width, pix.height], pix.samples)
                im = _wm(im)
                im.thumbnail((640, 2000))
                ph = ImageTk.PhotoImage(im); keep.append(ph)
                tk.Label(inner, image=ph, bg=CARD).pack(pady=6)
            img_ref["img"] = keep
            inner.update_idletasks()
            cv.configure(scrollregion=cv.bbox("all"))
        except Exception as e:
            tk.Label(prev, text="PDF 렌더 실패: %s" % e, font=(FONT, 10),
                     bg=CARD, fg=SUB).pack(expand=True)

    def show_video(data, name):
        clear_prev()
        play["stop"] = False
        if not (HAVE_VIDEO and HAVE_PIL):
            tk.Label(prev, text="영상 미리보기 모듈이 없습니다", font=(FONT, 11),
                     bg=CARD, fg=SUB).pack(expand=True)
            return
        # ffmpeg 가 파일 경로를 요구하므로 숨김 임시폴더에 잠깐 두고, 재생 후 삭제
        import tempfile
        d = workspace()
        vpath = os.path.join(d, "_v" + os.path.splitext(name)[1].lower())
        try:
            with open(vpath, "wb") as f:
                f.write(data)
            try:
                os.chmod(vpath, __import__("stat").S_IREAD)
            except Exception:
                pass
        except Exception as e:
            tk.Label(prev, text="영상 준비 실패: %s" % e, bg=CARD, fg=SUB,
                     font=(FONT, 10)).pack(expand=True); return

        wrap = tk.Frame(prev, bg=CARD); wrap.pack(fill="both", expand=True)
        canv = tk.Label(wrap, bg="#000"); canv.pack(fill="both", expand=True)
        bar = tk.Frame(wrap, bg=CARD); bar.pack(fill="x")
        st = {"playing": True, "meta": None, "reader": None}

        def toggle():
            st["playing"] = not st["playing"]
            pb.configure(text="❚❚ 일시정지" if st["playing"] else "▶ 재생")
            if st["playing"]:
                loop()
        pb = tk.Button(bar, text="❚❚ 일시정지", font=(FONT, 9), bg=LINE, fg=FG,
                       relief="flat", command=toggle, cursor="hand2", padx=10)
        pb.pack(side="left", padx=6, pady=6)
        info = tk.Label(bar, text="재생 중...", font=(FONT, 9), bg=CARD, fg=SUB)
        info.pack(side="left")

        try:
            meta = iio3.immeta(vpath, plugin="pyav")
            fps = float(meta.get("fps", 24)) or 24
        except Exception:
            fps = 24.0
        delay = max(15, int(1000 / fps))
        frames_iter = {"it": None}

        def _open_iter():
            frames_iter["it"] = iio3.imiter(vpath, plugin="pyav")

        try:
            _open_iter()
        except Exception as e:
            tk.Label(prev, text="영상 디코드 실패: %s" % e, bg=CARD, fg=SUB,
                     font=(FONT, 10)).pack(expand=True); return

        def loop():
            if play["stop"] or not st["playing"]:
                return
            try:
                frame = next(frames_iter["it"])
            except StopIteration:
                _open_iter()  # 반복 재생
                try:
                    frame = next(frames_iter["it"])
                except Exception:
                    return
            except Exception:
                return
            try:
                from PIL import Image as _I
                im = _I.fromarray(frame)
                cw = max(canv.winfo_width(), 320); ch = max(canv.winfo_height(), 240)
                im.thumbnail((cw, ch))
                im = _wm(im)
                ph = ImageTk.PhotoImage(im)
                img_ref["img"] = ph
                canv.configure(image=ph)
            except Exception:
                pass
            if not play["stop"] and st["playing"]:
                prev.after(delay, loop)
        prev.after(60, loop)

    def show_mesh(data, name):
        clear_prev()
        if not (HAVE_MESH and HAVE_PIL):
            tk.Label(prev, text="3D 미리보기 모듈이 없습니다", font=(FONT, 11),
                     bg=CARD, fg=SUB).pack(expand=True)
            return
        ext = os.path.splitext(name)[1].lower()
        mesh = core.load_mesh_from_bytes(data, ext)
        if mesh is None:
            tk.Label(prev, text="3D 파일을 열 수 없습니다 (%s)" % ext, font=(FONT, 11),
                     bg=CARD, fg=SUB).pack(expand=True)
            return
        lbl = tk.Label(prev, bg=CARD); lbl.pack(fill="both", expand=True)
        hint = tk.Label(prev, text="드래그로 회전 · 내부 렌더(추출 불가)", font=(FONT, 8),
                        bg=CARD, fg=SUB); hint.pack(side="bottom", pady=4)
        ang = {"x": 0.5, "y": 0.6, "lx": 0, "ly": 0}

        def draw():
            try:
                sz = min(max(lbl.winfo_width(), 300), max(lbl.winfo_height(), 300))
                sz = min(sz, 640) or 520
                im = core.render_mesh_image(mesh, size=sz, angle_x=ang["x"],
                                            angle_y=ang["y"], watermark=watermark)
                ph = ImageTk.PhotoImage(im); img_ref["img"] = ph
                lbl.configure(image=ph)
            except Exception as e:
                lbl.configure(text="3D 렌더 실패: %s" % e)

        def on_down(e):
            ang["lx"], ang["ly"] = e.x, e.y
        def on_drag(e):
            ang["y"] += (e.x - ang["lx"]) * 0.01
            ang["x"] += (e.y - ang["ly"]) * 0.01
            ang["lx"], ang["ly"] = e.x, e.y
            draw()
        lbl.bind("<Button-1>", on_down)
        lbl.bind("<B1-Motion>", on_drag)
        lbl.bind("<Button-3>", block)
        prev.after(60, draw)

    def open_native(name, data):
        """지원 안 되는 전문 포맷: 임시 작업폴더에 풀어 거래처의 해당 프로그램으로 열기. 닫으면 삭제."""
        try:
            d = workspace()
            path = os.path.join(d, os.path.basename(name))
            ext = os.path.splitext(name)[1].lower()
            wrote = False
            # 가능하면 워터마크를 박아서 내보냄 (이미지/PDF/오디오)
            if watermark:
                try:
                    if ext in IMG_EXT and HAVE_PIL:
                        im = _wm(Image.open(io.BytesIO(data)).convert("RGB"))
                        im.save(path)
                        wrote = True
                    elif ext == ".wav":
                        wmd = core.audio_watermark_wav(data, (data_pkg_id or watermark)[:8])
                        with open(path, "wb") as f:
                            f.write(wmd)
                        wrote = True
                    elif ext == ".pdf" and HAVE_PDF:
                        doc = fitz.open(stream=data, filetype="pdf")
                        for pg in doc:
                            rect = pg.rect
                            pg.insert_textbox(rect, (watermark + "    ") * 3,
                                              fontsize=14, color=(0.6, 0.6, 0.6),
                                              rotate=0, align=1, overlay=True)
                        doc.save(path)
                        wrote = True
                except Exception:
                    wrote = False
            if not wrote:
                with open(path, "wb") as f:
                    f.write(data)
            try:
                os.chmod(path, _stat.S_IREAD)   # 읽기 전용
            except Exception:
                pass
            ws["opened"].append(path)
            if sys.platform.startswith("win"):
                os.startfile(path)              # 연결된 프로그램으로 열기
            elif sys.platform == "darwin":
                _sp.call(["open", path])
            else:
                _sp.call(["xdg-open", path])
            messagebox.showinfo(APP_NAME,
                "연결된 프로그램으로 열었습니다.\n\n"
                "이 임시 파일은 뷰어를 닫으면 자동으로 삭제됩니다.\n"
                "열려 있는 동안의 복사·저장은 막지 못하는 점 참고하세요.")
        except Exception as e:
            messagebox.showerror(APP_NAME, "열기 실패: %s" % e)

    def show_other(name, size, data):
        clear_prev()
        f = tk.Frame(prev, bg=CARD); f.pack(expand=True)
        tk.Label(f, text="🗂", font=(FONT, 36), bg=CARD, fg=ACCENT).pack(pady=(0, 8))
        tk.Label(f, text="전문 포맷 파일", font=(FONT, 13, "bold"),
                 bg=CARD, fg=FG).pack()
        tk.Label(f, text="%s · %s" % (name, _fmt(size)), font=(FONT, 9),
                 bg=CARD, fg=SUB).pack(pady=(4, 2))
        tk.Label(f, text="CAD 등 미지원 포맷은 거래처 PC의 해당 프로그램으로 엽니다",
                 font=(FONT, 9), bg=CARD, fg=SUB).pack(pady=(2, 14))
        tk.Button(f, text="연결된 프로그램으로 열기", font=(FONT, 11, "bold"),
                  bg=ACCENT, fg="white", relief="flat", padx=16, pady=8, cursor="hand2",
                  command=lambda: open_native(name, data)).pack()
        tk.Label(f, text="닫으면 임시파일 자동 삭제 · 기한 만료 시 봉인 본체 자동 삭제",
                 font=(FONT, 8), bg=CARD, fg=SUB).pack(pady=(12, 0))

    def _fmt(n):
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return "%.0f %s" % (n, u) if u == "B" else "%.1f %s" % (n, u)
            n /= 1024
        return "%.1f TB" % n

    def on_select(_e=None):
        sel = lb.curselection()
        if not sel:
            return
        i = sel[0]
        name, data = files[i]
        ext = os.path.splitext(name)[1].lower()
        name_lbl.configure(text=name)
        meta_lbl.configure(text=_fmt(len(data)))
        if ext in TEXT_EXT:
            show_text(data)
        elif ext in IMG_EXT:
            root.after(30, lambda: show_image(data, name))
        elif ext == ".pdf":
            show_pdf(data)
        elif ext in core.VIDEO_EXT:
            show_video(data, name)
        elif ext in core.MESH_EXT:
            show_mesh(data, name)
        else:
            show_other(name, len(data), data)

    lb.bind("<<ListboxSelect>>", on_select)
    if files:
        lb.selection_set(0); on_select()

    # 전역 단축키 차단
    for seq in ("<Control-s>", "<Control-S>", "<Control-p>", "<Control-P>"):
        root.bind(seq, block)

    def on_close():
        wipe_workspace()
        try:
            root.destroy()
        except Exception:
            pass
        os._exit(0)

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


def register_file_association():
    """윈도우 HKCU 에 .igs 확장자를 이 뷰어로 연결(관리자 권한 불필요)."""
    if not sys.platform.startswith("win"):
        return False, "윈도우에서만 지원"
    try:
        import winreg
        exe = _self_path()
        progid = "igSeal.Sealed"
        # 확장자 -> ProgID
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.igs") as k:
            winreg.SetValue(k, "", winreg.REG_SZ, progid)
        # ProgID 설명 + 아이콘 + 실행 명령
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\%s" % progid) as k:
            winreg.SetValue(k, "", winreg.REG_SZ, "igSeal 봉인 파일")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                              r"Software\Classes\%s\DefaultIcon" % progid) as k:
            winreg.SetValue(k, "", winreg.REG_SZ, '"%s",0' % exe)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                              r"Software\Classes\%s\shell\open\command" % progid) as k:
            winreg.SetValue(k, "", winreg.REG_SZ, '"%s" "%%1"' % exe)
        # 탐색기 캐시 갱신
        try:
            import ctypes
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
        except Exception:
            pass
        return True, exe
    except Exception as e:
        return False, str(e)


def main():
    if os.environ.get("IGSEAL_SELFTEST") == "1" or "--selftest" in sys.argv:
        sys.exit(selftest())
    if "--register" in sys.argv:
        okr, info = register_file_association()
        print(("REGISTERED " if okr else "REGISTER_FAIL ") + str(info))
        sys.exit(0 if okr else 1)
    # GUI 실행 전, 윈도우에서 .igs 연결이 없으면 조용히 1회 자가등록
    if sys.platform.startswith("win"):
        try:
            register_file_association()
        except Exception:
            pass
    try:
        run_gui()
    except SystemExit:
        raise
    except BaseException:
        tb = traceback.format_exc()
        try:
            logp = os.path.join(os.path.dirname(_self_path()), "igseal_viewer_error.log")
            open(logp, "w", encoding="utf-8").write(tb)
        except Exception:
            pass
        try:
            import tkinter.messagebox as mb
            mb.showerror(APP_NAME, "실행 중 오류가 발생했습니다:\n\n" + tb[-800:])
        except Exception:
            sys.stderr.write(tb)
        sys.exit(1)


if __name__ == "__main__":
    main()
