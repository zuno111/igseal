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
    payload = core.read_payload_from_file(path)
    if payload is None:
        return _report("SELFTEST FAIL: payload 없음 (file=%s)" % path, 1)
    hdr, _ = core.parse_header(payload)
    if core.header_tampered(hdr):
        return _report("SELFTEST FAIL: 헤더 변조 탐지됨", 1)
    try:
        title, exp, files = core.unlock(payload, pw)
    except Exception as e:
        return _report("SELFTEST FAIL: unlock 실패: %s" % e, 1)
    return _report("SELFTEST PASS title=%r expiry=%r files=%d" % (title, exp, len(files)), 0)


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

    self_path = _self_path()
    payload = core.read_payload_from_file(self_path)

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
    if core.clock_rolled_back(hdr):
        die("시스템 시계가 과거로 변경된 것이 감지되었습니다.\n날짜를 올바르게 맞춘 뒤 다시 실행하세요.")
        return
    if core.is_expired(hdr):
        die("사용 기간이 만료되어 파일이 삭제되었습니다.", destruct=True)
        return

    # ---- 비밀번호 입력 ----
    state = {"files": None, "title": "", "expiry": hdr.get("expiry")}

    def ask_password():
        dlg = tk.Toplevel(root); dlg.title(APP_NAME); dlg.configure(bg=BG)
        dlg.resizable(False, False); dlg.grab_set()
        w, h = 380, 220
        x = (dlg.winfo_screenwidth() - w) // 2; y = (dlg.winfo_screenheight() - h) // 2
        dlg.geometry("%dx%d+%d+%d" % (w, h, x, y))
        tk.Label(dlg, text="🔒", font=(FONT, 28), bg=BG, fg=ACCENT).pack(pady=(22, 4))
        tk.Label(dlg, text=hdr.get("title", "봉인 패키지"), font=(FONT, 13, "bold"),
                 bg=BG, fg=FG).pack()
        exp = hdr.get("expiry")
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
                t, e, files = core.unlock(payload, ent.get())
            except ValueError:
                tries["n"] += 1
                ent.delete(0, "end")
                messagebox.showwarning(APP_NAME, "비밀번호가 올바르지 않습니다. (%d회)" % tries["n"])
                return
            state["files"] = files; state["title"] = t; state["expiry"] = e
            dlg.destroy()

        tk.Button(dlg, text="열기", font=(FONT, 11, "bold"), bg=ACCENT, fg="white",
                  relief="flat", width=10, command=submit, cursor="hand2").pack(pady=10)
        ent.bind("<Return>", submit)
        dlg.protocol("WM_DELETE_WINDOW", lambda: (dlg.destroy(), os._exit(0)))
        dlg.wait_window()

    ask_password()
    if state["files"] is None:
        os._exit(0)

    # ---- 메인 뷰어 ----
    files = state["files"]
    root.deiconify()
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

    def clear_prev():
        for w in prev.winfo_children():
            w.destroy()
        img_ref["img"] = None

    def block(*_):
        return "break"

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
                im.thumbnail((640, 2000))
                ph = ImageTk.PhotoImage(im); keep.append(ph)
                tk.Label(inner, image=ph, bg=CARD).pack(pady=6)
            img_ref["img"] = keep
            inner.update_idletasks()
            cv.configure(scrollregion=cv.bbox("all"))
        except Exception as e:
            tk.Label(prev, text="PDF 렌더 실패: %s" % e, font=(FONT, 10),
                     bg=CARD, fg=SUB).pack(expand=True)

    def open_native(name, data):
        """전문 포맷: 임시 작업폴더에 풀어 거래처의 해당 프로그램으로 열기. 닫으면 삭제."""
        try:
            d = workspace()
            path = os.path.join(d, os.path.basename(name))
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
        tk.Label(f, text="CAD · 3D · 영상 등은 거래처 PC의 해당 프로그램으로 엽니다",
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


def main():
    if os.environ.get("IGSEAL_SELFTEST") == "1" or "--selftest" in sys.argv:
        sys.exit(selftest())
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
