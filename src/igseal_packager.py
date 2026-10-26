# -*- coding: utf-8 -*-
"""
igSeal 제작기 — 사장님이 쓰는 봉인 도구.
폴더/파일 선택 + 비밀번호 + 만료일 -> 단일 뷰어 exe 한 개 생성.
뷰어 스텁(igSeal-Viewer.exe) 바이트를 내장하고 그 뒤에 암호화 payload 를 붙인다.
console=False (GUI). CLI 봉인 모드도 지원(CI end-to-end 검증용).
"""
import os, sys, datetime, traceback

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import igseal_core as core

APP_NAME = "igSeal 제작기"
FONT = "Malgun Gothic"
BG = "#14161c"; FG = "#e8eaf0"; SUB = "#9aa3b2"
ACCENT = "#4a8cff"; CARD = "#1d212b"; LINE = "#2a2f3a"; OK = "#36c37e"; DANGER = "#ff5d5d"

STUB_NAME = "igSeal-Viewer.exe"


def find_stub_bytes():
    """내장 스텁 우선, 없으면 env/옆폴더에서 탐색."""
    cands = []
    if getattr(sys, "frozen", False):
        cands.append(os.path.join(getattr(sys, "_MEIPASS", BASE), STUB_NAME))
        cands.append(os.path.join(os.path.dirname(sys.executable), STUB_NAME))
    env = os.environ.get("IGSEAL_STUB")
    if env:
        cands.append(env)
    cands += [
        os.path.join(BASE, STUB_NAME),
        os.path.join(BASE, "..", "build", "dist", STUB_NAME),
        os.path.join(BASE, "dist", STUB_NAME),
    ]
    for p in cands:
        try:
            if p and os.path.isfile(p):
                with open(p, "rb") as f:
                    return f.read(), p
        except Exception:
            pass
    return None, None


def gather_files(paths):
    """파일/폴더 목록 -> [(상대이름, bytes)]. 폴더는 재귀 포함."""
    out = []
    for p in paths:
        if os.path.isdir(p):
            root_name = os.path.basename(p.rstrip("/\\")) or "folder"
            for dirpath, _dn, fn in os.walk(p):
                for name in fn:
                    full = os.path.join(dirpath, name)
                    rel = os.path.relpath(full, p)
                    arc = os.path.join(root_name, rel).replace("\\", "/")
                    with open(full, "rb") as f:
                        out.append((arc, f.read()))
        elif os.path.isfile(p):
            with open(p, "rb") as f:
                out.append((os.path.basename(p), f.read()))
    return out


def seal(paths, out_exe, password, expiry=None, title="봉인 패키지", stub_bytes=None):
    if stub_bytes is None:
        stub_bytes, _ = find_stub_bytes()
    if not stub_bytes:
        raise RuntimeError("뷰어 스텁(%s)을 찾지 못했습니다." % STUB_NAME)
    files = gather_files(paths)
    if not files:
        raise RuntimeError("봉인할 파일이 없습니다.")
    payload = core.build_payload(files, password, expiry=expiry, title=title)
    exe = core.append_to_stub(stub_bytes, payload)
    with open(out_exe, "wb") as f:
        f.write(exe)
    return len(files), len(exe)


# ---------------- CLI / selftest ----------------
def cli_seal(argv):
    # --seal SRC OUT PASSWORD [EXPIRY]
    i = argv.index("--seal")
    src = argv[i + 1]; out = argv[i + 2]; pw = argv[i + 3]
    exp = argv[i + 4] if len(argv) > i + 4 and not argv[i + 4].startswith("--") else None
    n, sz = seal([src], out, pw, expiry=exp, title="CLI 봉인")
    print("SEALED files=%d size=%d -> %s" % (n, sz, out))
    return 0


def selftest():
    import tempfile
    stub, where = find_stub_bytes()
    if not stub:
        stub = b"MZ" + os.urandom(60000)  # 스텁 미발견 시 더미로 로직만 검증
        where = "(dummy)"
    d = tempfile.mkdtemp()
    f1 = os.path.join(d, "spec.txt"); open(f1, "w", encoding="utf-8").write("납품 사양서\n보기 전용")
    out = os.path.join(d, "out.exe")
    n, sz = seal([f1], out, "selftestpw", expiry="2099-12-31", title="셀프테스트", stub_bytes=stub)
    pay = core.read_payload_from_file(out)
    assert pay is not None, "payload 재추출 실패"
    t, e, files = core.unlock(pay, "selftestpw")
    assert len(files) == 1 and files[0][1].decode("utf-8").startswith("납품 사양서"), "복호화 내용 불일치"
    msg = "SELFTEST PASS stub=%s files=%d size=%d" % (where, n, sz)
    print(msg)
    outp = os.environ.get("IGSEAL_SELFTEST_OUT")
    if outp:
        try:
            open(outp, "w", encoding="utf-8").write(msg + "\n")
        except Exception:
            pass
    return 0


# ---------------- GUI ----------------
def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    sel_paths = []

    root = tk.Tk(); root.title(APP_NAME); root.configure(bg=BG)
    W, H = 720, 640
    x = (root.winfo_screenwidth() - W) // 2; y = (root.winfo_screenheight() - H) // 2
    root.geometry("%dx%d+%d+%d" % (W, H, x, y)); root.minsize(640, 560)

    tk.Label(root, text="igSeal 봉인 제작기", font=(FONT, 16, "bold"), bg=BG, fg=FG).pack(pady=(18, 2))
    tk.Label(root, text="파일을 암호화해 보기 전용 단일 exe 로 만듭니다 · 만료일 자동삭제",
             font=(FONT, 9), bg=BG, fg=SUB).pack(pady=(0, 12))

    def card(parent, title):
        f = tk.Frame(parent, bg=CARD); f.pack(fill="x", padx=20, pady=6)
        tk.Label(f, text=title, font=(FONT, 10, "bold"), bg=CARD, fg=ACCENT,
                 anchor="w").pack(fill="x", padx=14, pady=(10, 4))
        return f

    # 1. 파일 선택
    c1 = card(root, "1. 봉인할 파일 / 폴더")
    lb = tk.Listbox(c1, height=5, font=(FONT, 9), bg=BG, fg=FG, relief="flat",
                    highlightthickness=0, selectbackground=ACCENT)
    lb.pack(fill="x", padx=14, pady=(0, 6))

    def refresh():
        lb.delete(0, "end")
        for p in sel_paths:
            tag = "📁 " if os.path.isdir(p) else "📄 "
            lb.insert("end", tag + p)

    def add_files():
        ps = filedialog.askopenfilenames(title="파일 선택")
        for p in ps:
            if p not in sel_paths:
                sel_paths.append(p)
        refresh()

    def add_folder():
        p = filedialog.askdirectory(title="폴더 선택")
        if p and p not in sel_paths:
            sel_paths.append(p); refresh()

    def clear_sel():
        sel_paths.clear(); refresh()

    bf = tk.Frame(c1, bg=CARD); bf.pack(fill="x", padx=14, pady=(0, 10))
    for txt, cmd in (("파일 추가", add_files), ("폴더 추가", add_folder), ("비우기", clear_sel)):
        tk.Button(bf, text=txt, font=(FONT, 9), bg=LINE, fg=FG, relief="flat",
                  command=cmd, cursor="hand2", padx=10).pack(side="left", padx=(0, 6))

    # 2. 제목 + 비번
    c2 = card(root, "2. 제목 · 비밀번호")
    inner = tk.Frame(c2, bg=CARD); inner.pack(fill="x", padx=14, pady=(0, 10))
    def row(lbl):
        r = tk.Frame(inner, bg=CARD); r.pack(fill="x", pady=3)
        tk.Label(r, text=lbl, font=(FONT, 9), bg=CARD, fg=SUB, width=10, anchor="w").pack(side="left")
        e = tk.Entry(r, font=(FONT, 10), bg=BG, fg=FG, relief="flat", insertbackground=FG)
        e.pack(side="left", fill="x", expand=True, ipady=4)
        return e
    e_title = row("제목")
    e_title.insert(0, "납품 패키지")
    e_pw = row("비밀번호"); e_pw.configure(show="●")
    e_pw2 = row("비밀번호 확인"); e_pw2.configure(show="●")

    # 3. 만료일
    c3 = card(root, "3. 사용기한 (지나면 자동삭제)")
    use_exp = tk.BooleanVar(value=True)
    r3 = tk.Frame(c3, bg=CARD); r3.pack(fill="x", padx=14, pady=(0, 4))
    tk.Checkbutton(r3, text="사용기한 설정", variable=use_exp, font=(FONT, 9),
                   bg=CARD, fg=FG, selectcolor=BG, activebackground=CARD,
                   activeforeground=FG).pack(side="left")
    e_exp = tk.Entry(r3, font=(FONT, 10), bg=BG, fg=FG, relief="flat", width=14,
                     insertbackground=FG, justify="center")
    e_exp.pack(side="left", padx=10, ipady=3)
    e_exp.insert(0, (datetime.date.today() + datetime.timedelta(days=30)).strftime("%Y-%m-%d"))

    def set_days(d):
        e_exp.delete(0, "end")
        e_exp.insert(0, (datetime.date.today() + datetime.timedelta(days=d)).strftime("%Y-%m-%d"))
    qf = tk.Frame(c3, bg=CARD); qf.pack(fill="x", padx=14, pady=(0, 10))
    for txt, d in (("+7일", 7), ("+30일", 30), ("+90일", 90), ("+180일", 180)):
        tk.Button(qf, text=txt, font=(FONT, 8), bg=LINE, fg=FG, relief="flat",
                  command=lambda dd=d: set_days(dd), cursor="hand2", padx=8).pack(side="left", padx=(0, 5))
    tk.Label(c3, text="형식: YYYY-MM-DD", font=(FONT, 8), bg=CARD, fg=SUB).pack(anchor="w", padx=14, pady=(0, 10))

    status = tk.Label(root, text="", font=(FONT, 9), bg=BG, fg=SUB)
    status.pack(pady=(4, 0))

    def do_seal():
        if not sel_paths:
            messagebox.showwarning(APP_NAME, "봉인할 파일/폴더를 추가하세요."); return
        pw = e_pw.get()
        if len(pw) < 4:
            messagebox.showwarning(APP_NAME, "비밀번호는 4자 이상이어야 합니다."); return
        if pw != e_pw2.get():
            messagebox.showwarning(APP_NAME, "비밀번호 확인이 일치하지 않습니다."); return
        exp = None
        if use_exp.get():
            try:
                datetime.datetime.strptime(e_exp.get().strip(), "%Y-%m-%d")
                exp = e_exp.get().strip()
            except Exception:
                messagebox.showwarning(APP_NAME, "사용기한 날짜 형식이 올바르지 않습니다 (YYYY-MM-DD)."); return
        title = e_title.get().strip() or "납품 패키지"
        default_name = title.replace(" ", "_") + "_봉인.exe"
        out = filedialog.asksaveasfilename(title="봉인 파일 저장 위치",
                                           defaultextension=".exe",
                                           initialfile=default_name,
                                           filetypes=[("실행파일", "*.exe")])
        if not out:
            return
        status.configure(text="봉인 중...", fg=SUB); root.update()
        try:
            n, sz = seal(sel_paths, out, pw, expiry=exp, title=title)
        except Exception as e:
            messagebox.showerror(APP_NAME, "봉인 실패:\n" + str(e)); status.configure(text=""); return
        mb_txt = ("봉인 완료\n\n파일 %d개 · %.1f MB\n%s\n\n"
                  "이 exe 하나만 거래처에 전달하세요." % (n, sz / 1048576, out))
        status.configure(text="완료: " + os.path.basename(out), fg=OK)
        messagebox.showinfo(APP_NAME, mb_txt)

    tk.Button(root, text="봉인하기", font=(FONT, 13, "bold"), bg=ACCENT, fg="white",
              relief="flat", command=do_seal, cursor="hand2", pady=10).pack(fill="x", padx=20, pady=16)

    stub, where = find_stub_bytes()
    if not stub:
        status.configure(text="주의: 뷰어 스텁(%s)을 찾지 못했습니다. 같은 폴더에 두세요." % STUB_NAME, fg=DANGER)

    root.mainloop()


def main():
    if "--seal" in sys.argv:
        sys.exit(cli_seal(sys.argv))
    if os.environ.get("IGSEAL_SELFTEST") == "1" or "--selftest" in sys.argv:
        sys.exit(selftest())
    try:
        run_gui()
    except SystemExit:
        raise
    except BaseException:
        tb = traceback.format_exc()
        try:
            open(os.path.join(os.path.dirname(sys.executable if getattr(sys, "frozen", False) else BASE),
                              "igseal_packager_error.log"), "w", encoding="utf-8").write(tb)
        except Exception:
            pass
        try:
            import tkinter.messagebox as mb
            mb.showerror(APP_NAME, "오류:\n\n" + tb[-800:])
        except Exception:
            sys.stderr.write(tb)
        sys.exit(1)


if __name__ == "__main__":
    main()
