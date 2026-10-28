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


def seal(paths, out_exe, password, expiry=None, title="봉인 패키지", stub_bytes=None,
         watermark="", max_opens=None, revoke_url="", require_activation=False, lease_days=None):
    if stub_bytes is None:
        stub_bytes, _ = find_stub_bytes()
    if not stub_bytes:
        raise RuntimeError("뷰어 스텁(%s)을 찾지 못했습니다." % STUB_NAME)
    files = gather_files(paths)
    if not files:
        raise RuntimeError("봉인할 파일이 없습니다.")
    import uuid as _uuid
    pkg_id = _uuid.uuid4().hex[:12]
    payload = core.build_payload(files, password, expiry=expiry, title=title,
                                 watermark=watermark, max_opens=max_opens,
                                 revoke_url=revoke_url, pkg_id=pkg_id,
                                 require_activation=require_activation, lease_days=lease_days)
    exe = core.append_to_stub(stub_bytes, payload)
    with open(out_exe, "wb") as f:
        f.write(exe)
    return len(files), len(exe), pkg_id


def seal_igs(paths, out_igs, password, expiry=None, title="봉인 패키지",
             watermark="", max_opens=None, revoke_url="", require_activation=False,
             lease_days=None, bind_machine=True, bind_path=False, open_timer_hours=None):
    """전용 .igs 파일로 봉인(뷰어가 확장자 연결로 염). 머신/경로 바인딩·오픈타이머."""
    files = gather_files(paths)
    if not files:
        raise RuntimeError("봉인할 파일이 없습니다.")
    import uuid as _uuid
    pkg_id = _uuid.uuid4().hex[:12]
    payload = core.build_payload(
        files, password, expiry=expiry, title=title, watermark=watermark,
        max_opens=max_opens, revoke_url=revoke_url, pkg_id=pkg_id,
        require_activation=require_activation, lease_days=lease_days,
        bind_machine=bind_machine, bind_path=("yes" if bind_path else ""),
        open_timer_hours=open_timer_hours)
    core.write_igs(out_igs, payload)
    return len(files), os.path.getsize(out_igs), pkg_id


# ---------------- CLI / selftest ----------------
def cli_seal(argv):
    # --seal SRC OUT PASSWORD [EXPIRY]
    i = argv.index("--seal")
    src = argv[i + 1]; out = argv[i + 2]; pw = argv[i + 3]
    exp = argv[i + 4] if len(argv) > i + 4 and not argv[i + 4].startswith("--") else None
    n, sz, pid = seal([src], out, pw, expiry=exp, title="CLI 봉인")
    print("SEALED files=%d size=%d pkg_id=%s -> %s" % (n, sz, pid, out))
    return 0


def cli_seal_igs(argv):
    # --seal-igs SRC OUT.igs PASSWORD [EXPIRY]
    i = argv.index("--seal-igs")
    src = argv[i + 1]; out = argv[i + 2]; pw = argv[i + 3]
    exp = argv[i + 4] if len(argv) > i + 4 and not argv[i + 4].startswith("--") else None
    n, sz, pid = seal_igs([src], out, pw, expiry=exp, title="CLI IGS",
                          bind_machine=True, open_timer_hours=48)
    print("SEALED_IGS files=%d size=%d pkg_id=%s -> %s" % (n, sz, pid, out))
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
    n, sz, pid = seal([f1], out, "selftestpw", expiry="2099-12-31", title="셀프테스트",
                      stub_bytes=stub, watermark="WM테스트", max_opens=3)
    pay = core.read_payload_from_file(out)
    assert pay is not None, "payload 재추출 실패"
    r = core.unlock(pay, "selftestpw")
    assert len(r["files"]) == 1 and r["files"][0][1].decode("utf-8").startswith("납품 사양서"), "복호화 내용 불일치"
    assert r["watermark"] == "WM테스트" and r["max_opens"] == 3, "옵션 보존 실패"
    msg = "SELFTEST PASS stub=%s files=%d size=%d pkg=%s" % (where, n, sz, pid)
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
    W, H = 720, 980
    x = (root.winfo_screenwidth() - W) // 2; y = max(0, (root.winfo_screenheight() - H) // 2)
    root.geometry("%dx%d+%d+%d" % (W, H, x, y)); root.minsize(660, 700)

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
    e_client = row("거래처")
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

    # 4. 추가 보호 (선택)
    c4 = card(root, "4. 추가 보호 (선택)")
    i4 = tk.Frame(c4, bg=CARD); i4.pack(fill="x", padx=14, pady=(0, 10))
    def row4(lbl, hint=""):
        r = tk.Frame(i4, bg=CARD); r.pack(fill="x", pady=3)
        tk.Label(r, text=lbl, font=(FONT, 9), bg=CARD, fg=SUB, width=11, anchor="w").pack(side="left")
        e = tk.Entry(r, font=(FONT, 10), bg=BG, fg=FG, relief="flat", insertbackground=FG)
        e.pack(side="left", fill="x", expand=True, ipady=4)
        if hint:
            tk.Label(i4, text=hint, font=(FONT, 8), bg=CARD, fg=SUB, anchor="w").pack(fill="x")
        return e
    e_wm = row4("워터마크", "열람·임시파일에 박히는 문구 (예: 거래처명/날짜). 비우면 안 넣음")
    e_opens = row4("최대 열람수", "숫자만. 비우면 무제한")
    e_revoke = row4("원격폐기 URL", "무료 GitHub Gist raw JSON. 미납 시 관리창에서 폐기하면 다음 실행 때 삭제")

    ract = tk.BooleanVar(value=False)
    rr = tk.Frame(c4, bg=CARD); rr.pack(fill="x", padx=14, pady=(2, 0))
    tk.Checkbutton(rr, text="최초 1회 온라인 활성화 필수 (랜선 뽑고 첫 실행 차단)", variable=ract,
                   font=(FONT, 9), bg=CARD, fg=FG, selectcolor=BG, activebackground=CARD,
                   activeforeground=FG).pack(side="left")
    rl = tk.Frame(c4, bg=CARD); rl.pack(fill="x", padx=14, pady=(2, 10))
    tk.Label(rl, text="오프라인 허용일", font=(FONT, 9), bg=CARD, fg=SUB, width=11, anchor="w").pack(side="left")
    e_lease = tk.Entry(rl, font=(FONT, 10), bg=BG, fg=FG, relief="flat", width=8,
                       insertbackground=FG, justify="center"); e_lease.pack(side="left", ipady=3)
    tk.Label(rl, text="일. 이 기간마다 인터넷 재연결 필요. 비우면 리스 안 씀(활성화/폐기엔 URL 필요)",
             font=(FONT, 8), bg=CARD, fg=SUB).pack(side="left", padx=6)

    # 5. 전용 .igs 파일 + 이동 금지 + 자동 타이머 삭제
    c5 = card(root, "5. 전용 .igs 파일 (이동 금지 · 타이머 삭제)")
    igs_mode = tk.BooleanVar(value=True)
    r5a = tk.Frame(c5, bg=CARD); r5a.pack(fill="x", padx=14, pady=(2, 0))
    tk.Checkbutton(r5a, text=".igs 전용 파일로 만들기 (우리 뷰어로만 열림)", variable=igs_mode,
                   font=(FONT, 9), bg=CARD, fg=FG, selectcolor=BG, activebackground=CARD,
                   activeforeground=FG).pack(side="left")
    bind_m = tk.BooleanVar(value=True); bind_p = tk.BooleanVar(value=False)
    r5b = tk.Frame(c5, bg=CARD); r5b.pack(fill="x", padx=14, pady=(2, 0))
    tk.Checkbutton(r5b, text="다른 PC로 복사 금지(처음 연 PC 고정)", variable=bind_m,
                   font=(FONT, 9), bg=CARD, fg=FG, selectcolor=BG, activebackground=CARD,
                   activeforeground=FG).pack(side="left")
    tk.Checkbutton(r5b, text="다른 폴더·USB로 이동 금지(처음 연 위치 고정)", variable=bind_p,
                   font=(FONT, 9), bg=CARD, fg=FG, selectcolor=BG, activebackground=CARD,
                   activeforeground=FG).pack(side="left", padx=(14, 0))
    r5c = tk.Frame(c5, bg=CARD); r5c.pack(fill="x", padx=14, pady=(2, 10))
    tk.Label(r5c, text="개봉 후 삭제", font=(FONT, 9), bg=CARD, fg=SUB, width=11, anchor="w").pack(side="left")
    e_timer = tk.Entry(r5c, font=(FONT, 10), bg=BG, fg=FG, relief="flat", width=8,
                       insertbackground=FG, justify="center"); e_timer.pack(side="left", ipady=3)
    tk.Label(r5c, text="시간. 처음 연 뒤 이 시간이 지나면 자동 삭제. 비우면 안 씀",
             font=(FONT, 8), bg=CARD, fg=SUB).pack(side="left", padx=6)

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
        use_igs = igs_mode.get()
        if use_igs:
            default_name = title.replace(" ", "_") + "_봉인.igs"
            out = filedialog.asksaveasfilename(title="봉인 파일 저장 위치",
                                               defaultextension=".igs",
                                               initialfile=default_name,
                                               filetypes=[("igSeal 봉인 파일", "*.igs")])
        else:
            default_name = title.replace(" ", "_") + "_봉인.exe"
            out = filedialog.asksaveasfilename(title="봉인 파일 저장 위치",
                                               defaultextension=".exe",
                                               initialfile=default_name,
                                               filetypes=[("실행파일", "*.exe")])
        if not out:
            return
        timer_h = None
        if e_timer.get().strip():
            try:
                timer_h = float(e_timer.get().strip())
                if timer_h <= 0:
                    raise ValueError
            except Exception:
                messagebox.showwarning(APP_NAME, "개봉 후 삭제 시간은 양수여야 합니다."); return
        wm = e_wm.get().strip()
        mo = None
        if e_opens.get().strip():
            try:
                mo = int(e_opens.get().strip())
                if mo <= 0:
                    raise ValueError
            except Exception:
                messagebox.showwarning(APP_NAME, "최대 열람수는 양의 정수여야 합니다."); return
        rv = e_revoke.get().strip()
        req_act = ract.get()
        lease = None
        if e_lease.get().strip():
            try:
                lease = int(e_lease.get().strip())
                if lease <= 0:
                    raise ValueError
            except Exception:
                messagebox.showwarning(APP_NAME, "오프라인 허용일은 양의 정수여야 합니다."); return
        if (req_act or lease) and not rv:
            messagebox.showwarning(APP_NAME, "활성화/리스를 쓰려면 원격폐기 URL이 필요합니다."); return
        status.configure(text="봉인 중...", fg=SUB); root.update()
        try:
            if use_igs:
                n, sz, pid = seal_igs(sel_paths, out, pw, expiry=exp, title=title,
                                      watermark=wm, max_opens=mo, revoke_url=rv,
                                      require_activation=req_act, lease_days=lease,
                                      bind_machine=bind_m.get(), bind_path=bind_p.get(),
                                      open_timer_hours=timer_h)
            else:
                n, sz, pid = seal(sel_paths, out, pw, expiry=exp, title=title,
                                  watermark=wm, max_opens=mo, revoke_url=rv,
                                  require_activation=req_act, lease_days=lease)
        except Exception as e:
            messagebox.showerror(APP_NAME, "봉인 실패:\n" + str(e)); status.configure(text=""); return
        # 제작자 대장 기록
        import datetime as _dt
        core.ledger_add({
            "pkg_id": pid, "title": title, "client": e_client.get().strip(),
            "created": _dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "expiry": exp or "", "revoke_url": rv, "status": "active", "extend": "",
        })
        extra = "\n패키지 ID: %s" % pid
        if rv:
            extra += "\n(미납 시 관리창에서 이 건을 폐기하면 원격 삭제됩니다)"
        mb_txt = ("봉인 완료\n\n파일 %d개 · %.1f MB\n%s%s\n\n"
                  "이 exe 하나만 거래처에 전달하세요." % (n, sz / 1048576, out, extra))
        status.configure(text="완료: %s (ID %s)" % (os.path.basename(out), pid), fg=OK)
        messagebox.showinfo(APP_NAME, mb_txt)

    def open_manager():
        win = tk.Toplevel(root); win.title("패키지 관리 — 폐기 / 연장"); win.configure(bg=BG)
        win.geometry("760x560"); win.grab_set()
        tk.Label(win, text="봉인한 패키지 관리", font=(FONT, 14, "bold"), bg=BG, fg=FG).pack(pady=(14, 2))
        tk.Label(win, text="폐기하거나 만료일을 연장한 뒤, 아래 'revoke.json 저장'으로 내보내 Gist에 올리세요",
                 font=(FONT, 9), bg=BG, fg=SUB).pack(pady=(0, 10))
        canv = tk.Canvas(win, bg=BG, highlightthickness=0)
        sb = tk.Scrollbar(win, command=canv.yview); canv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); canv.pack(side="top", fill="both", expand=True, padx=14)
        holder = tk.Frame(canv, bg=BG); canv.create_window((0, 0), window=holder, anchor="nw")

        rows = core.ledger_all()
        if not rows:
            tk.Label(holder, text="아직 봉인한 패키지가 없습니다.", font=(FONT, 10),
                     bg=BG, fg=SUB).pack(pady=20)
        for r in rows:
            pid = r.get("pkg_id", "")
            fr = tk.Frame(holder, bg=CARD); fr.pack(fill="x", pady=5, padx=2)
            top = tk.Frame(fr, bg=CARD); top.pack(fill="x", padx=12, pady=(8, 2))
            tk.Label(top, text=r.get("title", ""), font=(FONT, 11, "bold"),
                     bg=CARD, fg=FG).pack(side="left")
            tk.Label(top, text="  %s" % (r.get("client", "") or "거래처 미기재"),
                     font=(FONT, 9), bg=CARD, fg=SUB).pack(side="left")
            tk.Label(top, text="ID %s · 만료 %s" % (pid, r.get("expiry", "") or "없음"),
                     font=(FONT, 8), bg=CARD, fg=SUB).pack(side="right")
            ctl = tk.Frame(fr, bg=CARD); ctl.pack(fill="x", padx=12, pady=(0, 8))
            sv = tk.StringVar(value=r.get("status", "active"))

            def mk_toggle(pid=pid, sv=sv, lbl=None):
                def t():
                    ns = "revoked" if sv.get() == "active" else "active"
                    sv.set(ns); core.ledger_update(pid, status=ns)
                    lbl.configure(text=("폐기됨" if ns == "revoked" else "활성"),
                                  fg=(DANGER if ns == "revoked" else OK))
                return t
            st_lbl = tk.Label(ctl, text=("폐기됨" if sv.get() == "revoked" else "활성"),
                              font=(FONT, 9, "bold"), bg=CARD,
                              fg=(DANGER if sv.get() == "revoked" else OK), width=7)
            st_lbl.pack(side="left")
            btn = tk.Button(ctl, text="폐기 / 해제", font=(FONT, 9), bg=LINE, fg=FG,
                            relief="flat", cursor="hand2", padx=8)
            btn.configure(command=mk_toggle(pid, sv, st_lbl)); btn.pack(side="left", padx=8)
            tk.Label(ctl, text="연장일", font=(FONT, 9), bg=CARD, fg=SUB).pack(side="left", padx=(16, 4))
            ee = tk.Entry(ctl, font=(FONT, 9), bg=BG, fg=FG, relief="flat", width=12,
                          insertbackground=FG, justify="center")
            ee.insert(0, r.get("extend", "") or ""); ee.pack(side="left", ipady=2)

            def mk_save(pid=pid, ee=ee):
                def s():
                    v = ee.get().strip()
                    if v:
                        try:
                            datetime.datetime.strptime(v, "%Y-%m-%d")
                        except Exception:
                            messagebox.showwarning("관리", "연장일 형식 YYYY-MM-DD"); return
                    core.ledger_update(pid, extend=v)
                    messagebox.showinfo("관리", "저장됨")
                return s
            tk.Button(ctl, text="연장 저장", font=(FONT, 9), bg=LINE, fg=FG, relief="flat",
                      cursor="hand2", padx=8, command=mk_save(pid, ee)).pack(side="left", padx=6)

        holder.update_idletasks(); canv.configure(scrollregion=canv.bbox("all"))

        def export():
            p = filedialog.asksaveasfilename(title="revoke.json 저장", defaultextension=".json",
                                             initialfile="revoke.json",
                                             filetypes=[("JSON", "*.json")])
            if not p:
                return
            nrev, next_ = core.ledger_export_revoke(p)
            messagebox.showinfo("관리", "저장 완료\n\n폐기 %d건 · 연장 %d건\n%s\n\n"
                                "이 파일 내용을 Gist(원격폐기 URL)에 붙여넣으면 적용됩니다."
                                % (nrev, next_, p))
        tk.Button(win, text="revoke.json 저장 (Gist에 올릴 파일)", font=(FONT, 11, "bold"),
                  bg=ACCENT, fg="white", relief="flat", command=export, cursor="hand2",
                  pady=8).pack(fill="x", padx=14, pady=12)

    bbar = tk.Frame(root, bg=BG); bbar.pack(fill="x", padx=20, pady=16)
    tk.Button(bbar, text="봉인하기", font=(FONT, 13, "bold"), bg=ACCENT, fg="white",
              relief="flat", command=do_seal, cursor="hand2", pady=10).pack(side="left", fill="x", expand=True)
    tk.Button(bbar, text="패키지 관리", font=(FONT, 11), bg=LINE, fg=FG,
              relief="flat", command=open_manager, cursor="hand2", pady=10, padx=16).pack(side="left", padx=(10, 0))

    stub, where = find_stub_bytes()
    if not stub:
        status.configure(text="주의: 뷰어 스텁(%s)을 찾지 못했습니다. 같은 폴더에 두세요." % STUB_NAME, fg=DANGER)

    root.mainloop()


def main():
    if "--seal-igs" in sys.argv:
        sys.exit(cli_seal_igs(sys.argv))
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
