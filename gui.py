# -*- coding: utf-8 -*-
"""
NetKill GUI —— 图形界面（一键让室友设备断网 / 到点自动恢复）

安全设计：
  * 网关与本机在列表里直接标记并禁止选择
  * 代码层二次校验：目标 == 本机 / 网关 一律拒绝
  * 所有可能影响本机的操作必须先选目标再点按钮，没有"全段攻击"入口
  * 停止/关闭窗口/到时 三种情况都自动回毒恢复
"""
from __future__ import annotations

import ipaddress
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from core.arpnet import (  # noqa: E402
    Adapter,
    ArpKiller,
    Device,
    NetError,
    can_send_packets,
    is_admin,
    list_adapters,
    resolve_adapter,
)

BG = "#12141c"
PANEL = "#1b1e2a"
FG = "#e6e8f0"
MUTED = "#8b90a2"
GREEN = "#37d67a"
RED = "#ff5c5c"
YELLOW = "#ffc857"
CYAN = "#5ac8fa"


def _enable_dpi_awareness() -> None:
    """让 Tk 自己感知高 DPI，避免 Windows 缩放导致的模糊。"""
    if os.name != "nt":
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)   # Per-Monitor
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


class App(tk.Tk):
    def __init__(self) -> None:
        _enable_dpi_awareness()
        super().__init__()
        # 高 DPI 适配：scaling 让字体清晰，窗口尺寸按缩放放大
        try:
            dpi = float(self.winfo_fpixels("1i"))
        except Exception:
            dpi = 96.0
        self._scale = max(1.0, dpi / 96.0)
        try:
            self.tk.call("tk", "scaling", dpi / 72.0)
        except tk.TclError:
            pass
        self.title("NetKill · 室友戒网瘾 · 一键断网")
        self.minsize(int(880 * self._scale), int(620 * self._scale))
        self.configure(bg=BG)
        self._center_window(int(960 * self._scale), int(780 * self._scale))
        # 启动时置顶闪一下，确保用户看得到（尤其被其它窗口压住时）
        self.after(50, self._flash_on_top)

        self.ui_q: "queue.Queue[tuple]" = queue.Queue()
        self.adapters: list[Adapter] = []
        self.killer: ArpKiller | None = None
        self.attack_thread: threading.Thread | None = None
        self.scan_thread: threading.Thread | None = None
        self.deadline: float | None = None
        self._pump_id = None
        self._last_devices: list = []
        self._last_adapter = None
        self._auto_scan_id = None
        self._group_iid = None

        self._build_style()
        self._build_ui()
        self._pump_id = self.after(45, self._pump)
        self.after(300, self.refresh_adapters)

    # ------------------------------------------------------------------ UI
    def _center_window(self, w: int, h: int) -> None:
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        # 不超过屏幕可用的 92%，避免高 DPI 下窗口超出屏幕
        w = min(w, int(sw * 0.92))
        h = min(h, int(sh * 0.92))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2 - 20)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _flash_on_top(self) -> None:
        # 只做前置与聚焦，不置顶（用户要求不要 always-on-top）
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
        except tk.TclError:
            pass

    def _restart_as_admin(self) -> None:
        """以管理员身份重新启动自己。"""
        try:
            import ctypes
            exe = sys.executable
            script = os.path.join(HERE, "gui.py")
            params = f'"{script}"'
            r = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, params, HERE, 1
            )
            if r <= 32:
                messagebox.showwarning("NetKill", "提权被取消或失败，仍可只读扫描，但无法断网。")
                return
            self.destroy()
        except Exception as e:
            messagebox.showerror("NetKill", f"提权重启失败：{e}")

    def _build_style(self) -> None:
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=PANEL)
        st.configure("TFrame", background=BG)
        st.configure("Panel.TFrame", background=PANEL)
        st.configure("TLabel", background=BG, foreground=FG, font=("Microsoft YaHei UI", 9))
        st.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Microsoft YaHei UI", 9))
        st.configure("Title.TLabel", background=BG, foreground=FG,
                     font=("Microsoft YaHei UI", 16, "bold"))
        st.configure("TButton", font=("Microsoft YaHei UI", 9), padding=(10, 6))
        st.configure("TCheckbutton", background=BG, foreground=FG,
                     font=("Microsoft YaHei UI", 9), padding=(2, 2))
        st.map("TCheckbutton",
               background=[("active", BG)],
               foreground=[("active", FG)])
        st.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                     insertcolor=FG, padding=5)
        st.configure("TCombobox", fieldbackground=PANEL, background="#242838",
                     foreground=FG, arrowcolor=FG, padding=5)
        st.map("TCombobox",
               fieldbackground=[("readonly", PANEL)],
               foreground=[("readonly", FG)],
               selectbackground=[("readonly", PANEL)],
               selectforeground=[("readonly", FG)],
               background=[("readonly", PANEL)])
        # Combobox 下拉列表（Tk 原生 Listbox）配色
        self.option_add("*TCombobox*Listbox.background", PANEL)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", "#2f6feb")
        self.option_add("*TCombobox*Listbox.selectForeground", "white")
        st.configure("Accent.TButton", font=("Microsoft YaHei UI", 10, "bold"),
                     padding=(14, 8), background="#2f6feb", foreground="white")
        st.map("Accent.TButton", background=[("active", "#3b7bf5")])
        st.configure("Danger.TButton", font=("Microsoft YaHei UI", 10, "bold"),
                     padding=(14, 8), background="#c8382f", foreground="white")
        st.map("Danger.TButton", background=[("active", "#e0483e")])
        # 主操作按钮（更大更醒目）
        st.configure("BigDanger.TButton", font=("Microsoft YaHei UI", 13, "bold"),
                     padding=(34, 16), background="#c8382f", foreground="white")
        st.map("BigDanger.TButton",
               background=[("active", "#e0483e"), ("disabled", "#5a2a28")],
               foreground=[("disabled", "#c9a3a0")])
        st.configure("BigAccent.TButton", font=("Microsoft YaHei UI", 12, "bold"),
                     padding=(30, 15), background="#2f6feb", foreground="white")
        st.map("BigAccent.TButton",
               background=[("active", "#3b7bf5"), ("disabled", "#2a3550")],
               foreground=[("disabled", "#8ea3c2")])
        # 扫描栏按钮（中等偏大）
        st.configure("Medium.TButton", font=("Microsoft YaHei UI", 11, "bold"),
                     padding=(20, 12), background="#2a3550", foreground="#dfe6f5")
        st.map("Medium.TButton",
               background=[("active", "#36446b"), ("disabled", "#232838")],
               foreground=[("active", "white"), ("disabled", "#6b7182")])
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                     foreground=FG, rowheight=int(26 * self._scale), borderwidth=0,
                     font=("Microsoft YaHei UI", 9))
        st.configure("Treeview.Heading", background="#242838", foreground=FG,
                     font=("Microsoft YaHei UI", 9, "bold"))
        st.map("Treeview", background=[("selected", "#2f6feb")])
        st.configure("TCombobox", padding=5)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=16)
        root.pack(fill="both", expand=True)

        # 标题
        head = ttk.Frame(root)
        head.pack(fill="x")
        ttk.Label(head, text="NetKill", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="   局域网断网 · 室友戒网瘾/辅助睡眠 · 到点自动恢复",
                  style="Muted.TLabel").pack(side="left", pady=(6, 0))
        if is_admin():
            ttk.Label(head, text="✔ 管理员", foreground=GREEN,
                      background=BG, font=("Microsoft YaHei UI", 9, "bold")).pack(side="right")
        elif can_send_packets():
            ttk.Label(head, text="✔ 普通权限", foreground=GREEN,
                      background=BG, font=("Microsoft YaHei UI", 9, "bold")).pack(side="right")
        else:
            ttk.Label(head, text="✘ 需要管理员", foreground=RED,
                      background=BG, font=("Microsoft YaHei UI", 9, "bold")).pack(side="right")
            ttk.Button(head, text="以管理员身份重启",
                       command=self._restart_as_admin).pack(side="right", padx=8)

        # 网卡栏
        bar = ttk.Frame(root)
        bar.pack(fill="x", pady=(14, 8))
        ttk.Label(bar, text="网卡：").pack(side="left")
        self.iface_var = tk.StringVar()
        self.iface_box = ttk.Combobox(bar, textvariable=self.iface_var, state="readonly", width=58)
        self.iface_box.pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="刷新网卡", command=self.refresh_adapters).pack(
            side="left", padx=(0, 14))
        # 主按钮默认用只读扫描（不发包、校园网最稳）
        self.scan_btn = ttk.Button(bar, text="扫描网段设备", style="BigAccent.TButton",
                                   command=lambda: self.scan(passive=True))
        self.scan_btn.pack(side="right")
        self.passive_btn = ttk.Button(bar, text="主动扫描（会发包）",
                                      style="Medium.TButton",
                                      command=lambda: self.scan(passive=False))
        self.passive_btn.pack(side="right", padx=(0, 10))

        # 设备表（树形：代理 MAC 为父节点，真实 MAC 设备为子项）
        table_wrap = ttk.Frame(root)
        table_wrap.pack(fill="both", expand=True)
        cols = ("ip", "mac", "name", "tag")
        self.tree = ttk.Treeview(table_wrap, columns=cols, show="tree headings",
                                 height=11, selectmode="browse")
        self.tree.column("#0", width=int(34 * self._scale), stretch=False)
        self.tree.heading("#0", text="")
        for c, t, w, anchor in (
            ("ip", "IP 地址", 150, "w"),
            ("mac", "MAC 地址", 190, "w"),
            ("name", "主机名 / 厂商", 300, "w"),
            ("tag", "状态", 130, "w"),
        ):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor=anchor)
        sb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_pick)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.tag_configure("gw", foreground=YELLOW)
        self.tree.tag_configure("proxy", foreground=YELLOW)   # 代理 MAC：只能广播断网
        self.tree.tag_configure("real", foreground=GREEN)     # 真实 MAC：可单播精准断网
        self.tree.tag_configure("self", foreground=MUTED)
        self.tree.tag_configure("offline", foreground="#5b6172")
        self.tree.tag_configure("target", foreground=RED)
        self.tree.tag_configure("group", foreground=CYAN)

        # 目标 + 操作
        ctl = ttk.Frame(root)
        ctl.pack(fill="x", pady=(10, 6))
        self._target_label = ttk.Label(ctl, text="目标 IP：")
        self._target_label.pack(side="left")
        self.target_var = tk.StringVar()
        ttk.Entry(ctl, textvariable=self.target_var, width=20,
                  font=("Consolas", 10)).pack(side="left")
        ttk.Label(ctl, text="   断网时长：").pack(side="left")
        self.dur_var = tk.StringVar(value="不自动停")
        self.dur_box = ttk.Combobox(ctl, textvariable=self.dur_var, state="readonly", width=16,
                                    values=["不自动停", "5 分钟", "15 分钟", "30 分钟",
                                            "1 小时", "2 小时", "自定义"])
        self.dur_box.pack(side="left")
        self.dur_box.bind("<<ComboboxSelected>>", self._on_duration_change)
        self.custom_var = tk.StringVar(value="60")
        self.custom_entry = ttk.Entry(ctl, textvariable=self.custom_var, width=6,
                                      font=("Consolas", 10))
        self.custom_min_label = ttk.Label(ctl, text="分钟", style="Muted.TLabel")
        # 默认「不自动停」→ 自定义框完全不显示
        self._on_duration_change()

        # 按钮行：左移一半（缩进取对齐位置的 50%）
        try:
            self.update_idletasks()
            indent = int((self._target_label.winfo_reqwidth() + 6) * 0.5)
        except Exception:
            indent = int(42 * self._scale)
        btns = ttk.Frame(root)
        btns.pack(fill="x", pady=(6, 6), padx=(indent, 0))
        self.start_btn = ttk.Button(btns, text="⚡ 一键断网", style="BigDanger.TButton",
                                    command=self.start_attack)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text="■ 恢复网络", style="BigAccent.TButton",
                                   command=self.stop_attack, state="disabled")
        self.stop_btn.pack(side="left", padx=(14, 8))
        self.probe_btn = ttk.Button(btns, text="🔍 探测网络", style="Medium.TButton",
                                    command=self.probe_target)
        self.probe_btn.pack(side="left", padx=(4, 8))
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(btns, textvariable=self.status_var, foreground=CYAN,
                  background=BG, font=("Microsoft YaHei UI", 11, "bold")).pack(side="right")

        # 选项单独一行，避免和按钮挤在一起
        opts = ttk.Frame(root)
        opts.pack(fill="x", pady=(0, 8))
        self.forward_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="限速模式（开启转发，不彻底断）",
                        variable=self.forward_var,
                        command=self._sync_start_label).pack(side="left")
        self.broadcast_var = tk.BooleanVar(value=True)   # 校园网默认开启广播穿透
        ttk.Checkbutton(opts, text="广播模式（校园网隔离穿透·默认开）",
                        variable=self.broadcast_var).pack(side="left", padx=16)
        self.auto_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="实时扫描（每 5 秒自动刷新）",
                        variable=self.auto_scan_var,
                        command=self._toggle_auto_scan).pack(side="left", padx=(0, 16))
        self._sync_start_label()

        # 日志
        log_wrap = ttk.Frame(root)
        log_wrap.pack(fill="both", expand=True, pady=(6, 0))
        self.log = tk.Text(log_wrap, height=10, bg="#0d0f15", fg="#9fe3b0", bd=0,
                           font=("Consolas", 9), wrap="word", state="disabled")
        lsb = ttk.Scrollbar(log_wrap, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=lsb.set)
        self.log.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")

        tip = ("提示：需管理员运行；断网后对方表现为『Wi-Fi 已连接但无网络』。"
               "点『恢复网络』或到时自动回毒。")
        ttk.Label(root, text=tip, style="Muted.TLabel").pack(fill="x", pady=(8, 0))

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ 日志
    def put_log(self, line: str) -> None:
        self.ui_q.put(("log", line))

    def _apply_log(self, lines) -> None:
        """批量写入日志：一次 insert 少一次重绘，界面更流畅。"""
        if isinstance(lines, str):
            lines = [lines]
        if not lines:
            return
        # 日志超过阈值时一次性裁剪，避免频繁大段删除造成卡顿
        try:
            row = int(self.log.index("end-1c").split(".")[0])
        except Exception:
            row = 0
        if row > 600:
            self.log.configure(state="normal")
            self.log.delete("1.0", "300.0")
            self.log.configure(state="disabled")
        self.log.configure(state="normal")
        self.log.insert("end", "\n".join(lines) + "\n")
        self.log.configure(state="disabled")
        # 只有用户在底部时才自动滚动，避免用户上翻查看历史时被拽回
        try:
            if self.log.yview()[1] > 0.98:
                self.log.yview_moveto(1.0)
        except Exception:
            pass

    def _pump(self) -> None:
        logs = []
        try:
            while True:
                kind, payload = self.ui_q.get_nowait()
                if kind == "log":
                    logs.append(payload)
                elif kind == "adapters":
                    self._apply_adapters(payload)
                elif kind == "scan_done":
                    self._fill_devices(payload)
                elif kind == "hosts":
                    self._apply_hosts(payload)
                elif kind == "expand":
                    self._apply_expand(payload)
                elif kind == "probe":
                    self._show_probe_result(payload)
                elif kind == "started":
                    self.status_var.set("● 限速中" if self.forward_var.get() else "● 断网中")
                    self.start_btn.configure(state="disabled")
                    self.stop_btn.configure(state="normal")
                elif kind == "stopped":
                    self.status_var.set("就绪")
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self._sync_start_label()
                    self.deadline = None
                elif kind == "warning":
                    # 绝不在事件泵里弹模态框：弹窗被窗口挡住时 Tk 会整体卡死
                    logs.append(f"[警告] {payload}")
        except queue.Empty:
            pass
        except Exception as e:      # 单条消息出错不能拖死整个 UI 泵
            try:
                self._apply_log(f"[界面] 处理消息异常：{e}")
            except Exception:
                pass
        # 倒计时显示
        try:
            if logs:
                self._apply_log(logs)
            if self.deadline:
                left = int(self.deadline - time.time())
                if left > 0:
                    m, s = divmod(left, 60)
                    tag = "限速中" if self.forward_var.get() else "断网中"
                    self.status_var.set(f"● {tag} · 剩余 {m:02d}:{s:02d}")
                else:
                    self.status_var.set("● 到时，正在恢复 …")
                    self.stop_attack()
        finally:
            # 只注册一条链：先撤销旧的再排新的，避免指数级重复回调
            try:
                if self._pump_id:
                    self.after_cancel(self._pump_id)
            except Exception:
                pass
            self._pump_id = self.after(45, self._pump)

    # ------------------------------------------------------------------ 网卡/扫描
    def refresh_adapters(self) -> None:
        """后台读取网卡，避免任何系统调用阻塞 Tk 主线程。"""
        self.put_log("[网卡] 正在读取网卡信息 …")

        def work():
            try:
                items = list_adapters()
                self.ui_q.put(("adapters", items))
            except Exception as e:
                self.ui_q.put(("adapters", []))
                self.put_log(f"[错误] 读取网卡失败：{e}")

        threading.Thread(target=work, daemon=True).start()

    def _apply_adapters(self, items: list) -> None:
        self.adapters = items
        if not items:
            self.put_log("[警告] 没有已连接网卡，请连上 Wi-Fi/网线后点『刷新网卡』。")
            return
        names = [f"{i+1}. {a}" for i, a in enumerate(items)]
        self.iface_box.configure(values=names)
        default = 0
        for i, a in enumerate(items):
            if a.gateway:
                default = i
                break
        self.iface_box.current(default)
        self.put_log(f"[网卡] 发现 {len(items)} 块可用网卡，已选：{items[default].name}  "
                     f"(网关 {items[default].gateway or '无'})")

    def selected_adapter(self) -> Adapter:
        idx = self.iface_box.current()
        if idx < 0 or idx >= len(self.adapters):
            raise NetError("请先选择网卡。")
        return self.adapters[idx]

    def scan(self, passive: bool = True, auto: bool = False) -> None:
        # 上一次扫描若卡死（>20s），自动重置，保证点击永远有反馈
        if self.scan_thread and self.scan_thread.is_alive():
            if auto:
                return
            waited = time.time() - getattr(self, "_scan_start", 0)
            if waited < 20:
                self.put_log(f"[扫描] 上一次扫描仍在进行（已 {waited:.0f} 秒），请稍等…")
                return
            self.put_log("[扫描] 检测到上次扫描卡住，已强制重置，重新开始。")
            self.scan_thread = None
        self._scan_start = time.time()
        try:
            ad = self.selected_adapter()
        except NetError as e:
            if not auto:
                messagebox.showerror("NetKill", str(e))
            return
        if not passive and not can_send_packets():
            if not auto:
                messagebox.showerror("NetKill", "主动扫描需要发包权限（管理员或允许用户模式的 Npcap）。\n"
                                               "用『扫描网段设备』即可，它只读、不需要任何权限。")
            return
        if not auto:
            self._set_scanning_ui(True, passive=passive)
            mode = "只读邻居表（不发包）" if passive else "主动 ARP 扫描"
            self.put_log(f"[扫描] {mode}，网卡 {ad.name} …")
        # 看门狗：15 秒内没结果就强制恢复按钮，避免看起来“卡死”
        self._scan_seq = getattr(self, "_scan_seq", 0) + 1
        seq = self._scan_seq

        def work():
            try:
                k = ArpKiller(adapter=ad)
                k.on_log = self.put_log
                devs = k.scan_passive() if passive else k.scan()
                self.ui_q.put(("scan_done", (ad, devs, passive, seq, auto)))
            except Exception as e:
                self.put_log(f"[错误] 扫描失败：{e}")
                self.ui_q.put(("scan_done", (ad, [], passive, seq, auto)))

        self.scan_thread = threading.Thread(target=work, daemon=True)
        self.scan_thread.start()
        if not auto:
            self.after(15000, lambda: self._scan_watchdog(seq))

    # ------------------------------------------------------------------ 实时扫描
    def _toggle_auto_scan(self) -> None:
        if self.auto_scan_var.get():
            self._auto_scan_id = None
            self.put_log("[实时] 已开启：每 5 秒自动刷新一次设备列表（只读扫描）。")
            self._auto_scan_tick()
        else:
            if getattr(self, "_auto_scan_id", None):
                try:
                    self.after_cancel(self._auto_scan_id)
                except Exception:
                    pass
                self._auto_scan_id = None
            self.put_log("[实时] 已关闭自动刷新。")

    def _auto_scan_tick(self) -> None:
        if not self.auto_scan_var.get():
            return
        if not (self.scan_thread and self.scan_thread.is_alive()):
            self.scan(passive=True, auto=True)
        self._auto_scan_id = self.after(5000, self._auto_scan_tick)

    def _set_scanning_ui(self, scanning: bool, passive: bool = True) -> None:
        """谁触发的扫描，就把谁变成『取消扫描』，另一个禁用。"""
        if scanning:
            if passive:
                self.scan_btn.configure(text="■ 取消扫描",
                                        command=self._cancel_scan, state="normal")
                self.passive_btn.configure(state="disabled")
            else:
                self.passive_btn.configure(text="■ 取消扫描",
                                           command=self._cancel_scan, state="normal")
                self.scan_btn.configure(state="disabled")
        else:
            self.scan_btn.configure(text="扫描网段设备",
                                    command=lambda: self.scan(passive=True),
                                    state="normal")
            self.passive_btn.configure(text="主动扫描（会发包）",
                                       command=lambda: self.scan(passive=False),
                                       state="normal")

    def _scan_finished_ui(self) -> None:
        """扫描结束/取消后统一恢复扫描栏状态。"""
        self._set_scanning_ui(False)

    def _cancel_scan(self) -> None:
        """取消扫描：丢弃本次结果，立即恢复可用状态。"""
        self._scan_seq = getattr(self, "_scan_seq", 0) + 1
        self.scan_thread = None
        self._scan_finished_ui()
        self.put_log("[扫描] 已取消。")

    def _scan_watchdog(self, seq: int) -> None:
        if seq != getattr(self, "_scan_seq", 0):
            return
        if self.scan_thread and self.scan_thread.is_alive():
            self.put_log("[超时] 扫描 15 秒未返回，已强制恢复按钮。可改用『只读扫描』。")
            self._scan_finished_ui()

    def _fill_devices(self, payload) -> None:
        if len(payload) == 5:
            ad, devs, passive, seq, auto = payload
        else:
            ad, devs, passive, seq = payload
            auto = False
        if seq and seq != getattr(self, "_scan_seq", 0):
            return
        if not auto:
            self._scan_finished_ui()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._last_devices = list(devs)
        self._last_adapter = ad

        gw_mac = ""
        for d in devs:
            if d.ip == ad.gateway:
                gw_mac = (d.mac or "").lower()
        proxy_arp = 0
        for d in devs:
            if d.ip != ad.gateway and gw_mac and d.mac.lower() == gw_mac:
                proxy_arp += 1

        # 顶层分组：组播探测发现的设备置顶，另一组放同网关设备（与它平级）
        self._group_iid = None
        self._other_group_iid = None
        self._other_group_iid = "__other_group__"
        self.tree.insert(
            "", 0, iid=self._other_group_iid, text="▾", open=True,
            values=("", "", "组播探测发现的设备（真实 MAC）", "共 0 台"),
            tags=("group",),
        )
        if gw_mac:
            self._group_iid = "__proxy_group__"
            self.tree.insert(
                "", 1, iid=self._group_iid, text="▾", open=True,
                values=("", gw_mac,
                        f"同一网关下的设备（网关 {ad.gateway}）",
                        "共 0 台"),
                tags=("group",),
            )

        for d in sorted(devs, key=lambda x: ipaddress.IPv4Address(x.ip)):
            if d.ip == ad.ip:
                tag, state = "self", "本机（禁止）"
            elif d.ip == ad.gateway:
                tag, state = "gw", "网关（禁止）"
            elif gw_mac and d.mac.lower() == gw_mac:
                tag, state = "proxy", "代理ARP(未展开)"
            else:
                tag, state = "real", "真实MAC"
            # 代理组只放「MAC = 我们的代理 MAC」的设备；真实 MAC 设备放平级组
            if tag == "real":
                parent = getattr(self, "_other_group_iid", None) or ""
            else:
                parent = self._group_iid or ""
            name = d.hostname or d.vendor or "-"
            self.tree.insert(parent, "end", iid=d.ip,
                             values=(d.ip, d.mac, name, state), tags=(tag,))
        self._refresh_group_count()
        if auto:
            n = len([d for d in devs if d.ip not in (ad.ip, ad.gateway)])
            if n != getattr(self, "_auto_last_count", -1):
                self._auto_last_count = n
                self.put_log(f"[实时] 在线设备 {n} 台（每 5 秒自动刷新）")
            return
        if proxy_arp:
            self.put_log(f"[提示] {proxy_arp} 台设备使用代理 MAC，正在展开真实 MAC …")
            self._expand_real_macs_async(ad)
        if not devs:
            if passive:
                self.put_log("[扫描] 邻居表为空：先让室友设备产生一点流量（开网页/刷视频），再点扫描。")
            else:
                self.put_log("[扫描] 主动扫描 0 台：该网络对 ARP 请求无响应（客户端隔离/代理ARP）。")
                self.put_log("[建议] 改用『扫描网段设备』——它不发包、不需要回应，能直接列出邻居设备。")
        else:
            self.put_log(f"[扫描] 完成，共 {len(devs)} 台设备（已排除本机/网关为可攻击项）。")
            self._resolve_names_async(ad, devs)

    def _expand_real_macs_async(self, ad) -> None:
        """后台组播探测：把代理 MAC 设备的真实 MAC / 厂商回填到列表。"""

        def work():
            try:
                from core.arpnet import probe_multicast
                multi = probe_multicast(ad, timeout=3.0)
                if multi:
                    self.ui_q.put(("expand", multi))
                else:
                    self.put_log("[展开] 组播无响应，无法获取真实 MAC（该网络可能连广播也隔离）。")
            except Exception as e:
                self.put_log(f"[展开] 组播探测失败：{e}")

        threading.Thread(target=work, daemon=True).start()

    def _apply_expand(self, multi) -> None:
        """把真实 MAC / 厂商回填到列表，并补充组播新发现的设备。"""
        try:
            ad = self.selected_adapter()
        except NetError:
            ad = getattr(self, "_last_adapter", None)
        gw_mac = ""
        dev_map = {d.ip: d for d in getattr(self, "_last_devices", [])}
        for d in dev_map.values():
            if ad and d.ip == ad.gateway:
                gw_mac = (d.mac or "").lower()
        updated = added = 0
        for m in multi:
            ip = m.get("ip")
            mac = (m.get("mac") or "").lower()
            if not ip or not mac:
                continue
            if ad and ip in (ad.ip, ad.gateway):
                continue
            name = m.get("hint") or m.get("vendor") or m.get("info") or ""
            if self.tree.exists(ip):
                vals = list(self.tree.item(ip, "values"))
                old_mac = (vals[1] or "").lower()
                if old_mac == gw_mac or not old_mac or old_mac == "-":
                    vals[1] = mac
                    if name:
                        vals[2] = name
                    vals[3] = "真实MAC"
                    self.tree.item(ip, values=vals, tags=("real",))
                    # 拿到真实 MAC 后就不属于「你的代理组」，移到平级的其他设备组
                    og = getattr(self, "_other_group_iid", None)
                    if og and self.tree.exists(og) and self.tree.parent(ip) != og:
                        self.tree.move(ip, og, "end")
                    updated += 1
                d = dev_map.get(ip)
                if d is not None:
                    d.mac = mac
                    if name:
                        d.hostname = name
                    d.vendor = m.get("vendor", "")
            else:
                from core.arpnet import Device
                d = Device(ip=ip, mac=mac, hostname=name,
                           vendor=m.get("vendor", ""), state=m.get("proto", ""))
                self._last_devices.append(d)
                # 组播新发现的设备不属于「你的代理组」，放到平级的独立组
                parent = getattr(self, "_other_group_iid", None) or ""
                self.tree.insert(parent, "end", iid=ip,
                                 values=(ip, mac, name or "-", "真实MAC"),
                                 tags=("real",))
                added += 1
        if updated or added:
            self._refresh_group_count()
            self.put_log(f"[展开] 完成：更新 {updated} 台真实 MAC，新增 {added} 台"
                         f"（现在可用单播模式精准断网）。")

    def _refresh_group_count(self) -> None:
        """更新代理组 / 组播发现组的设备计数。"""
        try:
            for gid in (getattr(self, "_group_iid", None),
                        getattr(self, "_other_group_iid", None)):
                if not gid or not self.tree.exists(gid):
                    continue
                total = len(self.tree.get_children(gid))
                vals = list(self.tree.item(gid, "values"))
                vals[3] = f"共 {total} 台"
                self.tree.item(gid, values=vals)
        except Exception:
            pass

    def _resolve_names_async(self, ad, devs) -> None:
        """后台解析主机名，不阻塞界面（查不到就保留厂商/短横线）。"""
        pend = [d for d in devs if not d.hostname
                and d.ip not in (ad.ip, ad.gateway)]
        if not pend:
            return

        def work():
            try:
                from core.arpnet import resolve_hostnames
                resolve_hostnames(pend, workers=8, timeout=0.8)
                ups = [(d.ip, d.hostname) for d in pend if d.hostname]
                if ups:
                    self.ui_q.put(("hosts", ups))
            except Exception:
                pass

        threading.Thread(target=work, daemon=True).start()

    def _apply_hosts(self, ups) -> None:
        for ip, name in ups:
            if not self.tree.exists(ip):
                continue
            vals = list(self.tree.item(ip, "values"))
            if len(vals) >= 3 and name:
                vals[2] = name
                self.tree.item(ip, values=vals)
        if ups:
            self.put_log(f"[信息] 已解析 {len(ups)} 台设备的主机名。")

    # ------------------------------------------------------------------ 右键详情
    def _on_right_click(self, evt) -> None:
        iid = self.tree.identify_row(evt.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        menu = tk.Menu(self, tearoff=0,
                       bg=PANEL, fg=FG, activebackground="#2f6feb",
                       activeforeground="white", bd=0)
        menu.add_command(label="  查看详细信息", command=self._show_details)
        menu.add_separator()
        menu.add_command(label="  复制 IP", command=lambda: self._copy(iid, 0))
        menu.add_command(label="  复制 MAC 地址", command=lambda: self._copy(iid, 1))
        try:
            menu.tk_popup(evt.x_root, evt.y_root)
        finally:
            menu.grab_release()

    def _copy(self, iid: str, idx: int) -> None:
        vals = self.tree.item(iid, "values")
        if len(vals) > idx:
            self.clipboard_clear()
            self.clipboard_append(str(vals[idx]))
            self.put_log(f"[复制] {vals[idx]}")

    def _show_details(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        if ip in (getattr(self, "_group_iid", None),
                  getattr(self, "_other_group_iid", None)):
            # 分组节点：不弹窗，双击由 _on_double_click 负责折叠/展开
            return
        vals = list(self.tree.item(ip, "values"))
        dev = next((d for d in getattr(self, "_last_devices", []) if d.ip == ip), None)
        ad = getattr(self, "_last_adapter", None)
        win = tk.Toplevel(self)
        win.title(f"设备详情 · {ip}")
        win.configure(bg=BG)
        # 按 DPI 缩放并居中对齐主窗口
        w = int(680 * self._scale)
        h = int(540 * self._scale)
        try:
            px, py = self.winfo_rootx(), self.winfo_rooty()
            pw, ph = self.winfo_width(), self.winfo_height()
            x, y = px + max(0, (pw - w) // 2), py + max(0, (ph - h) // 2)
        except Exception:
            x = y = 100
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.minsize(int(560 * self._scale), int(460 * self._scale))
        win.transient(self)
        try:
            win.grab_set()
        except tk.TclError:
            pass
        pad = ttk.Frame(win, padding=int(22 * self._scale))
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="设备详细信息", foreground=CYAN, background=BG,
                  font=("Microsoft YaHei UI", 15, "bold")).pack(anchor="w", pady=(0, 14))
        info = [
            ("IP 地址", vals[0] if len(vals) > 0 else ip),
            ("MAC 地址", vals[1] if len(vals) > 1 else "-"),
            ("厂商", (dev.vendor if dev and dev.vendor else "未知（不在本地厂商库）")),
            ("主机名", (dev.hostname if dev and dev.hostname else "未解析（网络不提供名称）")),
            ("邻居状态", (dev.state if dev and dev.state else "未知")),
            ("识别结果", vals[3] if len(vals) > 3 else "-"),
        ]
        if dev and dev.is_proxy_arp:
            info.append(("网络类型", "代理ARP / 客户端隔离（MAC 被网关代替）"))
        if ad and ip == ad.gateway:
            info.append(("备注", "这是网关，不能作为断网目标"))
        if ad and ip == ad.ip:
            info.append(("备注", "这是本机"))
        for k, v in info:
            row = ttk.Frame(pad)
            row.pack(fill="x", pady=int(5 * self._scale))
            ttk.Label(row, text=k, width=10, style="Muted.TLabel",
                      font=("Microsoft YaHei UI", 11)).pack(side="left", anchor="n")
            ttk.Label(row, text=str(v), wraplength=int(420 * self._scale),
                      font=("Microsoft YaHei UI", 12)).pack(side="left", anchor="n")
        hint = "建议：先选为目标 → 保持广播模式 → 1 分钟测试；" \
               "代理ARP网络下只能用广播模式。"
        ttk.Label(pad, text=hint, style="Muted.TLabel",
                  font=("Microsoft YaHei UI", 10),
                  wraplength=int(520 * self._scale)).pack(anchor="w", pady=(18, 0))
        btns = ttk.Frame(pad)
        btns.pack(fill="x", pady=(20, 0))
        ttk.Button(btns, text="复制全部信息",
                   command=lambda: self._copy_all(win, info)).pack(side="left")
        ttk.Button(btns, text="关闭", command=win.destroy).pack(side="right")

    def _copy_all(self, win, info) -> None:
        text = "\n".join(f"{k}: {v}" for k, v in info)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.put_log("[复制] 已复制设备详细信息")

    def _on_double_click(self, evt=None) -> None:
        """双击设备行 = 查看详情；分组行交给 Tk 原生处理（不干预折叠/展开）。"""
        if evt is not None:
            iid = self.tree.identify_row(evt.y)
        else:
            sel = self.tree.selection()
            iid = sel[0] if sel else ""
        if not iid:
            return
        if iid in (getattr(self, "_group_iid", None),
                   getattr(self, "_other_group_iid", None)):
            # 分组行不拦截，避免和 Tk 原生展开/折叠打架导致顿挫
            return
        self.tree.selection_set(iid)
        self._show_details()

    def _on_pick(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        if ip in (getattr(self, "_group_iid", None),
                  getattr(self, "_other_group_iid", None)):
            # 选中的是分组节点，不设为目标
            return
        try:
            ad = self.selected_adapter()
        except NetError:
            return
        if ip in (ad.ip, ad.gateway):
            if self.target_var.get():
                self.put_log(f"[保护] {ip} 是本机/网关，已拦截，不能作为目标。")
            self.target_var.set("")
            return
        # 目标没变就不重复写日志，避免日志暴涨导致界面卡顿
        if self.target_var.get() != ip:
            self.target_var.set(ip)
            self.put_log(f"[选择] 目标 = {ip}")

    # ------------------------------------------------------------------ 探测
    def probe_target(self) -> None:
        """有目标：只探测该设备；没有目标：做全网组播发现。"""
        ip = self.target_var.get().strip()
        if not ip:
            sel = self.tree.selection()
            if sel:
                ip = sel[0]
        try:
            ad = self.selected_adapter()
        except NetError as e:
            messagebox.showerror("NetKill", str(e))
            return
        if ip in (ad.ip, ad.gateway):
            messagebox.showinfo("NetKill", "这是本机 / 网关，不需要探测。")
            return
        self._probe_seq = getattr(self, "_probe_seq", 0) + 1
        seq = self._probe_seq
        self.probe_btn.configure(text="■ 停止探测", command=self._stop_probe)
        if ip:
            self.put_log(f"[探测] 正在探测 {ip}（ARP / ping / 端口，约 3 秒）…")
        else:
            self.put_log("[探测] 未指定目标，正在组播发现全网设备（约 3 秒）…")

        def work():
            try:
                from core.arpnet import probe_device, probe_multicast
                if ip:
                    # 指定了目标：只探测它，不做全网组播发现
                    single = probe_device(ad, ip)
                    multi = []
                else:
                    single = None
                    multi = probe_multicast(ad, timeout=3.0)
            except Exception as e:
                single, multi = ({"error": str(e)} if ip else None), []
            self.ui_q.put(("probe", {"ip": ip, "single": single,
                                     "multi": multi, "seq": seq}))

        threading.Thread(target=work, daemon=True).start()

    def _stop_probe(self) -> None:
        """停止探测：丢弃本次结果并恢复按钮。"""
        self._probe_seq = getattr(self, "_probe_seq", 0) + 1
        self.probe_btn.configure(text="🔍 探测网络", command=self.probe_target)
        self.put_log("[探测] 已停止。")

    def _adopt_multicast(self, multi, win) -> None:
        """把组播发现的设备（带真实 MAC）加入列表，可直接单播断网。"""
        from core.arpnet import Device
        try:
            ad = self.selected_adapter()
        except NetError:
            ad = getattr(self, "_last_adapter", None)
        exist = {d.ip for d in getattr(self, "_last_devices", [])}
        added = 0
        for m in multi:
            ip = m.get("ip")
            if not ip or ip in exist or (ad and ip == ad.ip):
                continue
            if ad and ip == ad.gateway:
                continue
            vend = m.get("vendor", "")
            hint = m.get("hint", "") or ""
            raw_info = m.get("info", "") or ""
            # 显示优先级：设备类型 → 厂商 → 原始标识
            label = hint or raw_info
            d = Device(ip=ip, mac=m.get("mac", ""), hostname=label,
                       vendor=vend, state=m.get("proto", ""))
            self._last_devices.append(d)
            name = label or vend or m.get("proto", "") or "-"
            parent = getattr(self, "_group_iid", None) or ""
            self.tree.insert(parent, "end", iid=ip,
                             values=(ip, d.mac or "-", name, "真实MAC"),
                             tags=("proxy",))
            added += 1
        self._refresh_group_count()
        self.put_log(f"[探测] 已把 {added} 台组播发现的设备加入列表"
                     f"（真实 MAC + 厂商已知，可用单播模式精准断网）。")
        win.destroy()

    def _show_probe_result(self, payload) -> None:
        seq = payload.get("seq", 0)
        if seq and seq != getattr(self, "_probe_seq", 0):
            return                      # 已被取消，丢弃结果
        self.probe_btn.configure(text="🔍 探测网络", command=self.probe_target)
        ip = payload.get("ip", "")
        single = payload.get("single")
        multi = payload.get("multi") or []
        running = bool(self.killer and self.killer.running)
        self.put_log(f"[探测] 完成：单播{'有响应' if single and single.get('responded') else '无响应'}，"
                     f"组播发现 {len(multi)} 台")

        win = tk.Toplevel(self)
        win.title(f"网络探测 · {ip or '全网'}")
        win.configure(bg=BG)
        w, h = int(860 * self._scale), int(700 * self._scale)
        try:
            px, py = self.winfo_rootx(), self.winfo_rooty()
            pw, ph = self.winfo_width(), self.winfo_height()
            x, y = px + max(0, (pw - w) // 2), py + max(0, (ph - h) // 2)
        except Exception:
            x = y = 100
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.transient(self)
        pad = ttk.Frame(win, padding=int(22 * self._scale))
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="网络探测结果", foreground=CYAN, background=BG,
                  font=("Microsoft YaHei UI", 15, "bold")).pack(anchor="w", pady=(0, 10))

        # ---- 单播结果 ----
        if single is not None:
            arp_txt = (f"有回应（{single['arp_mac']}）" if single.get("arp_mac")
                       else "无回应")
            icmp_txt = "通" if single.get("icmp_ok") else "不通"
            tcp_map = single.get("tcp") or {}
            tcp_txt = ("、".join(f"{p}:{'开放' if s == 'open' else '关闭'}"
                                for p, s in sorted(tcp_map.items()))
                       if tcp_map else "全部无回应")
            rows = [("目标 IP", ip or "-"),
                    ("ARP 探测", arp_txt),
                    ("Ping", icmp_txt),
                    ("端口探测", tcp_txt),
                    ("工具状态", "正在对该设备断网" if running else "未对该设备启动断网")]
            for k, v in rows:
                row = ttk.Frame(pad)
                row.pack(fill="x", pady=int(3 * self._scale))
                ttk.Label(row, text=k, width=9, style="Muted.TLabel",
                          font=("Microsoft YaHei UI", 10)).pack(side="left")
                ttk.Label(row, text=str(v), font=("Microsoft YaHei UI", 10),
                          wraplength=int(600 * self._scale)).pack(side="left")
            # 结论只看探测回应，和「工具状态」无关
            if single.get("error"):
                conclusion = f"探测过程出错：{single['error']}"
                color = RED
            elif single.get("responded"):
                conclusion = ("目标有回应（ARP/Ping/端口至少一项），设备在线；"
                              "但能不能上网要看它自己的业务是否正常。")
                color = GREEN
            else:
                conclusion = ("目标完全没有回应：可能设备离线、被网络隔离，"
                              "或者已经断网成功（探针本身也被隔离挡住）。")
                color = YELLOW
            ttk.Label(pad, text="探测结论", style="Muted.TLabel",
                      font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
            ttk.Label(pad, text=conclusion, foreground=color, background=BG,
                      font=("Microsoft YaHei UI", 10),
                      wraplength=int(700 * self._scale)).pack(anchor="w")
        else:
            ttk.Label(pad, text="（未指定目标，仅做组播发现）",
                      style="Muted.TLabel").pack(anchor="w")

        # ---- 组播发现（仅在未指定目标时显示） ----
        if not payload.get("ip"):
            ttk.Label(pad, text=f"组播/广播发现：{len(multi)} 台（已穿透客户端隔离）",
                      foreground=GREEN, background=BG,
                      font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", pady=(14, 4))
            cols = ("ip", "mac", "vendor", "proto", "info")
            tv = ttk.Treeview(pad, columns=cols, show="headings",
                              height=min(10, max(3, len(multi))), selectmode="browse")
            for c, t, wd in (("ip", "IP 地址", 140), ("mac", "MAC 地址", 170),
                             ("vendor", "厂商", 110), ("proto", "协议", 140),
                             ("info", "设备信息", 260)):
                tv.heading(c, text=t)
                tv.column(c, width=int(wd * self._scale), anchor="w")
            for m in multi:
                tv.insert("", "end", values=(m.get("ip", ""), m.get("mac", "") or "-",
                                             m.get("vendor", "") or "未知",
                                             m.get("proto", ""), m.get("info", "")))
            tv.pack(fill="both", expand=True, pady=(0, 8))

            verdict = ("组播帧能穿过去 → 说明该网络只隔离单播；"
                       "这些设备的真实 MAC 可用于精准单播断网。"
                       if multi else
                       "组播也没有响应 → 该 AP 同时拦截广播/组播，无法从本端发现设备。")
            ttk.Label(pad, text=verdict, foreground=YELLOW, background=BG,
                      font=("Microsoft YaHei UI", 10),
                      wraplength=int(760 * self._scale)).pack(anchor="w")

        btns = ttk.Frame(pad)
        btns.pack(fill="x", pady=(14, 0))
        if multi:
            ttk.Button(btns, text="把这些设备加入列表",
                       command=lambda: self._adopt_multicast(multi, win)).pack(side="left")
        ttk.Button(btns, text="再探测一次",
                   command=lambda: (win.destroy(), self.probe_target())).pack(side="left", padx=8)
        ttk.Button(btns, text="关闭", command=win.destroy).pack(side="right")

    # ------------------------------------------------------------------ 攻击
    def _duration_seconds(self) -> int:
        text = self.dur_var.get()
        table = {"不自动停": 0, "5 分钟": 300, "15 分钟": 900,
                 "30 分钟": 1800, "1 小时": 3600, "2 小时": 7200}
        if text in table:
            return table[text]
        try:
            mins = int(self.custom_var.get())
            return max(1, mins) * 60
        except ValueError:
            raise NetError("自定义时长请输入正整数（分钟）。")

    def _sync_start_label(self) -> None:
        """勾选限速模式时，主按钮从「一键断网」变成「开始限速」。"""
        if not hasattr(self, "start_btn"):
            return
        self.start_btn.configure(
            text="⚡ 开始限速" if self.forward_var.get() else "⚡ 一键断网"
        )

    def _on_duration_change(self, _evt=None) -> None:
        """只有选『自定义』时才显示分钟输入框，其它选项直接隐藏。"""
        if not hasattr(self, "custom_entry"):
            return
        if self.dur_var.get() == "自定义":
            self.custom_entry.pack(side="left", padx=(6, 2))
            self.custom_min_label.pack(side="left")
            self.custom_entry.configure(state="normal")
        else:
            self.custom_entry.pack_forget()
            self.custom_min_label.pack_forget()

    def start_attack(self) -> None:
        if not can_send_packets():
            messagebox.showerror(
                "NetKill",
                "当前权限无法发包。\n请关闭本窗口，右键 start_gui.bat → 以管理员身份运行。",
            )
            return
        if self.killer and self.killer.running:
            return
        try:
            ad = self.selected_adapter()
            ip = self.target_var.get().strip()
            if not ip:
                raise NetError("请先在列表里点选室友的设备，或手动填目标 IP。")
            seconds = self._duration_seconds()
            # 代码层自我保护（即使 UI 被绕过也不允许）
            if ip == ad.ip:
                raise NetError("拒绝：目标是本机。")
            if ip == ad.gateway:
                raise NetError("拒绝：目标是网关。")
            # 优先使用扫描列表里已显示的 MAC，避免二次解析失败（代理ARP网络必现）
            mac = ""
            if self.tree.exists(ip):
                vals = self.tree.item(ip, "values")
                if len(vals) >= 2:
                    mac = str(vals[1]).strip()
                    if mac in ("-", "None", ""):
                        mac = ""
            killer = ArpKiller(adapter=ad, forward=self.forward_var.get(),
                               broadcast=self.broadcast_var.get())
            killer.on_log = self.put_log
            killer.add(ip, mac or None)
            killer.start(background=True)
        except NetError as e:
            messagebox.showerror("NetKill", str(e))
            return

        self.killer = killer
        self.deadline = time.time() + seconds if seconds else None
        self.ui_q.put(("started", None))
        action = "限速中" if self.forward_var.get() else "断网中"
        self.put_log(f"[开战] 目标 {ip} {action}（{'限速模式' if self.forward_var.get() else '强制断网'}"
                     f"{'，广播穿透' if self.broadcast_var.get() else ''}）。")

    def stop_attack(self) -> None:
        k, self.killer = self.killer, None
        self.deadline = None
        if not k:
            return

        def work():
            try:
                k.stop()
                self.put_log("[停战] 已回毒，ARP 表恢复，网络正常。")
            finally:
                self.ui_q.put(("stopped", None))

        threading.Thread(target=work, daemon=True).start()

    def _on_close(self) -> None:
        if self.killer and self.killer.running:
            if not messagebox.askyesno("NetKill", "正在断网中，关闭将自动恢复对方网络。确定退出？"):
                return
            try:
                self.killer.stop()
            except Exception:
                pass
        self.destroy()


def main() -> int:
    app = App()
    if not can_send_packets():
        app.put_log("[警告] 当前权限无法发包（Npcap 限制为仅管理员）。")
        app.put_log("[提示] 关闭后右键 start_gui.bat → 以管理员身份运行。")
    elif is_admin():
        app.put_log("[权限] 管理员模式：可直接发包断网。")
    else:
        app.put_log("[权限] 普通用户模式：Npcap 允许发包，可直接断网（无需管理员）。")
    app.put_log("[就绪] 选择网卡 → 扫描 → 点选室友设备 → 一键断网（广播模式默认开启）。")
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
