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


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("NetKill · 室友戒网瘾 · 一键断网")
        self.minsize(820, 600)
        self.configure(bg=BG)
        self._center_window(900, 700)
        # 启动时置顶闪一下，确保用户看得到（尤其被其它窗口压住时）
        self.after(50, self._flash_on_top)

        self.ui_q: "queue.Queue[tuple]" = queue.Queue()
        self.adapters: list[Adapter] = []
        self.killer: ArpKiller | None = None
        self.attack_thread: threading.Thread | None = None
        self.scan_thread: threading.Thread | None = None
        self.deadline: float | None = None
        self._pump_id = None

        self._build_style()
        self._build_ui()
        self._pump_id = self.after(120, self._pump)
        self.after(300, self.refresh_adapters)

    # ------------------------------------------------------------------ UI
    def _center_window(self, w: int, h: int) -> None:
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
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
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                     foreground=FG, rowheight=26, borderwidth=0,
                     font=("Consolas", 9))
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
        ttk.Button(bar, text="刷新网卡", command=self.refresh_adapters).pack(side="left")
        self.scan_btn = ttk.Button(bar, text="扫描室友设备", style="Accent.TButton",
                                   command=lambda: self.scan(passive=False))
        self.scan_btn.pack(side="right")
        self.passive_btn = ttk.Button(bar, text="只读扫描（不发包）",
                                      command=lambda: self.scan(passive=True))
        self.passive_btn.pack(side="right", padx=(0, 8))

        # 设备表
        table_wrap = ttk.Frame(root)
        table_wrap.pack(fill="both", expand=True)
        cols = ("ip", "mac", "name", "tag")
        self.tree = ttk.Treeview(table_wrap, columns=cols, show="headings", height=11,
                                 selectmode="browse")
        for c, t, w, anchor in (
            ("ip", "IP 地址", 150, "w"),
            ("mac", "MAC 地址", 190, "w"),
            ("name", "主机名 / 厂商", 300, "w"),
            ("tag", "状态", 120, "w"),
        ):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor=anchor)
        sb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_pick)
        self.tree.tag_configure("gw", foreground=YELLOW)
        self.tree.tag_configure("self", foreground=MUTED)
        self.tree.tag_configure("target", foreground=RED)

        # 目标 + 操作
        ctl = ttk.Frame(root)
        ctl.pack(fill="x", pady=(10, 6))
        ttk.Label(ctl, text="目标 IP：").pack(side="left")
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

        btns = ttk.Frame(root)
        btns.pack(fill="x", pady=(4, 4))
        self.start_btn = ttk.Button(btns, text="⚡ 一键断网", style="Danger.TButton",
                                    command=self.start_attack)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text="■ 恢复网络", style="Accent.TButton",
                                   command=self.stop_attack, state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(btns, textvariable=self.status_var, foreground=CYAN,
                  background=BG, font=("Microsoft YaHei UI", 9, "bold")).pack(side="right")

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

    def _apply_log(self, line: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        if int(self.log.index("end-1c").split(".")[0]) > 600:
            self.log.delete("1.0", "200.0")
        self.log.configure(state="disabled")

    def _pump(self) -> None:
        try:
            while True:
                kind, payload = self.ui_q.get_nowait()
                if kind == "log":
                    self._apply_log(payload)
                elif kind == "adapters":
                    self._apply_adapters(payload)
                elif kind == "scan_done":
                    self._fill_devices(payload)
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
                    self._apply_log(f"[警告] {payload}")
        except queue.Empty:
            pass
        except Exception as e:      # 单条消息出错不能拖死整个 UI 泵
            try:
                self._apply_log(f"[界面] 处理消息异常：{e}")
            except Exception:
                pass
        # 倒计时显示
        try:
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
            self._pump_id = self.after(120, self._pump)

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

    def scan(self, passive: bool = False) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            return
        try:
            ad = self.selected_adapter()
        except NetError as e:
            messagebox.showerror("NetKill", str(e))
            return
        if not passive and not can_send_packets():
            messagebox.showerror("NetKill", "主动扫描需要发包权限（管理员或允许用户模式的 Npcap）。\n"
                                           "可以先点『只读扫描』，不需要任何权限。")
            return
        self.scan_btn.configure(state="disabled")
        self.passive_btn.configure(state="disabled")
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
                self.ui_q.put(("scan_done", (ad, devs, passive, seq)))
            except Exception as e:
                self.put_log(f"[错误] 扫描失败：{e}")
                self.ui_q.put(("scan_done", (ad, [], passive, seq)))

        self.scan_thread = threading.Thread(target=work, daemon=True)
        self.scan_thread.start()
        self.after(15000, lambda: self._scan_watchdog(seq))

    def _scan_watchdog(self, seq: int) -> None:
        if seq != getattr(self, "_scan_seq", 0):
            return
        if self.scan_thread and self.scan_thread.is_alive():
            self.put_log("[超时] 扫描 15 秒未返回，已强制恢复按钮。可改用『只读扫描』。")
            self.scan_btn.configure(state="normal")
            self.passive_btn.configure(state="normal")

    def _fill_devices(self, payload) -> None:
        ad, devs, passive, seq = payload if len(payload) == 4 else (*payload, False, 0)
        if seq and seq != getattr(self, "_scan_seq", 0):
            return
        self.scan_btn.configure(state="normal")
        self.passive_btn.configure(state="normal")
        for item in self.tree.get_children():
            self.tree.delete(item)
        for d in devs:
            if d.ip == ad.ip:
                tag, state = "self", "本机（禁止）"
            elif d.ip == ad.gateway:
                tag, state = "gw", "网关（禁止）"
            else:
                tag, state = "", "可断网"
            name = d.hostname or d.vendor or "-"
            self.tree.insert("", "end", iid=d.ip,
                             values=(d.ip, d.mac, name, state), tags=(tag,))
        if not devs:
            if passive:
                self.put_log("[扫描] 邻居表为空：先让室友设备产生一点流量（开网页/刷视频），再点只读扫描。")
            else:
                self.put_log("[扫描] 主动扫描 0 台：该网络对 ARP 请求无响应（客户端隔离/代理ARP）。")
                self.put_log("[建议] 改用『只读扫描』——它不发包、不需要回应，能直接列出邻居设备。")
        else:
            self.put_log(f"[扫描] 完成，共 {len(devs)} 台设备（已排除本机/网关为可攻击项）。")

    def _on_pick(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        try:
            ad = self.selected_adapter()
        except NetError:
            return
        if ip in (ad.ip, ad.gateway):
            self.put_log(f"[保护] {ip} 是本机/网关，已拦截，不能作为目标。")
            self.target_var.set("")
            return
        self.target_var.set(ip)
        self.put_log(f"[选择] 目标 = {ip}")

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
            killer = ArpKiller(adapter=ad, forward=self.forward_var.get(),
                               broadcast=self.broadcast_var.get())
            killer.on_log = self.put_log
            killer.add(ip)
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
