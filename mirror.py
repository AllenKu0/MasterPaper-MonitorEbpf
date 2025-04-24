from bcc import BPF
from pyroute2 import IPRoute
import time
import ctypes
from pyroute2 import NetlinkError
import socket
import struct

mirror_ip_str = "10.244.0.165"
mirror_mac = "8e:8d:f2:4d:ae:8b"
# gnb 網卡
IFNAME = "lxcc833053045a2"
MIRROR_IFNAME = "cilium_host"
ipr = IPRoute()


# 載入 BPF C 程式
b = BPF(src_file="mirror.c")

fn_mirror = b.load_func("mirror_traffic", BPF.SCHED_CLS)
fn_drop_mirror = b.load_func("ingress_drop", BPF.SCHED_CLS)

idx_list = ipr.link_lookup(ifname=IFNAME)
mirror_list = ipr.link_lookup(ifname=MIRROR_IFNAME)

if not idx_list:
    raise Exception(f"Interface {IFNAME} not found.")
if not mirror_list:
    raise Exception(f"Interface {IFNAME} not found.")

idx = idx_list[0]
mirror_idx = mirror_list[0]

try:
    ipr.tc("add", "clsact", idx)
except NetlinkError as e:
    if e.code == 17:  # File exists
        print("clsact already exists, skipping...")
    else:
        raise
    
ipr.tc("add-filter", "bpf", idx, ":2", fd=fn_mirror.fd,
       name=fn_mirror.name, parent="ffff:fff2", action="ok", classid=1)

# ipr.tc("add-filter", "bpf", idx, ":2", fd=fn_drop_mirror.fd,
#        name=fn_drop_mirror.name, parent="ffff:fff3", action="ok", classid=1)

print(f"BPF program loaded on {IFNAME}. Press Ctrl+C to exit...")

def mac_str_to_ubyte_array(mac_str):
    return (ctypes.c_ubyte * 6)(*map(lambda x: int(x, 16), mac_str.split(':')))

def ip_str_to_ubyte_array(ip_str):
    ip_packed = socket.inet_aton(ip_str)
    # 解包並保留大端字節序的整數值
    return struct.unpack("<I", ip_packed)[0]
# 鏡像map init
class MirrorConfig(ctypes.Structure):
    _fields_ = [
        ("enable", ctypes.c_uint),
        ("mirror_index", ctypes.c_uint), # gnb的網卡
        ("mirror_dst_ip", ctypes.c_uint),
        ("mirror_dst_mac", ctypes.c_ubyte * 6),
    ]

mirror_map = b.get_table("mirror_config_map")

key = ctypes.c_uint(0)  # 固定 key 為 0
value = MirrorConfig(enable=1,mirror_index=mirror_idx, mirror_dst_ip=ip_str_to_ubyte_array(mirror_ip_str), mirror_dst_mac=mac_str_to_ubyte_array(mirror_mac))
mirror_map[key] = value

print(f"[Control] Mirror enabled to ifindex {idx} ({IFNAME})")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nUnloading...")
    
    try:
        ipr.tc("del", "clsact", idx)
        print("clsact successfully removed.")
    except Exception as e:
        print(f"Failed to delete clsact: {e}")
    
    ipr.close()
