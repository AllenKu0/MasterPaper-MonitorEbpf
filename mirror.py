from bcc import BPF
from pyroute2 import IPRoute
import time
import ctypes
from pyroute2 import NetlinkError


ipr = IPRoute()

IFNAME = "lxc26e5bd86678d"
MIRROR_IFNAME = "cilium_vxlan"
MIRROR_IP = 

# 載入 BPF C 程式
b = BPF(src_file="mirror.c")

fn_mirror = b.load_func("mirror_traffic", BPF.SCHED_CLS)

idx_list = ipr.link_lookup(ifname=IFNAME)
mirror_idx_list = ipr.link_lookup(ifname=MIRROR_IFNAME)
if not idx_list:
    raise Exception(f"Interface {IFNAME} not found.")
if not mirror_idx_list:
    raise Exception(f"Mirror Interface {MIRROR_IFNAME} not found.")
idx = idx_list[0]
mirror_idx = mirror_idx_list[0]

# 掛載 tc ingress & egress 到 t1a
# ipr.tc("add", "ingress", idx, "ffff:")
try:
    ipr.tc("add", "clsact", idx)
except NetlinkError as e:
    if e.code == 17:  # File exists
        print("clsact already exists, skipping...")
    else:
        raise

print(f"BPF program loaded on {IFNAME}. Press Ctrl+C to exit...")

# 鏡像map init
class MirrorConfig(ctypes.Structure):
    _fields_ = [
        ("enable", ctypes.c_uint),
        ("mirror_index", ctypes.c_uint),
        ("mirror_dst_ip", ctypes.c_uint),
    ]

mirror_map = b.get_table("mirror_config_map")

key = ctypes.c_uint(0)  # 固定 key 為 0
value = MirrorConfig(enable=1,mirror_index=IFNAME, mirror_dst_ip=0)
mirror_map[key] = value

print(f"[Control] Mirror enabled to ifindex {mirror_idx} ({MIRROR_IFNAME})")

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
    # 清除 tc 規則
    # try:
    #     ipr.tc("del", "ingress", idx, "ffff:")
    # except:
    #     pass
    # try:
    #     ipr.tc("del", "egress", idx, "1:")
    # except:
    #     pass
    
    ipr.close()
