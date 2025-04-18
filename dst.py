from bcc import BPF
from pyroute2 import IPRoute
import time
import ctypes
from pyroute2 import NetlinkError


ipr = IPRoute()

IFNAME = "lxc4a3f00e6b514"

# 載入 BPF C 程式
b = BPF(src_file="dst.c")

# 載入 ingress / egress function（修正拼字錯誤）
fn_egress = b.load_func("trace_gtpu_dst_ip", BPF.SCHED_CLS)

idx_list = ipr.link_lookup(ifname=IFNAME)
if not idx_list:
    raise Exception(f"Interface {IFNAME} not found.")
idx = idx_list[0]

try:
    ipr.tc("add", "clsact", idx)
except NetlinkError as e:
    if e.code == 17:  # File exists
        print("clsact already exists, skipping...")
    else:
        raise

# ipr.tc("add-filter", "bpf", idx, ":1", fd=fn_ingress.fd,
#        name=fn_ingress.name, parent="ffff:fff2", action="ok", classid=1)

# ipr.tc("add", "clsact", idx, "1:")

# 在宿主機要反者掛，像要抓container 的 egress就要掛ingress，ffff:fff2(Ingress) ffff:fff3(Egress)
ipr.tc("add-filter", "bpf", idx, ":2", fd=fn_egress.fd,
       name=fn_egress.name, parent="ffff:fff2", action="ok", classid=1)

# ipr.tc("add-filter", "bpf", idx, ":2", fd=fn_mirror.fd,
#        name=fn_mirror.name, parent="ffff:fff2", action="ok", classid=1)

print(f"BPF program loaded on {IFNAME}. Press Ctrl+C to exit...")  

try:
    while True:
        # b.perf_buffer_poll()
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
