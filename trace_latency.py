from bcc import BPF
from pyroute2 import IPRoute
import time
import ctypes
from pyroute2 import NetlinkError
import requests

ipr = IPRoute()

IFNAME = "eth0"
# MIRROR_IFNAME = "lo"

package_count = 0
THRESHOLD_PACKAGE = 50
# 設定超時次數
over_latency_times = 0
OVER_LATENCY_THRESHOLD_TIMES = 2
# 設定延遲閾值
LATENCY_THRESHOLD_NS = 5_000_000  # 5ms

# Webhook URL
WEBHOOK_URL = "http://10.1.0.25:8080/alert"  # 根據你的實際伺服器修改

# 載入 BPF C 程式
b = BPF(src_file="trace_latency.c")

# Processing Map
processing_map = b.get_table("gtpu_processing_time")

# 載入 ingress / egress function
fn_ingress = b.load_func("tc_ingress_info", BPF.SCHED_CLS)
fn_egress = b.load_func("tc_egress_info", BPF.SCHED_CLS)
# fn_mirror = b.load_func("tc_mirror_egress_info", BPF.SCHED_CLS)

idx_list = ipr.link_lookup(ifname=IFNAME)
# mirror_idx_list = ipr.link_lookup(ifname=MIRROR_IFNAME)
if not idx_list:
    raise Exception(f"Interface {IFNAME} not found.")
# if not mirror_idx_list:
#     raise Exception(f"Mirror Interface {MIRROR_IFNAME} not found.")
idx = idx_list[0]
# mirror_idx = mirror_idx_list[0]

try:
    ipr.tc("add", "clsact", idx)
    # ipr.tc("add", "clsact", mirror_idx)
except NetlinkError as e:
    if e.code == 17:  # File exists
        print("clsact already exists, skipping...")
    else:
        raise

ipr.tc("add-filter", "bpf", idx, ":1", fd=fn_ingress.fd,
       name=fn_ingress.name, parent="ffff:fff2", action="ok", classid=1)

ipr.tc("add-filter", "bpf", idx, ":2", fd=fn_egress.fd,
       name=fn_egress.name, parent="ffff:fff3", action="ok", classid=1)

print(f"BPF program loaded on {IFNAME}. Press Ctrl+C to exit...")

# # 鏡像map init
# class MirrorConfig(ctypes.Structure):
#     _fields_ = [
#         ("enable", ctypes.c_uint),
#         ("ifindex", ctypes.c_uint),
#     ]

# mirror_map = b.get_table("mirror_config_map")

# key = ctypes.c_uint(0)  # 固定 key 為 0
# value = MirrorConfig(enable=1,ifindex=mirror_idx)
# mirror_map[key] = value

# print(f"[Control] Mirror enabled to ifindex {mirror_idx} ({MIRROR_IFNAME})")


try:
    while True:
        time.sleep(1)
        for k, v in processing_map.items():
            latency = v.value
            package_count += 1
            if package_count > THRESHOLD_PACKAGE:
                package_count = 0
                over_latency_times = 0
                print(f"[Latency Monitor] Package reset.")
            print(f"[Webhook Trigger] Latency for hash {k.value} is {latency} ns")
            if latency > LATENCY_THRESHOLD_NS:
                over_latency_times += 1
                print(f"[Latency Monitor] Latency time is over the expected threshold. Times: {over_latency_times}")
                if over_latency_times > OVER_LATENCY_THRESHOLD_TIMES:
                    over_latency_times = 0
                    print(f"[Latency Monitor] Webhook Trigger !! Latency times exceed {LATENCY_THRESHOLD_NS}")
                    # 準備 payload 發送 webhook
                    payload = {
                        "alertname": "High GTP-U Latency",
                        "threshold_ns": LATENCY_THRESHOLD_NS,
                        "over_latency_times": OVER_LATENCY_THRESHOLD_TIMES
                    }
                    try:
                        resp = requests.post(WEBHOOK_URL, json=payload, timeout=2)
                        if resp.status_code == 200:
                            print("[Webhook] Sent successfully")
                        else:
                            print(f"[Webhook] Failed with status {resp.status_code}")
                    except Exception as e:
                        print(f"[Webhook] Error: {e}")

            # 可以選擇清除 map 內容以避免重複通知
            processing_map.pop(k)
        
except KeyboardInterrupt:
    print("\nUnloading...")

    try:
        ipr.tc("del", "clsact", idx)
        print("clsact successfully removed.")
    except Exception as e:
        print(f"Failed to delete clsact: {e}")
    
    ipr.close()
