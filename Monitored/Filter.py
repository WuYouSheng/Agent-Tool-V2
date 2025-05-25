import pyshark
import logging
from typing import Callable, Optional
import threading
import json
import time
import datetime

# Static Variable
CONFIG_PATH = "../config.json"

# Global Variable
config = None
interface = None
port = None
service_type = None
time_gap = None


class PacketFilter:
    def __init__(self, config_path: str = CONFIG_PATH):
        self.config_path = config_path
        self.config = None
        self.interface = None
        self.port = None
        self.service_type = None
        self.time_gap = None
        self.capture_flow = None
        self.is_running = False
        self.packet_callback = None

    def load_config(self):
        """載入配置檔案"""
        try:
            with open(self.config_path) as f:
                self.config = json.load(f)
            print(f"Config loaded: {self.config}")
            return True
        except FileNotFoundError:
            print(f"Config file not found at {self.config_path}")
            return False
        except json.JSONDecodeError:
            print("Invalid JSON format in config file")
            return False

    def apply_config(self):
        """應用配置設定"""
        if self.config is None:
            raise ValueError("Config not loaded. Call load_config() first.")

        self.interface = str(self.config["interface"])
        self.port = str(self.config["port"])
        self.service_type = str(self.config["service_type"])
        self.time_gap = int(self.config.get("time_gap", 0))

        print(f"Applied config - Interface: {self.interface}, Port: {self.port}")
        return True

    def set_packet_callback(self, callback: Callable):
        """設定封包處理回調函數"""
        self.packet_callback = callback

    def start_capture(self, callback: Optional[Callable] = None):
        """開始封包捕獲"""
        if callback:
            self.set_packet_callback(callback)

        if not self.packet_callback:
            raise ValueError("No packet callback function set")

        try:
            bpf_filter = f"tcp src port {self.port}"
            print(f"Using bpf filter: {bpf_filter}")

            current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            self.capture_flow = pyshark.LiveCapture(
                interface=self.interface, # 設定監控網卡interface (macOS en0, windows eth0)
                bpf_filter=bpf_filter,  # BPF 語法
                output_file = f"./PCAP/captured_packets_{current_time}.pcap"
            )
            self.capture_flow.set_debug() # 顯示 Debug 資訊

            print(f"開始在介面 {self.interface} 上捕獲封包...")
            print(f"監聽從Port {self.port} 發出封包")
            print("按 Ctrl+C 停止捕獲\n")

            self.is_running = True

            for package in self.capture_flow.sniff_continuously():
                if not self.is_running:
                    break

                print(f"\n>>> 捕獲到封包! <<<")
                self._log_packet_info(package)


                # 呼叫回調函數處理封包
                if self.packet_callback:
                    try:
                        # 在背景執行回調函數，避免阻塞捕獲
                        callback_thread = threading.Thread(
                            target=self.packet_callback, # Thread 背景執行內容
                            args=(package,), # 將package 作為參數傳入
                            daemon=True # 表示為背景執行緒
                        )
                        callback_thread.start()
                    except Exception as e:
                        print(f"執行封包回調函數時發生錯誤: {e}")

                # 延遲處理（如果設定）
                if self.time_gap > 0:
                    import time
                    time.sleep(self.time_gap)

        except KeyboardInterrupt:
            print("\n封包捕獲被使用者中斷")
            self.stop_capture()
        except Exception as e:
            print(f"封包捕獲過程中發生錯誤: {e}")
            raise

    def stop_capture(self):
        """停止封包捕獲"""
        self.is_running = False
        if self.capture_flow:
            try:
                self.capture_flow.close()
            except:
                pass
        print("封包捕獲已停止")

    def _log_packet_info(self, package):
        """記錄封包基本資訊"""
        try:
            if hasattr(package, 'http'):
                print(f"HTTP封包攔截")
                if hasattr(package.http, 'request_method'):
                    print(f"  HTTP Method: {package.http.request_method}")
                if hasattr(package.http, 'host'):
                    print(f"  HTTP Host: {package.http.host}")
                if hasattr(package.http, 'request_uri'):
                    print(f"  HTTP URI: {package.http.request_uri}")

            if hasattr(package, 'tcp'):
                src_port = package.tcp.srcport
                dst_port = package.tcp.dstport
                print(f"  TCP: {package.ip.src}:{src_port} -> {package.ip.dst}:{dst_port}")

            if hasattr(package, 'ip'):
                print(f"  Protocol: {package.highest_layer}")
                print(f"  Packet Length: {package.length}")

        except Exception as e:
            print(f"記錄封包資訊時發生錯誤: {e}")

    def get_packet_summary(self, package):
        """取得封包摘要資訊"""
        summary = {
            "timestamp": str(package.sniff_time) if hasattr(package, 'sniff_time') else None,
            "protocol": package.highest_layer if hasattr(package, 'highest_layer') else "unknown",
            "length": package.length if hasattr(package, 'length') else 0
        }

        if hasattr(package, 'ip'):
            summary.update({
                "src_ip": package.ip.src,
                "dst_ip": package.ip.dst
            })

        if hasattr(package, 'tcp'):
            summary.update({
                "src_port": int(package.tcp.srcport),
                "dst_port": int(package.tcp.dstport),
                "tcp_flags": package.tcp.flags if hasattr(package.tcp, 'flags') else None
            })

        if hasattr(package, 'http'):
            summary.update({
                "http_method": package.http.request_method if hasattr(package.http, 'request_method') else None,
                "http_host": package.http.host if hasattr(package.http, 'host') else None,
                "http_uri": package.http.request_uri if hasattr(package.http, 'request_uri') else None
            })

        return summary

if __name__ == '__main__':
    # 測試用途
    def test_callback(packet):
        print(f"測試回調: 收到封包 {packet.highest_layer}")


    filter_instance = PacketFilter()
    if filter_instance.load_config():
        filter_instance.apply_config()
        filter_instance.start_capture(test_callback)