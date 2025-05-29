import pyshark
import logging
from typing import Callable, Optional
import threading
import json
import time
import datetime
import os

# Static Variable
CONFIG_PATH = "../config.json"
LOG_PATH = "../log/"

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
        """記錄封包基本資訊並儲存到日誌檔案"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            # 建立結構化的封包資訊
            packet_info = {
                "timestamp": timestamp,
                "packet_type": "",
                "details": {}
            }

            # 準備顯示用的日誌條目
            log_entries = [f"[{timestamp}] 封包攔截"]

            if hasattr(package, 'http'):
                packet_info["packet_type"] = "HTTP"
                print(f"HTTP封包攔截")
                log_entries.append("HTTP封包攔截")

                if hasattr(package.http, 'request_method'):
                    method = package.http.request_method
                    packet_info["details"]["http_method"] = method
                    method_info = f"  HTTP Method: {method}"
                    print(method_info)
                    log_entries.append(method_info)

                if hasattr(package.http, 'host'):
                    host = package.http.host
                    packet_info["details"]["http_host"] = host
                    host_info = f"  HTTP Host: {host}"
                    print(host_info)
                    log_entries.append(host_info)

                if hasattr(package.http, 'request_uri'):
                    uri = package.http.request_uri
                    packet_info["details"]["http_uri"] = uri
                    uri_info = f"  HTTP URI: {uri}"
                    print(uri_info)
                    log_entries.append(uri_info)

            if hasattr(package, 'tcp'):
                src_port = package.tcp.srcport
                dst_port = package.tcp.dstport
                src_ip = package.ip.src
                dst_ip = package.ip.dst

                packet_info["details"]["tcp"] = {
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port
                }

                tcp_info = f"  TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                print(tcp_info)
                log_entries.append(tcp_info)

            if hasattr(package, 'ip'):
                protocol = package.highest_layer
                length = package.length

                packet_info["details"]["protocol"] = protocol
                packet_info["details"]["packet_length"] = length

                protocol_info = f"  Protocol: {protocol}"
                length_info = f"  Packet Length: {length}"
                print(protocol_info)
                print(length_info)
                log_entries.append(protocol_info)
                log_entries.append(length_info)

            # 儲存到不同格式的日誌檔案
            self._save_to_log(log_entries, packet_info)

        except Exception as e:
            error_msg = f"記錄封包資訊時發生錯誤: {e}"
            print(error_msg)
            error_log = [f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {error_msg}"]
            self._save_to_log(error_log, {"timestamp": datetime.datetime.now().isoformat(), "error": str(e)})

    def _save_to_log(self, log_entries, packet_data=None):
        """將日誌條目儲存到檔案（按日期建立資料夾，檔名包含完整時間戳記）"""
        try:
            now = datetime.datetime.now()

            # 建立日期資料夾：YYYY-MM-DD
            date_folder = now.strftime('%Y-%m-%d')
            daily_log_path = os.path.join(LOG_PATH, date_folder)

            # 確保目錄存在
            if not os.path.exists(daily_log_path):
                os.makedirs(daily_log_path, exist_ok=True)

            # 生成包含完整時間戳記的檔案名稱：YYYYMMDD_HHMMSS_microseconds
            timestamp_str = now.strftime('%Y%m%d_%H%M%S_%f')[:-3]  # 保留毫秒，移除後3位微秒

            # 儲存人類可讀的日誌
            readable_log_filename = f"packet_capture_{timestamp_str}.log"
            readable_log_path = os.path.join(daily_log_path, readable_log_filename)

            with open(readable_log_path, 'w', encoding='utf-8') as f:  # 使用 'w' 模式，每個封包一個檔案
                for entry in log_entries:
                    f.write(f"{entry}\n")
                f.write("-" * 50 + "\n")

            # 儲存結構化的 JSON 日誌
            if packet_data:
                json_log_filename = f"packet_data_{timestamp_str}.json"
                json_log_path = os.path.join(daily_log_path, json_log_filename)

                with open(json_log_path, 'w', encoding='utf-8') as f:  # 使用 'w' 模式，每個封包一個檔案
                    json.dump(packet_data, f, ensure_ascii=False, indent=2)

            # 更新統計資訊
            self._update_statistics(daily_log_path)

        except Exception as e:
            print(f"儲存日誌時發生錯誤: {e}")

    def _update_statistics(self, log_path):
        """更新封包捕獲統計資訊"""
        try:
            stats_file = os.path.join(log_path, "daily_stats.json")

            # 讀取現有統計或建立新的
            if os.path.exists(stats_file):
                with open(stats_file, 'r', encoding='utf-8') as f:
                    stats = json.load(f)
            else:
                stats = {
                    "date": datetime.datetime.now().strftime('%Y-%m-%d'),
                    "total_packets": 0,
                    "session_start": datetime.datetime.now().isoformat(),
                    "hourly_stats": {},
                    "protocol_stats": {}
                }

            # 更新統計
            current_hour = datetime.datetime.now().strftime('%H')
            stats["total_packets"] += 1
            stats["last_packet_time"] = datetime.datetime.now().isoformat()

            # 更新每小時統計
            if current_hour not in stats["hourly_stats"]:
                stats["hourly_stats"][current_hour] = 0
            stats["hourly_stats"][current_hour] += 1

            # 儲存統計
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)

        except Exception as e:
            print(f"更新統計資訊時發生錯誤: {e}")

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