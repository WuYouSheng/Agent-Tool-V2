#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import hashlib
import time
import os
import threading
import signal
from datetime import datetime
from scapy.all import *
from collections import defaultdict
import shutil
import glob

class AutoJsonConverterService:
    """自動化PCAP到JSON轉換服務"""
    
    def __init__(self, config_path="./config_surveiling_sample.json"):
        self.config_path = config_path
        self.config = {}
        
        # 服務設定
        self.time_gen_gap = 5  # 預設5秒
        self.pcap_input_dir = "PCAP"
        self.json_output_dir = "JSON"
        self.processed_files = set()  # 追蹤已處理的檔案
        self.is_running = False
        
        # 統計資訊
        self.conversion_stats = {
            'total_files_processed': 0,
            'total_packets_converted': 0,
            'total_restored_packets': 0,
            'failed_conversions': 0,
            'service_start_time': None,
            'last_conversion_time': None
        }
        
        # 分片處理
        self.fragment_buffer = defaultdict(dict)
        
        # 設定信號處理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def load_config(self):
        """載入配置檔案"""
        try:
            with open(self.config_path,encoding='utf-8') as f:
                self.config = json.load(f)
            
            # 讀取time_gen_gap設定
            self.time_gen_gap = self.config.get("time_gen_gap", 5)
            
            # 可選的自訂目錄設定
            self.pcap_input_dir = self.config.get("pcap_input_directory", "PCAP")
            self.json_output_dir = self.config.get("json_output_directory", "JSON")
            
            print("=== JSON轉換服務配置載入成功 ===")
            print(f"配置檔案: {self.config_path}")
            print(f"轉換間隔: {self.time_gen_gap} 秒")
            print(f"PCAP輸入目錄: {self.pcap_input_dir}")
            print(f"JSON輸出目錄: {self.json_output_dir}")
            print("=" * 40)
            
            return True
            
        except FileNotFoundError:
            print(f"❌ 配置檔案未找到: {self.config_path}")
            print("使用預設設定繼續運行...")
            return True  # 使用預設設定繼續
        except json.JSONDecodeError as e:
            print(f"❌ 配置檔案JSON格式錯誤: {e}")
            return False
        except Exception as e:
            print(f"❌ 載入配置時發生錯誤: {e}")
            return False
    
    def _ensure_directories(self):
        """確保必要目錄存在"""
        try:
            # 確保JSON輸出目錄存在
            if not os.path.exists(self.json_output_dir):
                os.makedirs(self.json_output_dir)
                print(f"✅ 創建JSON輸出目錄: {self.json_output_dir}")
            
            # 確保PCAP輸入目錄存在
            if not os.path.exists(self.pcap_input_dir):
                os.makedirs(self.pcap_input_dir)
                print(f"✅ 創建PCAP輸入目錄: {self.pcap_input_dir}")
                print(f"⚠️  注意: PCAP目錄是空的，等待檔案...")
            
            return True
            
        except Exception as e:
            print(f"❌ 創建目錄失敗: {e}")
            return False
    
    def _signal_handler(self, signum, frame):
        """處理系統信號"""
        print(f"\n收到終止信號 {signum}，正在安全關閉...")
        self.shutdown()
    
    def start_service(self):
        """啟動自動轉換服務"""
        try:
            print("🚀 啟動自動JSON轉換服務...")
            
            # 載入配置
            if not self.load_config():
                return False
            
            # 確保目錄存在
            if not self._ensure_directories():
                return False
            
            self.is_running = True
            self.conversion_stats['service_start_time'] = time.time()
            
            print("✅ JSON轉換服務初始化完成")
            print(f"🔄 開始監控 {self.pcap_input_dir} 目錄...")
            print(f"   轉換間隔: {self.time_gen_gap} 秒")
            print("   按 Ctrl+C 停止服務\n")
            
            # 啟動監控執行緒
            monitor_thread = threading.Thread(target=self._monitor_and_convert, daemon=True)
            monitor_thread.start()
            
            # 主執行緒等待
            try:
                while self.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            
            return True
            
        except Exception as e:
            print(f"❌ 啟動服務時發生錯誤: {e}")
            return False
    
    def _monitor_and_convert(self):
        """監控並轉換PCAP檔案"""
        print(f"🔄 監控執行緒啟動 (間隔: {self.time_gen_gap}秒)")
        
        while self.is_running:
            try:
                # 掃描PCAP目錄中的新檔案
                pcap_pattern = os.path.join(self.pcap_input_dir, "*.pcap")
                
                # 使用os.listdir和fnmatch作為備選方案
                try:
                    import fnmatch
                    all_files = os.listdir(self.pcap_input_dir)
                    pcap_files = [os.path.join(self.pcap_input_dir, f) 
                                 for f in all_files if fnmatch.fnmatch(f, "*.pcap")]
                except ImportError:
                    # 如果fnmatch不可用，使用基本字串檢查
                    all_files = os.listdir(self.pcap_input_dir)
                    pcap_files = [os.path.join(self.pcap_input_dir, f) 
                                 for f in all_files if f.endswith(".pcap")]
                
                # 找出新檔案
                new_files = []
                for pcap_file in pcap_files:
                    if pcap_file not in self.processed_files:
                        new_files.append(pcap_file)
                
                # 處理新檔案
                if new_files:
                    print(f"\n🔍 發現 {len(new_files)} 個新PCAP檔案")
                    for pcap_file in new_files:
                        self._convert_single_file(pcap_file)
                        self.processed_files.add(pcap_file)
                
                # 等待下一次檢查
                time.sleep(self.time_gen_gap)
                
            except Exception as e:
                print(f"❌ 監控執行緒錯誤: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(5)  # 錯誤時等待5秒
    
    def _convert_single_file(self, pcap_file):
        """轉換單個PCAP檔案"""
        try:
            print(f"🔄 處理檔案: {os.path.basename(pcap_file)}")
            
            # 讀取PCAP檔案
            packets = rdpcap(pcap_file)
            
            if len(packets) == 0:
                print(f"   ⚠️  檔案為空，跳過")
                return
            
            # 確定檔案類型和轉換模式
            file_basename = os.path.basename(pcap_file)
            if file_basename.startswith('restored_'):
                conversion_mode = 'restored_analysis'
                print(f"   📋 檔案類型: 還原封包")
            elif file_basename.startswith('received_'):
                conversion_mode = 'embedded_analysis'
                print(f"   📋 檔案類型: 接收封包 (嵌入)")
            else:
                conversion_mode = 'general_analysis'
                print(f"   📋 檔案類型: 一般封包")
            
            # 轉換封包
            converted_data = self._convert_packets_to_json(packets, pcap_file, conversion_mode)
            
            # 生成輸出檔案名
            output_filename = self._generate_json_filename(pcap_file, conversion_mode)
            output_path = os.path.join(self.json_output_dir, output_filename)
            
            # 寫入JSON檔案
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(converted_data, f, indent=2, ensure_ascii=False, default=str)
            
            # 更新統計
            self.conversion_stats['total_files_processed'] += 1
            self.conversion_stats['total_packets_converted'] += len(packets)
            self.conversion_stats['last_conversion_time'] = time.time()
            
            file_size = os.path.getsize(output_path)
            print(f"   ✅ 轉換完成: {output_filename}")
            print(f"   📊 {len(packets)} 個封包 → {file_size/1024:.1f} KB JSON")
            
        except Exception as e:
            print(f"   ❌ 轉換失敗: {e}")
            self.conversion_stats['failed_conversions'] += 1
    
    def _convert_packets_to_json(self, packets, source_file, mode):
        """將封包轉換為JSON格式"""
        timestamp = datetime.now().isoformat()
        
        result = {
            "metadata": {
                "conversion_time": timestamp,
                "source_file": os.path.basename(source_file),
                "conversion_mode": mode,
                "total_packets": len(packets),
                "converter_version": "auto_service_v1.0"
            },
            "packets": [],
            "statistics": {},
            "embedded_analysis": {} if mode == 'embedded_analysis' else None,
            "restoration_analysis": {} if mode == 'restored_analysis' else None
        }
        
        if mode == 'embedded_analysis':
            return self._analyze_embedded_packets(packets, result)
        elif mode == 'restored_analysis':
            return self._analyze_restored_packets(packets, result)
        else:
            return self._analyze_general_packets(packets, result)
    
    def _analyze_embedded_packets(self, packets, result):
        """分析嵌入封包"""
        fragments = {}
        embedded_packets = []
        parsing_errors = []
        
        for i, packet in enumerate(packets):
            try:
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8')
                    embedded_data = json.loads(payload)
                    
                    packet_info = {
                        "packet_index": i,
                        "timestamp": float(packet.time) if hasattr(packet, 'time') else time.time(),
                        "source": f"{packet[IP].src}:{packet[TCP].sport}" if IP in packet and TCP in packet else "unknown",
                        "size": len(bytes(packet)),
                        "embedded_content": embedded_data
                    }
                    
                    # 處理分片
                    if "fragment_info" in embedded_data:
                        fragment_info = embedded_data["fragment_info"]
                        fragment_uuid = fragment_info["fragment_uuid"]
                        
                        if fragment_uuid not in fragments:
                            fragments[fragment_uuid] = {
                                "total_fragments": fragment_info["total_fragments"],
                                "received_fragments": [],
                                "is_complete": False,
                                "first_seen": packet_info["timestamp"]
                            }
                        
                        fragments[fragment_uuid]["received_fragments"].append({
                            "index": fragment_info["fragment_index"],
                            "packet_index": i,
                            "size": len(embedded_data.get("data", "")),
                            "timestamp": packet_info["timestamp"]
                        })
                        
                        # 檢查完整性
                        if len(fragments[fragment_uuid]["received_fragments"]) == fragment_info["total_fragments"]:
                            fragments[fragment_uuid]["is_complete"] = True
                            # 嘗試重組
                            restored = self._try_reassemble_fragment(fragment_uuid, fragments[fragment_uuid], embedded_data)
                            if restored:
                                fragments[fragment_uuid]["restoration_success"] = True
                                self.conversion_stats['total_restored_packets'] += 1
                    else:
                        embedded_packets.append(packet_info)
                        
            except json.JSONDecodeError as e:
                parsing_errors.append({
                    "packet_index": i,
                    "error": "JSON decode error",
                    "details": str(e)
                })
            except Exception as e:
                parsing_errors.append({
                    "packet_index": i,
                    "error": "General parsing error",
                    "details": str(e)
                })
        
        # 更新結果
        result["embedded_analysis"] = {
            "embedded_packets": embedded_packets,
            "fragments": fragments,
            "parsing_errors": parsing_errors,
            "statistics": {
                "total_embedded": len(embedded_packets),
                "total_fragments": len(fragments),
                "complete_fragments": sum(1 for f in fragments.values() if f["is_complete"]),
                "parsing_errors": len(parsing_errors)
            }
        }
        
        return result
    
    def _analyze_restored_packets(self, packets, result):
        """分析還原封包"""
        restored_packets = []
        
        for i, packet in enumerate(packets):
            try:
                packet_analysis = {
                    "packet_index": i,
                    "timestamp": float(packet.time) if hasattr(packet, 'time') else time.time(),
                    "size": len(bytes(packet)),
                    "hash": hashlib.sha256(bytes(packet)).hexdigest(),
                    "layers": self._get_packet_layers(packet),
                    "protocol_analysis": {}
                }
                
                # 協議分析
                if IP in packet:
                    packet_analysis["protocol_analysis"]["ip"] = {
                        "src": packet[IP].src,
                        "dst": packet[IP].dst,
                        "protocol": packet[IP].proto,
                        "ttl": packet[IP].ttl
                    }
                
                if TCP in packet:
                    packet_analysis["protocol_analysis"]["tcp"] = {
                        "src_port": packet[TCP].sport,
                        "dst_port": packet[TCP].dport,
                        "flags": int(packet[TCP].flags),
                        "flags_readable": self._tcp_flags_to_string(packet[TCP].flags)
                    }
                
                if Raw in packet:
                    payload = packet[Raw].load
                    packet_analysis["payload"] = {
                        "size": len(payload),
                        "encoding": self._detect_encoding(payload),
                        "preview": payload[:100].hex()
                    }
                
                restored_packets.append(packet_analysis)
                
            except Exception as e:
                print(f"   ⚠️  封包 {i} 分析失敗: {e}")
        
        result["restoration_analysis"] = {
            "restored_packets": restored_packets,
            "statistics": {
                "total_restored": len(restored_packets),
                "unique_sources": len(set(p["protocol_analysis"].get("ip", {}).get("src", "") for p in restored_packets)),
                "unique_destinations": len(set(p["protocol_analysis"].get("ip", {}).get("dst", "") for p in restored_packets))
            }
        }
        
        return result
    
    def _analyze_general_packets(self, packets, result):
        """分析一般封包"""
        packet_list = []
        
        for i, packet in enumerate(packets):
            try:
                packet_dict = {
                    "index": i,
                    "timestamp": float(packet.time) if hasattr(packet, 'time') else time.time(),
                    "size": len(bytes(packet)),
                    "summary": packet.summary(),
                    "hash": hashlib.sha256(bytes(packet)).hexdigest(),
                    "layers": self._get_packet_layers(packet)
                }
                
                packet_list.append(packet_dict)
                
            except Exception as e:
                print(f"   ⚠️  封包 {i} 處理失敗: {e}")
        
        result["packets"] = packet_list
        result["statistics"] = {
            "total_packets": len(packet_list),
            "average_size": sum(p["size"] for p in packet_list) / len(packet_list) if packet_list else 0
        }
        
        return result
    
    def _try_reassemble_fragment(self, fragment_uuid, fragment_info, sample_data):
        """嘗試重組分片（簡化版）"""
        try:
            # 這裡只是標記重組嘗試，實際重組邏輯可以更複雜
            return fragment_info["is_complete"]
        except:
            return False
    
    def _get_packet_layers(self, packet):
        """獲取封包層級"""
        layers = []
        current = packet
        while current:
            layer_name = current.__class__.__name__
            layers.append(layer_name)
            if hasattr(current, 'payload') and current.payload:
                current = current.payload
            else:
                break
        return layers
    
    def _tcp_flags_to_string(self, flags):
        """TCP flags轉字串"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        return "|".join(flag_names) if flag_names else "None"
    
    def _detect_encoding(self, data):
        """檢測資料編碼"""
        try:
            data.decode('utf-8')
            return "UTF-8"
        except:
            try:
                data.decode('ascii')
                return "ASCII"
            except:
                return "Binary"
    
    def _generate_json_filename(self, pcap_file, mode):
        """生成JSON檔案名"""
        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if mode == 'embedded_analysis':
            return f"{base_name}_embedded_{timestamp}.json"
        elif mode == 'restored_analysis':
            return f"{base_name}_restored_{timestamp}.json"
        else:
            return f"{base_name}_general_{timestamp}.json"
    
    def get_service_statistics(self):
        """獲取服務統計"""
        current_time = time.time()
        start_time = self.conversion_stats['service_start_time']
        
        runtime = current_time - start_time if start_time else 0
        
        return {
            **self.conversion_stats,
            "service_runtime_seconds": runtime,
            "files_per_hour": (self.conversion_stats['total_files_processed'] / (runtime / 3600)) if runtime > 0 else 0,
            "processed_files_list": list(self.processed_files),
            "current_time": datetime.now().isoformat()
        }
    
    def shutdown(self):
        """關閉服務"""
        print("\n🛑 正在關閉JSON轉換服務...")
        
        self.is_running = False
        
        # 顯示統計資訊
        stats = self.get_service_statistics()
        
        print(f"\n📊 服務統計:")
        print(f"   運行時間: {stats['service_runtime_seconds']:.1f} 秒")
        print(f"   處理檔案: {stats['total_files_processed']} 個")
        print(f"   轉換封包: {stats['total_packets_converted']} 個")
        print(f"   還原封包: {stats['total_restored_packets']} 個")
        print(f"   失敗轉換: {stats['failed_conversions']} 個")
        print(f"   處理效率: {stats['files_per_hour']:.1f} 檔案/小時")
        
        # 顯示已處理檔案
        if self.processed_files:
            print(f"\n📁 已處理檔案:")
            for i, file_path in enumerate(sorted(self.processed_files), 1):
                print(f"   {i}. {os.path.basename(file_path)}")
        
        # 計算JSON檔案統計
        try:
            import fnmatch
            json_files = []
            if os.path.exists(self.json_output_dir):
                all_files = os.listdir(self.json_output_dir)
                json_files = [os.path.join(self.json_output_dir, f) 
                             for f in all_files if fnmatch.fnmatch(f, "*.json")]
            
            total_json_size = sum(os.path.getsize(f) for f in json_files if os.path.exists(f))
            
            print(f"\n📄 JSON輸出統計:")
            print(f"   JSON檔案數: {len(json_files)} 個")
            print(f"   總大小: {total_json_size/1024:.1f} KB")
            
        except Exception as e:
            print(f"   JSON統計計算錯誤: {e}")
        
        print("✅ JSON轉換服務已安全關閉")


def main():
    """主程式"""
    print("🔄 自動化PCAP到JSON轉換服務")
    print("=" * 60)
    print("從config_surveiling_sample.json讀取設定")
    print("自動監控PCAP目錄並轉換為JSON")
    print("=" * 60)
    
    # 取得配置檔案路徑
    config_path = input("配置檔案路徑 (預設: ./config_surveiling_sample.json): ").strip()
    if not config_path:
        config_path = "./config_surveiling_sample.json"
    
    # 建立服務實例
    service = AutoJsonConverterService(config_path)
    
    try:
        # 啟動服務
        success = service.start_service()
        
        if not success:
            print("❌ JSON轉換服務啟動失敗")
            return 1
            
    except KeyboardInterrupt:
        print("\n⚠️  收到中斷信號")
    except Exception as e:
        print(f"❌ 服務運行時發生錯誤: {e}")
        return 1
    finally:
        service.shutdown()
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())