#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import time
import signal
import socket
import threading
import base64
import hashlib
import os
from collections import defaultdict
from datetime import datetime
from scapy.all import *

class SurveilingProcessor:
    def __init__(self, config_path="../config.json"):
        self.config_path = config_path
        self.config = {}
        self.is_running = False
        self.received_signals = []
        self.received_fragments = defaultdict(dict)
        self.processed_count = 0
        self.signal_count = 0
        self.restored_packets = []
        
        # PCAP定時匯出相關
        self.time_gen_gap = 5  # 預設5秒
        self.pcap_output_dir = "PCAP"
        self.pcap_export_enabled = False
        self.last_export_time = 0
        self.export_counter = 0
        
        # 臨時封包緩存 (用於定時匯出)
        self.temp_restored_packets = []
        self.temp_received_packets = []  # 原始接收到的嵌入封包
        
        # 設定信號處理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def load_config(self):
        """載入完整配置"""
        try:
            with open(self.config_path,encoding='utf-8') as f:
                self.config = json.load(f)

            # 驗證 service_type
            service_type = self.config.get("service_type", "").lower()
            if service_type != "surveiling":
                raise ValueError(f"此模組僅支援 Surveiling 模式，當前配置: {service_type}")

            # 驗證必要的配置項目
            required_keys = [
                "service_type", "signal_listen_port", "embed_listen_port"
            ]

            missing_keys = [key for key in required_keys if key not in self.config]
            if missing_keys:
                raise ValueError(f"配置檔案缺少必要項目: {missing_keys}")

            # 載入PCAP匯出設定
            self.time_gen_gap = self.config.get("time_gen_gap", 5)
            self.pcap_export_enabled = self.time_gen_gap > 0  # 如果設定了time_gen_gap就啟用

            print("=== 監控端配置載入成功 ===")
            print(f"服務模式: Surveiling（監控端）")
            print(f"信號監聽端口: {self.config['signal_listen_port']}")
            print(f"嵌入封包監聽端口: {self.config['embed_listen_port']}")
            
            if self.pcap_export_enabled:
                print(f"🔄 PCAP定時匯出: 啟用 (每 {self.time_gen_gap} 秒)")
                print(f"📁 PCAP輸出目錄: {self.pcap_output_dir}")
                self._ensure_pcap_directory()
            else:
                print("🔄 PCAP定時匯出: 停用")
            
            print("=" * 30)

            return True

        except FileNotFoundError:
            print(f"❌ 配置檔案未找到: {self.config_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ 配置檔案JSON格式錯誤: {e}")
            return False
        except Exception as e:
            print(f"❌ 載入配置時發生錯誤: {e}")
            return False

    def _ensure_pcap_directory(self):
        """確保PCAP輸出目錄存在"""
        try:
            if not os.path.exists(self.pcap_output_dir):
                os.makedirs(self.pcap_output_dir)
                print(f"✅ 創建PCAP目錄: {self.pcap_output_dir}")
            else:
                print(f"✅ PCAP目錄已存在: {self.pcap_output_dir}")
        except Exception as e:
            print(f"❌ 創建PCAP目錄失敗: {e}")
            self.pcap_export_enabled = False

    def _signal_handler(self, signum, frame):
        """處理系統信號（Ctrl+C等）"""
        print(f"\n收到終止信號 {signum}，正在安全關閉...")
        self.shutdown()

    def start_processing(self):
        """啟動監控端處理"""
        try:
            print("🚀 啟動監控端系統...")

            # 載入配置
            if not self.load_config():
                return False

            self.is_running = True
            self.last_export_time = time.time()

            print("✅ 監控端初始化完成")
            print("🔍 開始監聽Signal和嵌入封包...")
            print("   等待被監控端發送資料")
            
            if self.pcap_export_enabled:
                print(f"   🔄 PCAP定時匯出已啟用，每 {self.time_gen_gap} 秒生成一次")
            
            print("   按 Ctrl+C 停止系統\n")

            # 啟動多個監聽執行緒
            signal_thread = threading.Thread(target=self._listen_for_signals, daemon=True)
            embed_thread = threading.Thread(target=self._listen_for_embedded_packets, daemon=True)
            
            # 啟動PCAP定時匯出執行緒
            if self.pcap_export_enabled:
                pcap_export_thread = threading.Thread(target=self._pcap_export_worker, daemon=True)
                pcap_export_thread.start()

            signal_thread.start()
            embed_thread.start()

            # 主執行緒等待
            try:
                while self.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

            return True

        except Exception as e:
            print(f"❌ 啟動處理系統時發生錯誤: {e}")
            return False

    def _pcap_export_worker(self):
        """PCAP定時匯出工作執行緒"""
        print(f"🔄 PCAP定時匯出執行緒啟動 (間隔: {self.time_gen_gap}秒)")
        
        while self.is_running:
            try:
                current_time = time.time()
                
                # 檢查是否到了匯出時間
                if current_time - self.last_export_time >= self.time_gen_gap:
                    self._export_current_packets()
                    self.last_export_time = current_time
                
                # 每秒檢查一次
                time.sleep(1)
                
            except Exception as e:
                print(f"❌ PCAP匯出執行緒錯誤: {e}")
                time.sleep(5)  # 錯誤時等待5秒再繼續

    def _export_current_packets(self):
        """匯出當前時間段的封包"""
        try:
            # 檢查是否有封包需要匯出
            restored_count = len(self.temp_restored_packets)
            received_count = len(self.temp_received_packets)
            
            if restored_count == 0 and received_count == 0:
                return  # 沒有封包，跳過這次匯出
            
            self.export_counter += 1
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            print(f"\n💾 定時PCAP匯出 #{self.export_counter} ({timestamp})")
            
            files_created = []
            
            # 匯出還原封包
            if restored_count > 0:
                restored_filename = os.path.join(
                    self.pcap_output_dir, 
                    f"restored_{timestamp}_{self.export_counter:03d}.pcap"
                )
                
                try:
                    packets_to_export = [info['packet'] for info in self.temp_restored_packets]
                    wrpcap(restored_filename, packets_to_export)
                    files_created.append(restored_filename)
                    print(f"   ✅ 還原封包: {restored_filename} ({restored_count} 個封包)")
                except Exception as e:
                    print(f"   ❌ 還原封包匯出失敗: {e}")
            
            # 匯出原始接收封包
            if received_count > 0:
                received_filename = os.path.join(
                    self.pcap_output_dir, 
                    f"received_{timestamp}_{self.export_counter:03d}.pcap"
                )
                
                try:
                    packets_to_export = [info['packet'] for info in self.temp_received_packets]
                    wrpcap(received_filename, packets_to_export)
                    files_created.append(received_filename)
                    print(f"   ✅ 接收封包: {received_filename} ({received_count} 個封包)")
                except Exception as e:
                    print(f"   ❌ 接收封包匯出失敗: {e}")
            
            # 顯示匯出統計
            if files_created:
                total_size = sum(os.path.getsize(f) for f in files_created)
                print(f"   📊 匯出統計: {len(files_created)} 個檔案, 總大小: {total_size/1024:.1f} KB")
            
            # 清空暫存
            self.temp_restored_packets.clear()
            self.temp_received_packets.clear()
            
        except Exception as e:
            print(f"❌ 匯出封包時發生錯誤: {e}")

    def _listen_for_signals(self):
        """監聽信號封包"""
        try:
            port = self.config["signal_listen_port"]
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            server_socket.settimeout(1)

            print(f"🔍 開始監聽信號封包，端口: {port}")

            while self.is_running:
                try:
                    client_socket, address = server_socket.accept()

                    data = client_socket.recv(1024)
                    if data:
                        signal_info = json.loads(data.decode('utf-8'))
                        self._handle_received_signal(signal_info, address)

                    client_socket.close()

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.is_running:
                        print(f"⚠️  接收信號封包時發生錯誤: {e}")

            server_socket.close()

        except Exception as e:
            print(f"❌ 監聽信號封包時發生錯誤: {e}")

    def _handle_received_signal(self, signal_info, sender_address):
        """處理接收到的信號封包"""
        try:
            self.signal_count += 1

            print(f"\n🚨 收到信號封包 #{self.signal_count}!")
            print(f"   來源: {sender_address[0]}:{sender_address[1]}")
            print(f"   時間戳: {signal_info.get('timestamp', 'unknown')}")
            print(f"   UUID: {signal_info.get('uuid', 'unknown')}")
            print(f"   信號類型: {signal_info.get('signal_type', 'unknown')}")

            # 記錄信號
            self.received_signals.append({
                "signal_info": signal_info,
                "sender": sender_address,
                "received_time": time.time()
            })

            print(f"   ✅ 信號已記錄，來源主機 {sender_address[0]} 已識別")
            print(f"   📊 已接收信號總數: {self.signal_count}\n")

        except Exception as e:
            print(f"❌ 處理信號封包時發生錯誤: {e}")

    def _listen_for_embedded_packets(self):
        """監聽嵌入封包"""
        try:
            port = self.config["embed_listen_port"]

            print(f"🔍 開始監聽嵌入封包，端口: {port}")

            def packet_handler(packet):
                if TCP in packet and packet[TCP].dport == port:
                    self._handle_received_embedded_packet(packet)

            # 設定過濾器
            filter_str = f"tcp dst port {port}"

            # 這會在背景執行直到程式結束
            sniff(filter=filter_str, prn=packet_handler, store=0, stop_filter=lambda x: not self.is_running)

        except Exception as e:
            print(f"❌ 監聽嵌入封包時發生錯誤: {e}")

    def _handle_received_embedded_packet(self, packet):
        """處理接收到的嵌入封包"""
        try:
            if Raw not in packet:
                return

            payload = packet[Raw].load.decode('utf-8')

            print(f"\n📥 收到嵌入封包")
            print(f"   來源: {packet[IP].src}:{packet[TCP].sport}")
            print(f"   大小: {len(payload)} bytes")

            # 如果啟用PCAP匯出，將原始封包加入暫存
            if self.pcap_export_enabled:
                received_packet_info = {
                    'packet': packet,
                    'timestamp': time.time(),
                    'size': len(bytes(packet))
                }
                self.temp_received_packets.append(received_packet_info)

            # 解析封包內容
            try:
                data = json.loads(payload)
                
                # 先檢查數據結構
                print(f"   📋 封包結構: {list(data.keys())}")

                if "fragment_info" in data:
                    # 這是分片封包
                    print("   📦 識別為分片封包")
                    self._handle_embedded_fragment(data, packet)
                elif "metadata" in data and "original_packet" in data:
                    # 這是完整封包
                    print("   📋 識別為完整封包")
                    self._handle_complete_embedded_packet(data, packet)
                else:
                    # 檢查是否是簡化版本的封包
                    print("   ⚠️  未知的封包格式，嘗試簡化處理")
                    print(f"   數據鍵值: {list(data.keys())}")
                    
                    # 嘗試處理簡化版本
                    if any(key in data for key in ['embed_uuid', 'original_packet', 'data']):
                        print("   🔄 嘗試簡化格式處理")
                        self._handle_simplified_embedded_packet(data, packet)
                    else:
                        print("   ❌ 無法識別的封包格式")

            except json.JSONDecodeError as e:
                print(f"   ❌ JSON解析失敗: {e}")
                print(f"   前100字元: {payload[:100]}")

        except UnicodeDecodeError as e:
            print(f"   ❌ UTF-8解碼失敗: {e}")
        except Exception as e:
            print(f"❌ 處理嵌入封包時發生錯誤: {e}")
            import traceback
            traceback.print_exc()

    def _handle_simplified_embedded_packet(self, data, source_packet):
        """處理簡化格式的嵌入封包"""
        try:
            print("   🔧 處理簡化格式封包")
            
            # 尋找metadata和original_packet
            metadata = None
            original_packet_data = None
            
            # 檢查不同的可能結構
            if "metadata" in data:
                metadata = data["metadata"]
            elif "embed_uuid" in data:
                # 構建簡化的metadata
                metadata = {
                    "embed_uuid": data.get("embed_uuid", "unknown"),
                    "embed_timestamp": data.get("embed_timestamp", "unknown")
                }
            
            if "original_packet" in data:
                original_packet_data = data["original_packet"]
            elif "data" in data:
                # 可能是直接的數據格式
                original_packet_data = {
                    "data": data["data"],
                    "length": data.get("length", 0),
                    "original_hash": data.get("original_hash", "")
                }
            
            if metadata and original_packet_data:
                print("   ✅ 成功解析簡化格式")
                self._process_extracted_packet(metadata, original_packet_data)
            else:
                print("   ❌ 簡化格式解析失敗")
                print(f"   metadata: {'✅' if metadata else '❌'}")
                print(f"   original_packet_data: {'✅' if original_packet_data else '❌'}")
                
        except Exception as e:
            print(f"   ❌ 簡化格式處理錯誤: {e}")

    def _handle_embedded_fragment(self, fragment_data, source_packet):
        """處理嵌入封包分片"""
        try:
            fragment_info = fragment_data["fragment_info"]
            fragment_uuid = fragment_info["fragment_uuid"]
            fragment_index = fragment_info["fragment_index"]
            total_fragments = fragment_info["total_fragments"]

            print(f"   📦 分片封包: {fragment_uuid[:8]}... [{fragment_index + 1}/{total_fragments}]")

            # 儲存分片
            self.received_fragments[fragment_uuid][fragment_index] = fragment_data

            # 檢查是否收集完所有分片
            if len(self.received_fragments[fragment_uuid]) == total_fragments:
                print(f"   ✅ 所有分片已收到，開始重組")
                self._reassemble_and_process(fragment_uuid)

        except Exception as e:
            print(f"❌ 處理分片時發生錯誤: {e}")

    def _reassemble_and_process(self, fragment_uuid):
        """重組分片並處理原始封包"""
        try:
            fragments = self.received_fragments[fragment_uuid]

            # 按索引排序
            sorted_fragments = sorted(fragments.items())

            # 重組數據
            reassembled_data = b""
            for _, fragment_data in sorted_fragments:
                fragment_bytes = base64.b64decode(fragment_data["data"])
                reassembled_data += fragment_bytes

            # 解析完整數據
            complete_data = json.loads(reassembled_data.decode('utf-8'))

            # 處理完整封包
            self._handle_complete_embedded_packet(complete_data, None)

            # 清理分片緩存
            del self.received_fragments[fragment_uuid]

        except Exception as e:
            print(f"❌ 重組分片時發生錯誤: {e}")

    def _handle_complete_embedded_packet(self, embedded_data, source_packet):
        """處理完整的嵌入封包並還原原始封包 - 修復版本"""
        try:
            # 安全地獲取metadata和original_packet
            metadata = embedded_data.get("metadata")
            original_packet_data = embedded_data.get("original_packet")
            
            if not metadata:
                print("   ❌ 缺少metadata")
                return
                
            if not original_packet_data:
                print("   ❌ 缺少original_packet")
                return
            
            self._process_extracted_packet(metadata, original_packet_data)

        except Exception as e:
            print(f"❌ 處理完整嵌入封包時發生錯誤: {e}")
            import traceback
            traceback.print_exc()

    def _process_extracted_packet(self, metadata, original_packet_data):
        """處理提取的封包數據"""
        try:
            print(f"\n🎯 還原原始封包:")
            print(f"   嵌入UUID: {metadata.get('embed_uuid', 'unknown')}")
            print(f"   嵌入時間: {metadata.get('embed_timestamp', 'unknown')}")
            print(f"   原始來源: {original_packet_data.get('original_src', 'unknown')}")
            print(f"   原始目標: {original_packet_data.get('original_dst', 'unknown')}")
            print(f"   原始協議: {original_packet_data.get('original_protocol', 'unknown')}")
            print(f"   原始大小: {original_packet_data.get('length', 'unknown')} bytes")

            # 獲取原始雜湊值（如果有的話）
            expected_hash = original_packet_data.get('original_hash', '')
            if expected_hash:
                print(f"   期望雜湊: {expected_hash[:16]}...")

            # 重建原始封包
            original_data_b64 = original_packet_data.get("data")
            if not original_data_b64:
                print("   ❌ 缺少封包數據")
                return
                
            original_bytes = base64.b64decode(original_data_b64)

            # 驗證數據完整性
            actual_hash = hashlib.sha256(original_bytes).hexdigest()
            print(f"   實際雜湊: {actual_hash[:16]}...")

            if expected_hash and actual_hash != expected_hash:
                print(f"   ⚠️  資料完整性驗證失敗!")
                print(f"      期望: {expected_hash}")
                print(f"      實際: {actual_hash}")

            try:
                # 智能還原 - 根據層級資訊決定還原方式
                layers = original_packet_data.get('layers', [])
                print(f"   封包層級: {' / '.join(layers) if layers else '未知'}")

                # 根據原始封包的層級結構選擇還原方式
                if layers:
                    if "Ether" in layers:
                        # 原始封包有Ether層
                        original_packet = Ether(original_bytes)
                        print(f"   📋 從Ether層還原")
                    elif "IP" in layers:
                        # 原始封包從IP層開始
                        original_packet = IP(original_bytes)
                        print(f"   📋 從IP層還原")
                    else:
                        # 未知結構，嘗試Ether
                        original_packet = Ether(original_bytes)
                        print(f"   📋 預設從Ether層還原")
                else:
                    # 沒有層級資訊，嘗試智能判斷
                    if len(original_bytes) > 14 and original_bytes[12:14] == b'\x08\x00':
                        # 看起來像Ethernet + IPv4
                        original_packet = Ether(original_bytes)
                        print(f"   📋 檢測到Ethernet header，從Ether層還原")
                    elif len(original_bytes) > 0 and (original_bytes[0] >> 4) == 4:
                        # 看起來像IPv4
                        original_packet = IP(original_bytes)
                        print(f"   📋 檢測到IPv4，從IP層還原")
                    else:
                        # 預設使用Ether
                        original_packet = Ether(original_bytes)
                        print(f"   📋 無法判斷，預設從Ether層還原")

                print(f"   ✅ 原始封包重建成功")

                # 計算還原後的雜湊值
                restored_hash = hashlib.sha256(bytes(original_packet)).hexdigest()
                print(f"   還原雜湊: {restored_hash[:16]}...")

                # 儲存還原的封包用於比較
                restored_info = {
                    'timestamp': time.time(),
                    'packet': original_packet,
                    'size': len(bytes(original_packet)),
                    'hash': restored_hash,
                    'metadata': metadata,
                    'original_hash': expected_hash,
                    'data_integrity_ok': (actual_hash == expected_hash) if expected_hash else True,
                    'restoration_method': 'smart_detection'
                }
                
                self.restored_packets.append(restored_info)
                
                # 如果啟用PCAP匯出，也加入暫存
                if self.pcap_export_enabled:
                    self.temp_restored_packets.append(restored_info)

                # 更新統計
                self.processed_count += 1

                # 進行進一步處理
                self._analyze_original_packet(original_packet, metadata)

                print(f"   📊 已處理嵌入封包總數: {self.processed_count}")
                
                # 雜湊比較結果
                if expected_hash:
                    if actual_hash == expected_hash:
                        print(f"   ✅ 資料完整性驗證通過")
                    else:
                        print(f"   ❌ 資料完整性驗證失敗")
                
                print(f"{'=' * 60}\n")

            except Exception as e:
                print(f"   ❌ 重建原始封包失敗: {e}")
                print(f"   原始數據前32位元組: {original_bytes[:32].hex()}")

        except Exception as e:
            print(f"❌ 處理提取封包時發生錯誤: {e}")
            import traceback
            traceback.print_exc()

    def _analyze_original_packet(self, original_packet, metadata):
        """分析還原的原始封包"""
        try:
            print(f"   🔍 封包分析:")

            # 分析IP層
            if IP in original_packet:
                ip_layer = original_packet[IP]
                print(f"      IP: {ip_layer.src} -> {ip_layer.dst}")
                print(f"      TTL: {ip_layer.ttl}, 協議: {ip_layer.proto}")

                # 分析TCP層
                if TCP in original_packet:
                    tcp_layer = original_packet[TCP]
                    print(f"      TCP: Port {tcp_layer.sport} -> {tcp_layer.dport}")
                    print(f"      Flags: {tcp_layer.flags}")

                    # 分析Payload
                    if Raw in original_packet:
                        payload = original_packet[Raw].load
                        print(f"      Payload: {len(payload)} bytes")

                        # 嘗試檢測HTTP
                        try:
                            payload_str = payload.decode('utf-8', errors='ignore')
                            if any(method in payload_str for method in ['GET', 'POST', 'PUT', 'DELETE']):
                                lines = payload_str.split('\n')
                                print(f"      HTTP請求: {lines[0][:100]}...")
                        except:
                            pass

        except Exception as e:
            print(f"   ⚠️  分析封包時發生錯誤: {e}")

    def export_packets_to_pcap(self, filename="captured_packets.pcap"):
        """匯出還原的封包到PCAP檔案"""
        try:
            if self.restored_packets:
                packets = [info['packet'] for info in self.restored_packets]
                wrpcap(filename, packets)
                print(f"   💾 已匯出 {len(packets)} 個還原封包到 {filename}")
                return filename
            else:
                print(f"   ⚠️  沒有還原封包可匯出")
                return None
        except Exception as e:
            print(f"   ❌ 匯出封包失敗: {e}")
            return None

    def get_statistics(self):
        """取得詳細統計資訊"""
        return {
            "received_signals": self.signal_count,
            "processed_packets": self.processed_count,
            "restored_packets_count": len(self.restored_packets),
            "pending_fragments": len(self.received_fragments),
            "pcap_export_enabled": self.pcap_export_enabled,
            "pcap_export_counter": self.export_counter,
            "time_gen_gap": self.time_gen_gap,
            "fragment_details": {
                uuid[:8]: len(fragments)
                for uuid, fragments in self.received_fragments.items()
            },
            "signal_sources": list(set(
                signal["sender"][0] for signal in self.received_signals
            )),
            "data_integrity_stats": {
                "total_with_hash": len([p for p in self.restored_packets if p.get('original_hash')]),
                "integrity_ok": len([p for p in self.restored_packets if p.get('data_integrity_ok', True)]),
                "integrity_failed": len([p for p in self.restored_packets if not p.get('data_integrity_ok', True)])
            }
        }

    def shutdown(self):
        """安全關閉系統"""
        print("\n🛑 正在關閉監控端系統...")

        self.is_running = False

        # 如果啟用PCAP匯出，執行最後一次匯出
        if self.pcap_export_enabled and (self.temp_restored_packets or self.temp_received_packets):
            print("🔄 執行最後一次PCAP匯出...")
            self._export_current_packets()

        # 顯示詳細統計資訊
        stats = self.get_statistics()

        print(f"\n📊 監控端統計:")
        print(f"   已接收信號數: {stats['received_signals']}")
        print(f"   已處理封包數: {stats['processed_packets']}")
        print(f"   已還原封包數: {stats['restored_packets_count']}")
        print(f"   待處理分片: {stats['pending_fragments']}")

        # PCAP匯出統計
        if stats['pcap_export_enabled']:
            print(f"   PCAP定時匯出: ✅ 啟用")
            print(f"   匯出間隔: {stats['time_gen_gap']} 秒")
            print(f"   已匯出批次: {stats['pcap_export_counter']} 次")
            
            # 計算PCAP檔案總數和大小
            pcap_files = []
            total_size = 0
            try:
                import glob
                pcap_pattern = os.path.join(self.pcap_output_dir, "*.pcap")
                pcap_files = glob.glob(pcap_pattern)
                total_size = sum(os.path.getsize(f) for f in pcap_files)
                print(f"   PCAP檔案總數: {len(pcap_files)} 個")
                print(f"   PCAP檔案總大小: {total_size/1024:.1f} KB")
            except Exception as e:
                print(f"   PCAP統計計算錯誤: {e}")
        else:
            print(f"   PCAP定時匯出: ❌ 停用")

        # 資料完整性統計
        integrity_stats = stats['data_integrity_stats']
        if integrity_stats['total_with_hash'] > 0:
            success_rate = (integrity_stats['integrity_ok'] / integrity_stats['total_with_hash']) * 100
            print(f"   資料完整性: {success_rate:.1f}% ({integrity_stats['integrity_ok']}/{integrity_stats['total_with_hash']})")

        if stats['signal_sources']:
            print(f"   信號來源: {', '.join(stats['signal_sources'])}")

        if stats['fragment_details']:
            print(f"   未完成分片: {list(stats['fragment_details'].keys())}")

        # 自動匯出最終的還原封包
        if self.restored_packets:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            final_pcap_file = f"final_restored_packets_{timestamp}.pcap"
            self.export_packets_to_pcap(final_pcap_file)

        print("✅ 監控端已安全關閉")

    def get_status(self):
        """取得系統狀態"""
        return {
            "is_running": self.is_running,
            "service_mode": "Surveiling",
            "received_signals": self.signal_count,
            "processed_packets": self.processed_count,
            "restored_packets_count": len(self.restored_packets),
            "pending_fragments": len(self.received_fragments),
            "pcap_export_enabled": self.pcap_export_enabled,
            "pcap_export_counter": self.export_counter,
            "config": self.config
        }


def main():
    """主程式進入點"""
    print("=" * 60)
    print("👁️ 監控端系統 (PCAP定時匯出版)")
    print("   接收Signal和嵌入封包並還原分析")
    print("   支援智能封包還原和完整性驗證")
    print("   支援定時PCAP檔案匯出功能")
    print("=" * 60)

    # 建立處理器實例
    processor = SurveilingProcessor(config_path="./config_surveiling_sample.json")

    try:
        # 啟動處理系統
        success = processor.start_processing()

        if not success:
            print("❌ 監控端系統啟動失敗")
            return 1

    except KeyboardInterrupt:
        print("\n⚠️  收到中斷信號")
    except Exception as e:
        print(f"❌ 系統運行時發生錯誤: {e}")
        return 1
    finally:
        processor.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())