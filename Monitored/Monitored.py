#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import time
import signal
import uuid
from pathlib import Path

# 導入自定義模組
from Filter import PacketFilter
from SignalGen import send_signal
from Embedding import embed_and_send_packet, PacketEmbedder
import scapy.all


class MonitoredProcessor:
    def __init__(self, config_path="../config.json"):
        self.config_path = config_path
        self.config = {}
        self.packet_filter = None
        self.packet_embedder = PacketEmbedder()
        self.is_running = False
        self.processed_count = 0
        self.signal_sent = False  # 記錄是否已發送signal
        self.current_uuid = uuid.uuid4() #服務專用UUID

        # 設定信號處理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def load_config(self):
        """載入完整配置"""
        try:
            with open(self.config_path) as f:
                self.config = json.load(f)

            # 驗證 service_type
            service_type = self.config.get("service_type", "").lower()
            if service_type != "monitored":
                raise ValueError(f"此模組僅支援 Monitored 模式，當前配置: {service_type}")

            # 驗證必要的配置項目
            required_keys = [
                "interface", "port", "service_type",
                "signal_target_ip", "signal_target_port",
                "embed_target_ip", "embed_target_port"
            ]

            missing_keys = [key for key in required_keys if key not in self.config]
            if missing_keys:
                raise ValueError(f"配置檔案缺少必要項目: {missing_keys}")

            print("=== 被監控端配置載入成功 ===")
            print(f"服務模式: Monitored（被監控端）")
            print(f"監聽介面: {self.config['interface']}")
            print(f"監聽Port: {self.config['port']}")
            print(f"信號目標: {self.config['signal_target_ip']}:{self.config['signal_target_port']}")
            print(f"嵌入目標: {self.config['embed_target_ip']}:{self.config['embed_target_port']}")
            print(f"處理間隔: {self.config.get('time_gap', 0)}秒")
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

    def _signal_handler(self, signum, frame):
        """處理系統信號（Ctrl+C等）"""
        print(f"\n收到終止信號 {signum}，正在安全關閉...")
        self.shutdown()

    def start_processing(self):
        """啟動被監控端處理"""
        try:
            print("🚀 啟動被監控端系統...")

            # 載入配置
            if not self.load_config():
                return False

            # 初始化封包過濾器
            self.packet_filter = PacketFilter(self.config_path)

            if not self.packet_filter.load_config():
                print("❌ 封包過濾器配置載入失敗")
                return False

            if not self.packet_filter.apply_config():
                print("❌ 封包過濾器配置應用失敗")
                return False

            self.is_running = True

            print("✅ 被監控端初始化完成")
            print("🔍 開始監聽本機封包流量...")
            print("   發現封包時將發送Signal並轉發封包到監控端")
            print("   按 Ctrl+C 停止系統\n")

            # 開始封包捕獲
            self.packet_filter.start_capture(self._packet_callback)
            return True

        except Exception as e:
            print(f"❌ 啟動處理系統時發生錯誤: {e}")
            return False

    def _packet_callback(self, captured_packet):
        """封包處理回調函數"""
        try:
            print(f"\n{'=' * 60}")
            print(f"處理封包 #{self.processed_count + 1} (被監控端模式)")
            print(f"{'=' * 60}")

            # 步驟1: 檢查是否需要發送信號封包（只發送一次）
            signal_success = True
            if not self.signal_sent:
                print("🚀 步驟1: 發送信號封包（首次識別本機）...")
                signal_success = self._send_signal_packet()
                if signal_success:
                    self.signal_sent = True
                    print("   📋 本機已向監控端標識，後續封包將直接轉發")
            else:
                print("📋 信號已發送，跳過信號發送步驟")

            # 步驟2: 處理原始封包嵌入和轉發
            print("📦 步驟2: 嵌入並轉發封包到監控端...")
            embed_success = self._process_packet_embedding(captured_packet)

            # 更新統計
            self.processed_count += 1

            # 顯示處理結果
            print(f"\n📊 處理結果:")
            if not self.signal_sent and self.processed_count == 1:
                print(f"   信號發送: {'✅ 成功' if signal_success else '❌ 失敗'}")
            print(f"   封包轉發: {'✅ 成功' if embed_success else '❌ 失敗'}")
            print(f"   已處理封包總數: {self.processed_count}")
            print(f"   標識狀態: {'✅ 已標識' if self.signal_sent else '❌ 未標識'}")
            print(f"{'=' * 60}\n")

        except Exception as e:
            print(f"❌ 處理封包時發生錯誤: {e}")

    def _send_signal_packet(self):
        """發送信號封包到監控端"""
        try:
            target_ip = self.config["signal_target_ip"]
            target_port = self.config["signal_target_port"]
            current_uuid = self.current_uuid

            success = send_signal(target_ip, target_port, current_uuid)

            if success:
                print(f"   ✅ 信號封包已發送至監控端 {target_ip}:{target_port}")
            else:
                print(f"   ❌ 信號封包發送失敗")

            return success

        except Exception as e:
            print(f"   ❌ 發送信號封包時發生錯誤: {e}")
            return False

    def _process_packet_embedding(self, captured_packet):
        """處理封包嵌入並發送到監控端"""
        try:
            # 將PyShark封包轉換為Scapy格式
            scapy_packet = self._convert_to_scapy_packet(captured_packet)

            if scapy_packet is None:
                print("   ❌ 封包格式轉換失敗")
                return False

            # 嵌入並發送到監控端
            target_ip = self.config["embed_target_ip"]
            target_port = self.config["embed_target_port"]
            max_size = self.config.get("max_packet_size", 1400)

            success = embed_and_send_packet(scapy_packet, target_ip, target_port, max_size, uuid)

            if success:
                print(f"   ✅ 封包已嵌入並轉發至監控端 {target_ip}:{target_port}")
            else:
                print(f"   ❌ 封包嵌入和轉發失敗")

            return success

        except Exception as e:
            print(f"   ❌ 處理封包嵌入時發生錯誤: {e}")
            return False

    def _convert_to_scapy_packet(self, pyshark_packet):
        """將PyShark封包轉換為Scapy封包格式"""
        try:
            if not hasattr(pyshark_packet, 'ip'):
                print("   ⚠️  封包不包含IP層")
                return None

            src_ip = pyshark_packet.ip.src
            dst_ip = pyshark_packet.ip.dst

            # 建立基本IP封包
            scapy_packet = IP(src=src_ip, dst=dst_ip)

            # 處理TCP層
            if hasattr(pyshark_packet, 'tcp'):
                src_port = int(pyshark_packet.tcp.srcport)
                dst_port = int(pyshark_packet.tcp.dstport)
                scapy_packet = scapy_packet / TCP(sport=src_port, dport=dst_port)

                # 嘗試取得payload
                payload_data = self._extract_payload(pyshark_packet)
                if payload_data:
                    scapy_packet = scapy_packet / Raw(load=payload_data)

            print(f"   📋 封包資訊: {src_ip} -> {dst_ip} ({pyshark_packet.highest_layer})")

            return scapy_packet

        except Exception as e:
            print(f"   ❌ 封包轉換錯誤: {e}")
            return None

    def _extract_payload(self, pyshark_packet):
        """嘗試提取封包payload"""
        payload_data = ""

        try:
            # HTTP payload
            if hasattr(pyshark_packet, 'http'):
                if hasattr(pyshark_packet.http, 'request_full_uri'):
                    payload_data = pyshark_packet.http.request_full_uri
                elif hasattr(pyshark_packet.http, 'file_data'):
                    payload_data = pyshark_packet.http.file_data

            # TCP payload
            elif hasattr(pyshark_packet, 'tcp') and hasattr(pyshark_packet.tcp, 'payload'):
                payload_data = pyshark_packet.tcp.payload

            return payload_data

        except Exception as e:
            print(f"   ⚠️  提取payload時發生錯誤: {e}")
            return ""

    def shutdown(self):
        """安全關閉系統"""
        print("\n🛑 正在關閉被監控端系統...")

        self.is_running = False

        if self.packet_filter:
            self.packet_filter.stop_capture()

        # 顯示統計資訊
        print(f"\n📊 被監控端統計:")
        print(f"   已處理本機封包: {self.processed_count}")
        print(f"   信號發送狀態: {'✅ 已發送' if self.signal_sent else '❌ 未發送'}")

        if hasattr(self, 'packet_embedder'):
            stats = self.packet_embedder.get_processing_stats()
            print(f"   嵌入處理統計: {stats['total_processed']}")

        print("✅ 被監控端已安全關閉")

    def get_status(self):
        """取得系統狀態"""
        return {
            "is_running": self.is_running,
            "service_mode": "Monitored",
            "processed_count": self.processed_count,
            "signal_sent": self.signal_sent,
            "config": self.config
        }


def main():
    """主程式進入點"""
    print("=" * 60)
    print("📡 被監控端系統")
    print("   監控本機流量並轉發給監控端")
    print("=" * 60)

    # 建立處理器實例
    processor = MonitoredProcessor()



    try:
        # 啟動處理系統
        success = processor.start_processing()

        if not success:
            print("❌ 被監控端系統啟動失敗")
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