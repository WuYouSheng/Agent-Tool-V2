#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import uuid
import os
import time
from datetime import datetime
from pathlib import Path
import threading


class Recorder:
    def __init__(self, save_path="./", current_uuid=None):
        """
        初始化記錄器

        Args:
            save_path (str): 儲存路徑，預設為當前目錄
            current_uuid (uuid): 服務的UUID，如果未提供會自動生成
        """
        self.save_path = Path(save_path)
        self.record_uuid = current_uuid if current_uuid else uuid.uuid4()
        self.serial_counter = 0  # 封包序列號計數器
        self.records = []  # 記錄列表
        self.lock = threading.Lock()  # 執行緒鎖，確保多執行緒安全

        # 確保儲存目錄存在
        self.save_path.mkdir(parents=True, exist_ok=True)

        # 建立記錄檔案路徑
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.json_filename = f"embedded_packets_record_{timestamp}.json"
        self.json_filepath = self.save_path / self.json_filename

        print(f"記錄器初始化完成:")
        print(f"  服務UUID: {self.record_uuid}")
        print(f"  儲存路徑: {self.json_filepath}")

    def record_embedded_packet(self, embedded_packet, original_packet_info=None, metadata=None, fragment_info=None):
        """
        記錄嵌入式封包資訊

        Args:
            embedded_packet: 嵌入式封包（Scapy封包格式）
            original_packet_info (dict): 原始封包資訊
            metadata (dict): 封包的metadata資訊
            fragment_info (dict): 分片資訊（如果是分片封包）
        """
        try:
            with self.lock:
                self.serial_counter += 1

                # 建立記錄項目
                record_entry = self._create_record_entry(
                    embedded_packet,
                    original_packet_info,
                    metadata,
                    fragment_info
                )

                # 加入記錄列表
                self.records.append(record_entry)

                # 即時儲存到JSON檔案
                self._save_to_json()

                print(f"📝 封包記錄完成 (序號: {self.serial_counter})")
                print(f"   ServiceID: {record_entry['ServiceID']}")
                print(f"   目標: {record_entry['DestinationIP']}:{record_entry['DestinationPort']}")

                return True

        except Exception as e:
            print(f"❌ 記錄封包時發生錯誤: {e}")
            return False

    def _create_record_entry(self, embedded_packet, original_packet_info, metadata, fragment_info):
        """
        建立記錄項目

        Returns:
            dict: 包含所有必要欄位的記錄項目
        """
        # 從embedded_packet提取基本資訊
        source_ip = "unknown"
        source_port = "unknown"
        destination_ip = "unknown"
        destination_port = "unknown"

        try:
            if hasattr(embedded_packet, 'src'):
                source_ip = str(embedded_packet.src)
            elif hasattr(embedded_packet, '__getitem__') and 'IP' in str(embedded_packet):
                # 嘗試從Scapy封包中提取IP資訊
                if embedded_packet.haslayer('IP'):
                    source_ip = str(embedded_packet['IP'].src)
                    destination_ip = str(embedded_packet['IP'].dst)

            if hasattr(embedded_packet, 'dport'):
                destination_port = str(embedded_packet.dport)
            elif hasattr(embedded_packet, '__getitem__') and 'TCP' in str(embedded_packet):
                if embedded_packet.haslayer('TCP'):
                    source_port = str(embedded_packet['TCP'].sport)
                    destination_port = str(embedded_packet['TCP'].dport)

        except Exception as e:
            print(f"⚠️  提取封包資訊時發生錯誤: {e}")

        # 確定ServiceID（UUID）
        service_id = str(self.record_uuid)

        # 如果有metadata，使用其中的UUID
        if metadata and 'embed_uuid' in metadata:
            service_id = str(metadata['embed_uuid'])

        # 如果是分片封包，使用原始UUID
        if fragment_info and 'fragment_uuid' in fragment_info:
            # 分片封包使用原始服務的UUID
            service_id = str(self.record_uuid)

        # 從原始封包資訊提取來源資訊
        if original_packet_info:
            if 'original_src' in original_packet_info:
                source_ip = str(original_packet_info['original_src'])
            if 'original_dst' in original_packet_info:
                # 注意：這裡記錄的是原始封包的目標，現在變成了嵌入封包的來源參考
                pass
            if 'tcp_sport' in original_packet_info:
                source_port = str(original_packet_info['tcp_sport'])

        # 建立記錄項目
        record_entry = {
            "ServiceID": service_id,
            "Serial_Number": self.serial_counter,
            "SourceIP": source_ip,
            "SourcePort": source_port,
            "DestinationIP": destination_ip,
            "DestinationPort": destination_port,
            "封包攔截時間": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],

            # 額外的詳細資訊
            "metadata": {
                "original_packet_info": original_packet_info,
                "embed_metadata": metadata,
                "fragment_info": fragment_info,
                "packet_size": len(bytes(embedded_packet)) if hasattr(embedded_packet, '__len__') else 0,
                "is_fragment": fragment_info is not None,
                "record_timestamp": time.time()
            }
        }

        return record_entry

    def _save_to_json(self):
        """儲存記錄到JSON檔案"""
        try:
            # 建立輸出資料結構
            output_data = {
                "recorder_info": {
                    "service_uuid": str(self.record_uuid),
                    "total_records": len(self.records),
                    "created_time": datetime.now().isoformat(),
                    "json_filename": self.json_filename
                },
                "packet_records": self.records
            }

            # 寫入JSON檔案
            with open(self.json_filepath, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, ensure_ascii=False, indent=2, default=str)

        except Exception as e:
            print(f"❌ 儲存JSON檔案時發生錯誤: {e}")

    def record_from_embedding_result(self, embedding_result, embedded_packets):
        """
        從Embedding模組的結果記錄封包

        Args:
            embedding_result (dict): 從PacketEmbedder.processed_packets獲得的結果
            embedded_packets (list): 嵌入式封包列表
        """
        try:
            if not embedded_packets:
                print("⚠️  沒有嵌入式封包可記錄")
                return False

            # 記錄每個嵌入式封包
            for i, packet in enumerate(embedded_packets):
                # 建立分片資訊（如果適用）
                fragment_info = None
                if len(embedded_packets) > 1:
                    fragment_info = {
                        "fragment_uuid": embedding_result.get('fragment_uuid'),
                        "fragment_index": i,
                        "total_fragments": len(embedded_packets),
                        "is_last_fragment": (i == len(embedded_packets) - 1)
                    }

                # 建立metadata
                metadata = {
                    "embed_uuid": embedding_result.get('original_packet_id'),
                    "embed_timestamp": embedding_result.get('timestamp'),
                    "destination": embedding_result.get('destination'),
                    "original_hash": embedding_result.get('original_hash'),
                    "original_size": embedding_result.get('original_size')
                }

                # 記錄封包
                self.record_embedded_packet(
                    packet,
                    original_packet_info=None,  # 可以從embedding_result中提取
                    metadata=metadata,
                    fragment_info=fragment_info
                )

            return True

        except Exception as e:
            print(f"❌ 從嵌入結果記錄封包時發生錯誤: {e}")
            return False

    def get_statistics(self):
        """取得記錄統計資訊"""
        with self.lock:
            fragment_count = sum(1 for record in self.records
                                 if record['metadata']['is_fragment'])

            return {
                "total_records": len(self.records),
                "fragment_records": fragment_count,
                "non_fragment_records": len(self.records) - fragment_count,
                "service_uuid": str(self.record_uuid),
                "json_filepath": str(self.json_filepath),
                "current_serial": self.serial_counter
            }

    def export_csv(self, csv_filename=None):
        """匯出記錄到CSV檔案"""
        try:
            import csv

            if not csv_filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                csv_filename = f"embedded_packets_record_{timestamp}.csv"

            csv_filepath = self.save_path / csv_filename

            with open(csv_filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'ServiceID', 'Serial_Number', 'SourceIP', 'SourcePort',
                    'DestinationIP', 'DestinationPort', '封包攔截時間'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for record in self.records:
                    # 只寫入主要欄位到CSV
                    csv_record = {field: record.get(field, '') for field in fieldnames}
                    writer.writerow(csv_record)

            print(f"✅ CSV檔案已匯出: {csv_filepath}")
            return str(csv_filepath)

        except ImportError:
            print("❌ 無法匯入csv模組")
            return None
        except Exception as e:
            print(f"❌ 匯出CSV時發生錯誤: {e}")
            return None


def main():
    """測試用主程式"""
    print("🧪 測試Recorder模組...")

    # 建立測試記錄器
    test_uuid = uuid.uuid4()
    recorder = Recorder(save_path="./test_records", current_uuid=test_uuid)

    # 模擬測試資料
    test_metadata = {
        "embed_uuid": test_uuid,
        "embed_timestamp": datetime.now().isoformat(),
        "process_time": time.time()
    }

    # 注意：這裡使用模擬封包資料，實際使用時會是Scapy封包對象
    class MockPacket:
        def __init__(self):
            self.src = "192.168.1.100"
            self.dst = "10.0.0.1"
            self.sport = 12345
            self.dport = 8080

        def __len__(self):
            return 1024

    mock_packet = MockPacket()

    # 記錄測試封包
    success = recorder.record_embedded_packet(
        mock_packet,
        original_packet_info={
            "original_src": "192.168.1.100",
            "original_dst": "8.8.8.8",
            "tcp_sport": 12345,
            "tcp_dport": 80
        },
        metadata=test_metadata
    )

    if success:
        print("✅ 測試記錄成功")

        # 顯示統計資訊
        stats = recorder.get_statistics()
        print(f"📊 統計資訊: {stats}")

        # 嘗試匯出CSV
        csv_path = recorder.export_csv()
        if csv_path:
            print(f"📄 CSV匯出成功: {csv_path}")
    else:
        print("❌ 測試記錄失敗")


if __name__ == "__main__":
    main()