import json
import uuid
import base64
import time
import hashlib
from datetime import datetime
from scapy.all import *

class PacketEmbedder:
    def __init__(self, max_packet_size=1400, current_uuid=uuid.uuid4()):
        self.processed_packets = []
        self.max_packet_size = max_packet_size
        self.current_uuid = current_uuid

    def create_metadata(self):
        """建立新的UUID和時間戳Metadata"""
        metadata = {
            "embed_uuid": self.current_uuid, #同一個服務使用同一組UUID
            "embed_timestamp": datetime.now().isoformat(), #記錄當前時間
            "process_time": time.time() #紀錄處理時間
        }
        return metadata

    def _convert_to_json_serializable(self, obj):
        """將物件轉換為JSON可序列化的格式"""
        if hasattr(obj, '__int__'):
            # 處理FlagValue等可轉換為int的物件
            return int(obj)
        elif hasattr(obj, '__str__'):
            # 處理其他有字串表示的物件
            return str(obj)
        elif isinstance(obj, (list, tuple)):
            # tuple或是list走遞迴
            return [self._convert_to_json_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self._convert_to_json_serializable(value) for key, value in obj.items()}
        else:
            # 對於不可序列化的物件，轉換為字串
            return str(obj)

    def serialize_packet(self, packet):
        """將原始封包序列化為base64字串，保留更多資訊"""
        try:
            # print("TEST Packet content")
            # print(packet)

            # 將封包轉換為bytes，即二進制
            packet_bytes = bytes(packet)

            # 計算原始雜湊值用於驗證
            original_hash = hashlib.sha256(packet_bytes).hexdigest()

            # 編碼為base64並且使用utf-8格式
            packet_b64 = base64.b64encode(packet_bytes).decode('utf-8')

            # 記錄封包的詳細資訊
            packet_info = {
                "data": packet_b64,
                "length": len(packet_bytes),
                "original_hash": original_hash,
                "layers": [],
                "has_ether": Ether in packet, # Ethernet Layer
                "has_ip": IP in packet, # IP Layer
                "has_tcp": TCP in packet, # TCP Layer
                "summary": packet.summary() #顯示封包基本結構
            }

            # 記錄封包層級結構
            current = packet
            while current:
                layer_name = current.__class__.__name__  # 取得目前封包類別名稱
                packet_info["layers"].append(layer_name) # 將解析到的封包類別名稱加入packet_info 的 layer欄位
                if hasattr(current, 'payload') and current.payload: # Payload紀錄下一層的內容
                    current = current.payload
                else:
                    break

            print("Packet Layer Name: ")
            print(packet_info["layers"])

            # 如果有IP層，記錄詳細資訊
            if IP in packet:
                # IP 基本資訊顯示
                print("IP information")
                print(packet[IP])

                packet_info.update({
                    "original_src": str(packet[IP].src),
                    "original_dst": str(packet[IP].dst),
                    "original_protocol": int(packet[IP].proto),# 協定編號，6 表示TCP、17 表示UDP、1 表示ICMP
                    "ip_version": int(packet[IP].version), # 4表示IPv4 6表示IPv6
                    "ip_ttl": int(packet[IP].ttl) # TTL數值，表示最多能經過多少個路由器
                })
            else:
                packet_info.update({
                    "original_src": "unknown",
                    "original_dst": "unknown",
                    "original_protocol": "unknown"
                })

            # 如果有TCP層，記錄端口資訊
            if TCP in packet:
                #TCP 基本資訊
                print("TCP flags")
                print(packet[TCP].flags)

                # 處理FlagValue
                tcp_flags = packet[TCP].flags
                if hasattr(tcp_flags, '__int__'):
                    tcp_flags_value = int(tcp_flags)
                else:
                    tcp_flags_value = str(tcp_flags) #SYN 表示正在建立連線、ACK 表示風包確認收到、FIN表示關閉連線、SYN+ACK 表示伺服器回應連線請求

                packet_info.update({
                    "tcp_sport": int(packet[TCP].sport),
                    "tcp_dport": int(packet[TCP].dport),
                    "tcp_flags": tcp_flags_value,
                    "tcp_seq": int(packet[TCP].seq), # 序列號
                    "tcp_ack": int(packet[TCP].ack), # 確認號
                    "tcp_window": int(packet[TCP].window) # 接收大小
                })

            print(f"📦 封包序列化:")
            print(f"   大小: {len(packet_bytes)} bytes")
            print(f"   雜湊: {original_hash[:16]}...")
            print(f"   層級: {' / '.join(packet_info['layers'])}")
            print(f"   摘要: {packet_info['summary']}")

            return packet_info

        except Exception as e:
            print(f"封包序列化錯誤: {e}")
            import traceback
            traceback.print_exc()
            return None

    def fragment_large_payload(self, payload_json, fragment_uuid):
        """將大型 payload 切割"""
        payload_bytes = payload_json.encode('utf-8') # 將 payload json轉utf8格式
        payload_size = len(payload_bytes)

        # 計算每個切割分片的最大payload大小
        # 200為誤差值
        max_payload_per_fragment = self.max_packet_size - 200

        if payload_size <= max_payload_per_fragment: #小於最大 payload 分割大小
            return [payload_json]

        # 需要切割成多少個Partial
        fragments = []
        total_fragments = (payload_size + max_payload_per_fragment - 1) // max_payload_per_fragment

        for i in range(total_fragments):
            start_idx = i * max_payload_per_fragment #計算每個分片在原始資料中的起始索引，依據分片大小進行偏移
            end_idx = min(start_idx + max_payload_per_fragment, payload_size) #確保不超過原始資料大小
            fragment_data = payload_bytes[start_idx:end_idx] # 抓取payloads 資料

            fragment_info = {
                "fragment_uuid": fragment_uuid,
                "fragment_index": i,
                "total_fragments": total_fragments,
                "fragment_size": len(fragment_data),
                "is_last_fragment": (i == total_fragments - 1)
            }

            fragment_payload = {
                "fragment_info": fragment_info,
                "data": base64.b64encode(fragment_data).decode('utf-8')
            }

            fragments.append(json.dumps(fragment_payload))

        print(f"封包分片完成: {payload_size} bytes -> {total_fragments} 個分片")
        return fragments

    def embed_packet(self, original_packet, destination_ip, destination_port):
        """將原始封包重新包裝到新的封包中，支援分片"""
        try:
            # 建立metadata
            metadata = self.create_metadata()
            fragment_uuid = str(uuid.uuid4())

            # 序列化原始封包（包含更多資訊）
            packet_info = self.serialize_packet(original_packet)
            if packet_info is None:
                return []

            # 建立嵌入式封包的payload
            embedded_payload = {
                "metadata": metadata,
                "original_packet": packet_info,
                "embedding_info": {
                    "embedded_by": "PacketEmbedder_v2",
                    "version": "2.0",
                    "fragment_uuid": fragment_uuid,
                    "embedding_timestamp": time.time()
                }
            }

            # 將payload轉換為JSON字串 - 使用安全的序列化
            try:
                payload_json = json.dumps(embedded_payload, indent=2, default=self._convert_to_json_serializable)
            except Exception as json_error:
                print(f"JSON序列化錯誤: {json_error}")
                # 嘗試簡化payload重新序列化
                simplified_payload = {
                    "metadata": metadata,
                    "original_packet": {
                        "data": packet_info["data"],
                        "length": packet_info["length"],
                        "original_hash": packet_info["original_hash"],
                        "layers": packet_info["layers"],
                        "summary": str(packet_info["summary"])  # 強制轉換為字串
                    },
                    "embedding_info": {
                        "embedded_by": "PacketEmbedder_v2_simplified",
                        "version": "2.0",
                        "fragment_uuid": fragment_uuid,
                        "embedding_timestamp": time.time()
                    }
                }
                payload_json = json.dumps(simplified_payload, indent=2)

            # 檢查是否需要分片
            fragments = self.fragment_large_payload(payload_json, fragment_uuid)

            # 建立封包列表
            embedded_packets = []

            for fragment_data in fragments:
                # 建立新的TCP封包
                new_packet = IP(dst=destination_ip) / TCP(dport=destination_port) / Raw(load=fragment_data)
                embedded_packets.append(new_packet)

            # 記錄處理過的封包
            self.processed_packets.append({
                "original_packet_id": metadata["embed_uuid"],
                "fragment_uuid": fragment_uuid,
                "timestamp": metadata["embed_timestamp"],
                "destination": f"{destination_ip}:{destination_port}",
                "fragment_count": len(fragments),
                "original_hash": packet_info["original_hash"],
                "original_size": packet_info["length"]
            })

            print(f"封包重新包裝完成:")
            print(f"  新UUID: {metadata['embed_uuid']}")
            print(f"  分片UUID: {fragment_uuid}")
            print(f"  時間戳: {metadata['embed_timestamp']}")
            print(f"  目標: {destination_ip}:{destination_port}")
            print(f"  原始封包大小: {packet_info['length']} bytes")
            print(f"  原始雜湊: {packet_info['original_hash'][:16]}...")
            print(f"  分片數量: {len(fragments)}")

            return embedded_packets

        except Exception as e:
            print(f"封包嵌入錯誤: {e}")
            import traceback
            traceback.print_exc()
            return []

    def send_embedded_packets(self, embedded_packets, delay_between_fragments=0.001):
        if not embedded_packets:
            print("沒有封包可發送")
            return False

        try:
            success_count = 0
            for i, packet in enumerate(embedded_packets):
                print(f"🚀 發送封包 {i + 1}/{len(embedded_packets)}")
                print(f"   目標: {packet[IP].dst}:{packet[TCP].dport}")
                print(f"   大小: {len(bytes(packet))} bytes")

                if Raw in packet:
                    payload_size = len(packet[Raw].load)
                    print(f"   Payload大小: {payload_size} bytes")

                send(packet, verbose=True)
                success_count += 1

                if delay_between_fragments > 0 and i < len(embedded_packets) - 1:
                    time.sleep(delay_between_fragments)

            print(f"✅ 成功發送 {success_count}/{len(embedded_packets)} 個封包分片")
            return True

        except Exception as e:
            print(f"發送嵌入式封包錯誤: {e}")
            return False

    def extract_original_packet(self, embedded_packet):
        """從嵌入式封包中提取原始封包，改進版本"""
        try:
            if Raw in embedded_packet:
                payload = embedded_packet[Raw].load.decode('utf-8')
                embedded_data = json.loads(payload)

                # 取得原始封包資訊
                packet_info = embedded_data["original_packet"]
                original_data_b64 = packet_info["data"]
                original_bytes = base64.b64decode(original_data_b64)

                # 驗證資料完整性
                restored_hash = hashlib.sha256(original_bytes).hexdigest()
                expected_hash = packet_info.get("original_hash", "")

                if expected_hash and restored_hash != expected_hash:
                    print(f"⚠️  雜湊值不匹配!")
                    print(f"   期望: {expected_hash[:16]}...")
                    print(f"   實際: {restored_hash[:16]}...")

                # 智能重建封包 - 根據層級資訊決定如何重建
                layers = packet_info.get("layers", [])

                if "Ether" in layers:
                    original_packet = Ether(original_bytes)
                elif "IP" in layers:
                    original_packet = IP(original_bytes)
                else:
                    original_packet = Ether(original_bytes)

                print("原始封包提取成功:")
                print(f"  UUID: {embedded_data['metadata']['embed_uuid']}")
                print(f"  時間戳: {embedded_data['metadata']['embed_timestamp']}")
                print(f"  原始大小: {packet_info['length']} bytes")
                print(f"  原始雜湊: {packet_info.get('original_hash', 'unknown')[:16]}...")
                print(f"  重建雜湊: {restored_hash[:16]}...")
                print(f"  層級結構: {' / '.join(layers)}")

                return original_packet, embedded_data["metadata"]
            else:
                print("封包中沒有Raw層")
                return None, None

        except Exception as e:
            print(f"提取原始封包錯誤: {e}")
            return None, None

    def get_processing_stats(self):
        """取得處理統計資料"""
        return {
            "total_processed": len(self.processed_packets),
            "processed_packets": self.processed_packets
        }

# 向後相容的外部調用函數
def embed_and_send_packet(original_packet, destination_ip, destination_port, max_packet_size=1400, current_uuid=uuid.uuid4()):
    """嵌入並發送封包的便利函數"""
    embedder = PacketEmbedder(max_packet_size, current_uuid)
    embedded_packets = embedder.embed_packet(original_packet, destination_ip, destination_port)

    if embedded_packets:
        return embedder.send_embedded_packets(embedded_packets)
    return False


if __name__ == "__main__":
    # 測試用途
    embedder = PacketEmbedder()

    # 建立測試封包
    test_packet = IP(dst="8.8.8.8") / TCP(dport=80) / Raw(load="Test data")

    # 嵌入並發送
    result = embed_and_send_packet(test_packet, "127.0.0.1", 9090)
    print(f"處理結果: {result}")