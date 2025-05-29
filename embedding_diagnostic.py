#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import hashlib
from scapy.all import *

class EmbeddingDiagnostic:
    """診斷Embedding和還原過程的問題"""
    
    def __init__(self):
        self.issues_found = []
    
    def diagnose_pcap_files(self, incoming_pcap, embedded_pcap, restored_pcap):
        """診斷三個PCAP檔案的問題"""
        print("🔍 開始診斷Embedding還原問題...")
        print("=" * 60)
        
        # 1. 讀取並分析PCAP檔案
        incoming_packets = rdpcap(incoming_pcap)
        embedded_packets = rdpcap(embedded_pcap)
        restored_packets = rdpcap(restored_pcap)
        
        print(f"📂 檔案載入:")
        print(f"   來源封包: {len(incoming_packets)} 個")
        print(f"   嵌入封包: {len(embedded_packets)} 個")  
        print(f"   還原封包: {len(restored_packets)} 個")
        
        # 2. 分析嵌入封包格式
        self._analyze_embedded_packets(embedded_packets[:5])  # 只分析前5個
        
        # 3. 分析還原封包
        self._analyze_restored_packets(restored_packets[:5])
        
        # 4. 比較原始和還原封包的雜湊值
        self._compare_packet_hashes(incoming_packets[:10], restored_packets[:10])
        
        # 5. 測試embedding和還原流程
        self._test_embedding_restoration_flow(incoming_packets[0] if incoming_packets else None)
        
        # 6. 總結問題
        self._summarize_issues()
    
    def _analyze_embedded_packets(self, packets):
        """分析嵌入封包的格式和內容"""
        print("\n🔍 分析嵌入封包格式:")
        
        for i, packet in enumerate(packets):
            print(f"\n封包 {i+1}:")
            
            if Raw not in packet:
                print("   ❌ 沒有Raw payload")
                self.issues_found.append("嵌入封包缺少Raw payload")
                continue
            
            try:
                payload = packet[Raw].load.decode('utf-8')
                print(f"   Payload大小: {len(payload)} bytes")
                
                # 嘗試解析JSON
                try:
                    data = json.loads(payload)
                    print("   ✅ JSON格式正確")
                    
                    # 檢查必要欄位
                    if "fragment_info" in data:
                        print("   📦 這是分片封包")
                        fragment_info = data["fragment_info"]
                        print(f"      UUID: {fragment_info.get('fragment_uuid', 'missing')[:16]}...")
                        print(f"      分片: {fragment_info.get('fragment_index', 'missing')}/{fragment_info.get('total_fragments', 'missing')}")
                    elif "metadata" in data and "original_packet" in data:
                        print("   📋 這是完整封包")
                        metadata = data["metadata"]
                        original = data["original_packet"]
                        print(f"      UUID: {metadata.get('embed_uuid', 'missing')[:16]}...")
                        print(f"      原始大小: {original.get('length', 'missing')} bytes")
                        print(f"      原始來源: {original.get('original_src', 'missing')}")
                        print(f"      原始目標: {original.get('original_dst', 'missing')}")
                    else:
                        print("   ❌ 缺少必要欄位")
                        self.issues_found.append("嵌入封包缺少必要欄位")
                        
                except json.JSONDecodeError as e:
                    print(f"   ❌ JSON解析失敗: {e}")
                    self.issues_found.append("嵌入封包JSON格式錯誤")
                    print(f"   前100字元: {payload[:100]}")
                    
            except UnicodeDecodeError:
                print("   ❌ UTF-8解碼失敗")
                self.issues_found.append("嵌入封包編碼問題")
    
    def _analyze_restored_packets(self, packets):
        """分析還原封包"""
        print("\n🔍 分析還原封包:")
        
        for i, packet in enumerate(packets):
            print(f"\n還原封包 {i+1}:")
            print(f"   大小: {len(bytes(packet))} bytes")
            print(f"   雜湊: {hashlib.sha256(bytes(packet)).hexdigest()[:16]}...")
            
            if IP in packet:
                print(f"   IP: {packet[IP].src} -> {packet[IP].dst}")
                
            if TCP in packet:
                print(f"   TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
                
            if Raw in packet:
                print(f"   Payload: {len(packet[Raw].load)} bytes")
    
    def _compare_packet_hashes(self, incoming_packets, restored_packets):
        """比較原始和還原封包的雜湊值"""
        print("\n🔍 雜湊值比較分析:")
        
        incoming_hashes = []
        for packet in incoming_packets:
            hash_val = hashlib.sha256(bytes(packet)).hexdigest()
            incoming_hashes.append({
                'hash': hash_val,
                'size': len(bytes(packet)),
                'summary': packet.summary()
            })
        
        restored_hashes = []
        for packet in restored_packets:
            hash_val = hashlib.sha256(bytes(packet)).hexdigest()
            restored_hashes.append({
                'hash': hash_val,
                'size': len(bytes(packet)),
                'summary': packet.summary()
            })
        
        print(f"\n原始封包雜湊 (前5個):")
        for i, info in enumerate(incoming_hashes[:5]):
            print(f"   {i+1}. {info['hash'][:16]}... ({info['size']} bytes)")
        
        print(f"\n還原封包雜湊 (前5個):")
        for i, info in enumerate(restored_hashes[:5]):
            print(f"   {i+1}. {info['hash'][:16]}... ({info['size']} bytes)")
        
        # 檢查是否有任何匹配
        incoming_hash_set = {info['hash'] for info in incoming_hashes}
        restored_hash_set = {info['hash'] for info in restored_hashes}
        
        matches = incoming_hash_set.intersection(restored_hash_set)
        print(f"\n匹配的雜湊值: {len(matches)} 個")
        
        if len(matches) == 0:
            self.issues_found.append("沒有任何雜湊值匹配 - 封包還原可能有問題")
    
    def _test_embedding_restoration_flow(self, sample_packet):
        """測試完整的embedding和還原流程"""
        if not sample_packet:
            return
            
        print("\n🧪 測試embedding和還原流程:")
        
        try:
            # 模擬Embedding過程
            from Embedding import PacketEmbedder
            embedder = PacketEmbedder()
            
            print("   1. 測試封包序列化...")
            serialized = embedder.serialize_packet(sample_packet)
            if serialized:
                print("   ✅ 序列化成功")
            else:
                print("   ❌ 序列化失敗")
                self.issues_found.append("封包序列化失敗")
                return
            
            print("   2. 測試封包嵌入...")
            embedded_packets = embedder.embed_packet(sample_packet, "127.0.0.1", 9999)
            if embedded_packets:
                print(f"   ✅ 嵌入成功，產生 {len(embedded_packets)} 個封包")
            else:
                print("   ❌ 嵌入失敗")
                self.issues_found.append("封包嵌入失敗")
                return
            
            print("   3. 測試封包還原...")
            
            # 模擬還原過程
            for embedded_packet in embedded_packets:
                if Raw in embedded_packet:
                    try:
                        payload = embedded_packet[Raw].load.decode('utf-8')
                        embedded_data = json.loads(payload)
                        
                        if "fragment_info" not in embedded_data:
                            # 完整封包
                            original_data_b64 = embedded_data['original_packet']['data']
                            original_bytes = base64.b64decode(original_data_b64)
                            restored_packet = Ether(original_bytes)
                            
                            # 比較雜湊值
                            original_hash = hashlib.sha256(bytes(sample_packet)).hexdigest()
                            restored_hash = hashlib.sha256(bytes(restored_packet)).hexdigest()
                            
                            print(f"   原始雜湊: {original_hash[:16]}...")
                            print(f"   還原雜湊: {restored_hash[:16]}...")
                            
                            if original_hash == restored_hash:
                                print("   ✅ 還原成功，雜湊值匹配")
                            else:
                                print("   ❌ 還原失敗，雜湊值不匹配")
                                self.issues_found.append("測試還原時雜湊值不匹配")
                                
                                # 詳細分析差異
                                self._analyze_packet_differences(sample_packet, restored_packet)
                            
                            break
                            
                    except Exception as e:
                        print(f"   ❌ 還原過程錯誤: {e}")
                        self.issues_found.append(f"還原過程錯誤: {e}")
        
        except Exception as e:
            print(f"   ❌ 測試流程錯誤: {e}")
            self.issues_found.append(f"測試流程錯誤: {e}")
    
    def _analyze_packet_differences(self, original, restored):
        """分析原始和還原封包的差異"""
        print("\n🔍 封包差異分析:")
        
        original_bytes = bytes(original)
        restored_bytes = bytes(restored)
        
        print(f"   原始封包大小: {len(original_bytes)} bytes")
        print(f"   還原封包大小: {len(restored_bytes)} bytes")
        
        if len(original_bytes) != len(restored_bytes):
            print("   ❌ 封包大小不同")
            self.issues_found.append("還原封包大小與原始封包不同")
        
        # 比較前50個位元組
        min_len = min(len(original_bytes), len(restored_bytes))
        for i in range(min(50, min_len)):
            if original_bytes[i] != restored_bytes[i]:
                print(f"   ❌ 位元組 {i}: 原始={original_bytes[i]:02x}, 還原={restored_bytes[i]:02x}")
                break
        
        # 分析封包層級
        print("\n   層級比較:")
        print(f"   原始: {original.summary()}")
        print(f"   還原: {restored.summary()}")
    
    def _summarize_issues(self):
        """總結發現的問題"""
        print("\n" + "=" * 60)
        print("🎯 診斷結果總結")
        print("=" * 60)
        
        if not self.issues_found:
            print("✅ 沒有發現明顯問題")
        else:
            print(f"❌ 發現 {len(self.issues_found)} 個問題:")
            for i, issue in enumerate(self.issues_found, 1):
                print(f"   {i}. {issue}")
        
        print("\n🔧 建議修復措施:")
        
        if any("雜湊值不匹配" in issue for issue in self.issues_found):
            print("   1. 檢查封包重建過程是否完整保留所有欄位")
            print("   2. 確認Ether層的重建是否正確")
            print("   3. 檢查是否有額外的header被添加或移除")
        
        if any("JSON" in issue for issue in self.issues_found):
            print("   4. 檢查嵌入封包的JSON格式和編碼")
        
        if any("分片" in issue for issue in self.issues_found):
            print("   5. 檢查分片重組邏輯")
        
        print("   6. 建議在Embedding.py和Analyst.py中增加更多除錯輸出")
        print("   7. 考慮使用相同的封包重建方法")

# 使用方法
def main():
    print("🔍 Embedding診斷工具")
    print("=" * 60)
    
    # 請修改為你的實際檔案路徑
    incoming_pcap = "incoming_packets_5006_20250526_212452.pcap"
    embedded_pcap = "embedded_packets_20_20250526_212452.pcap"
    restored_pcap = "restored_packets_20250526_212452.pcap"
    
    diagnostic = EmbeddingDiagnostic()
    
    try:
        diagnostic.diagnose_pcap_files(incoming_pcap, embedded_pcap, restored_pcap)
    except FileNotFoundError as e:
        print(f"❌ 檔案未找到: {e}")
        print("請確認PCAP檔案路徑正確")
    except Exception as e:
        print(f"❌ 診斷過程發生錯誤: {e}")

if __name__ == "__main__":
    main()