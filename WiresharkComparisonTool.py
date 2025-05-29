#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import base64
import hashlib
import time
from datetime import datetime
from scapy.all import *

sys.path.append('Monitored')
sys.path.append('Surveiling')

class WiresharkComparisonTool:
    def __init__(self):
        self.original_packets = []
        self.restored_packets = []
        self.embedded_packets = []
        
    def capture_original_packets(self, interface="eth0", filter_port=80, duration=30):
        """捕獲Filter.py攔截的原始封包並保存為PCAP"""
        print(f"🔍 步驟1: 捕獲Filter.py攔截的原始封包")
        print(f"   介面: {interface}")
        print(f"   端口: {filter_port}")
        print(f"   時長: {duration}秒")
        print(f"   說明: 這些是Filter.py會攔截的封包")
        
        captured_packets = []
        
        def packet_handler(packet):
            if TCP in packet and packet[TCP].sport == filter_port:
                # 記錄封包資訊
                packet_info = {
                    'timestamp': time.time(),
                    'packet': packet,
                    'size': len(bytes(packet)),
                    'hash': hashlib.sha256(bytes(packet)).hexdigest(),
                    'summary': packet.summary()
                }
                captured_packets.append(packet_info)
                self.original_packets.append(packet)
                
                print(f"📦 原始封包 #{len(captured_packets)}: {packet.summary()}")
                print(f"   大小: {packet_info['size']} bytes")
                print(f"   雜湊: {packet_info['hash'][:16]}...")
        
        try:
            filter_expr = f"tcp and src port {filter_port}"
            print(f"🔍 開始捕獲 (過濾器: {filter_expr})...")
            sniff(filter=filter_expr, prn=packet_handler, timeout=duration, iface=interface)
            
            # 保存原始封包為PCAP
            if self.original_packets:
                original_pcap = f"original_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                wrpcap(original_pcap, self.original_packets)
                print(f"💾 原始封包已保存: {original_pcap}")
                print(f"   📊 總共捕獲: {len(self.original_packets)} 個封包")
                return original_pcap
            else:
                print("❌ 沒有捕獲到任何封包")
                return None
                
        except Exception as e:
            print(f"❌ 捕獲失敗: {e}")
            return None
    
    def capture_embedded_packets(self, embed_port=9090, duration=30):
        """捕獲嵌入封包並即時還原"""
        print(f"\n🔍 步驟2: 捕獲Analyst.py接收的嵌入封包")
        print(f"   端口: {embed_port}")
        print(f"   時長: {duration}秒")
        print(f"   說明: 這些是經過嵌入處理的封包")
        
        embedded_packets = []
        restored_packets = []
        
        def packet_handler(packet):
            if TCP in packet and packet[TCP].dport == embed_port and Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8')
                    embedded_data = json.loads(payload)
                    
                    print(f"📥 嵌入封包 #{len(embedded_packets)+1}")
                    print(f"   Payload大小: {len(payload)} bytes")
                    
                    # 嘗試還原原始封包
                    if self._is_complete_packet(embedded_data):
                        restored_packet = self._restore_original_packet(embedded_data)
                        if restored_packet:
                            restored_packets.append(restored_packet)
                            self.restored_packets.append(restored_packet)
                            
                            # 計算還原封包資訊
                            restored_hash = hashlib.sha256(bytes(restored_packet)).hexdigest()
                            print(f"   ✅ 成功還原封包")
                            print(f"   還原雜湊: {restored_hash[:16]}...")
                            print(f"   還原摘要: {restored_packet.summary()}")
                    
                    embedded_packets.append(packet)
                    self.embedded_packets.append(packet)
                    
                except Exception as e:
                    print(f"   ❌ 處理嵌入封包失敗: {e}")
        
        try:
            filter_expr = f"tcp and dst port {embed_port}"
            print(f"🔍 開始監聽 (過濾器: {filter_expr})...")
            sniff(filter=filter_expr, prn=packet_handler, timeout=duration)
            
            # 保存嵌入封包和還原封包為PCAP
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if embedded_packets:
                embedded_pcap = f"embedded_packets_{timestamp}.pcap"
                wrpcap(embedded_pcap, embedded_packets)
                print(f"💾 嵌入封包已保存: {embedded_pcap}")
            
            if restored_packets:
                restored_pcap = f"restored_packets_{timestamp}.pcap"
                wrpcap(restored_pcap, restored_packets)
                print(f"💾 還原封包已保存: {restored_pcap}")
                print(f"   📊 成功還原: {len(restored_packets)} 個封包")
                return restored_pcap
            else:
                print("❌ 沒有成功還原任何封包")
                return None
                
        except Exception as e:
            print(f"❌ 監聽失敗: {e}")
            return None
    
    def _is_complete_packet(self, embedded_data):
        """檢查是否為完整封包 (非分片)"""
        return ('metadata' in embedded_data and 
                'original_packet' in embedded_data and 
                'fragment_info' not in embedded_data)
    
    def _restore_original_packet(self, embedded_data):
        """還原原始封包"""
        try:
            original_packet_data = embedded_data['original_packet']
            original_bytes = base64.b64decode(original_packet_data['data'])
            restored_packet = Ether(original_bytes)
            return restored_packet
        except Exception as e:
            print(f"   還原錯誤: {e}")
            return None
    
    def perform_direct_comparison(self):
        """直接比較原始封包和還原封包"""
        print(f"\n🔍 步驟3: 直接比較分析")
        print("=" * 50)
        
        if not self.original_packets or not self.restored_packets:
            print("❌ 缺少原始封包或還原封包")
            return
        
        print(f"📊 封包數量:")
        print(f"   原始封包: {len(self.original_packets)} 個")
        print(f"   還原封包: {len(self.restored_packets)} 個")
        
        # 建立雜湊索引
        original_hashes = {}
        for i, packet in enumerate(self.original_packets):
            packet_hash = hashlib.sha256(bytes(packet)).hexdigest()
            original_hashes[packet_hash] = (i, packet)
        
        restored_hashes = {}
        for i, packet in enumerate(self.restored_packets):
            packet_hash = hashlib.sha256(bytes(packet)).hexdigest()
            restored_hashes[packet_hash] = (i, packet)
        
        # 找出匹配的封包
        perfect_matches = []
        original_only = []
        restored_only = []
        
        for hash_val, (idx, packet) in original_hashes.items():
            if hash_val in restored_hashes:
                perfect_matches.append((hash_val, idx, restored_hashes[hash_val][0]))
            else:
                original_only.append((hash_val, idx, packet))
        
        for hash_val, (idx, packet) in restored_hashes.items():
            if hash_val not in original_hashes:
                restored_only.append((hash_val, idx, packet))
        
        print(f"\n📋 比較結果:")
        print(f"   ✅ 完美匹配: {len(perfect_matches)} 個")
        print(f"   ⚠️  僅在原始: {len(original_only)} 個")
        print(f"   ⚠️  僅在還原: {len(restored_only)} 個")
        
        # 顯示完美匹配的詳細資訊
        if perfect_matches:
            print(f"\n🎯 完美匹配封包詳細:")
            for i, (hash_val, orig_idx, rest_idx) in enumerate(perfect_matches[:3]):
                print(f"   匹配 {i+1}:")
                print(f"     雜湊: {hash_val[:16]}...")
                print(f"     原始位置: #{orig_idx+1}")
                print(f"     還原位置: #{rest_idx+1}")
        
        # 計算成功率
        if len(self.original_packets) > 0:
            success_rate = (len(perfect_matches) / len(self.original_packets)) * 100
            print(f"\n📈 還原成功率: {success_rate:.1f}%")
            
            if success_rate == 100:
                print("🎉 完美！所有封包都正確還原")
            elif success_rate >= 90:
                print("✅ 優秀！大部分封包正確還原")
            elif success_rate >= 70:
                print("⚠️  良好，但有部分封包遺失")
            else:
                print("❌ 需要檢查，還原率過低")
    
    def generate_wireshark_analysis_guide(self, original_pcap, restored_pcap):
        """生成Wireshark分析指南"""
        print(f"\n📋 Wireshark分析指南")
        print("=" * 50)
        
        guide_content = f"""
# Wireshark封包比較分析指南

## 📁 檔案說明
- **原始封包**: {original_pcap}
  (Filter.py攔截的封包，這是系統輸入)
  
- **還原封包**: {restored_pcap}  
  (Analyst.py還原的封包，這是系統輸出)

## 🔍 Wireshark比較步驟

### 步驟1: 開啟檔案
1. 啟動Wireshark
2. 開啟原始封包檔案: File → Open → {original_pcap}
3. 另開視窗載入還原封包: File → Open in New Window → {restored_pcap}

### 步驟2: 基本比較
1. **封包數量比較**:
   - 原始檔案應該有 {len(self.original_packets)} 個封包
   - 還原檔案應該有 {len(self.restored_packets)} 個封包
   
2. **封包大小比較**:
   - 在Statistics → Packet Lengths 查看分布
   - 兩個檔案的分布應該相似

### 步驟3: 詳細比較
1. **選擇相同位置的封包**:
   - 在兩個視窗中選擇封包#1
   - 比較Frame、Ethernet、IP、TCP層

2. **檢查關鍵欄位**:
   - IP位址 (src/dst)
   - TCP端口 (src/dst)  
   - Sequence numbers
   - TCP Payload

3. **使用Follow Stream**:
   - 右鍵封包 → Follow → TCP Stream
   - 比較兩個stream的內容

### 步驟4: 自動化比較
1. **使用Wireshark命令列**:
```bash
# 比較兩個檔案的統計資訊
tshark -r {original_pcap} -q -z conv,tcp
tshark -r {restored_pcap} -q -z conv,tcp

# 提取封包摘要
tshark -r {original_pcap} -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.len
tshark -r {restored_pcap} -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.len
```

### 步驟5: 驗證點
✅ **完全一致的封包應該有**:
- 相同的IP位址和端口
- 相同的TCP序列號  
- 相同的Payload內容
- 相同的封包大小

⚠️  **可能的差異** (這些是正常的):
- 時間戳 (capture time)
- Frame number
- 網路介面資訊

❌ **不應該有的差異**:
- IP/TCP header內容
- Payload資料
- 封包大小

## 🎯 預期結果
如果Agent-Tool-V2運作正常，您應該看到:
- 兩個PCAP檔案的封包內容完全相同
- 除了時間戳外，所有欄位都匹配
- TCP Stream內容100%相同

## 🔧 問題診斷
如果發現差異:
1. 檢查是否為時間戳等正常差異
2. 確認IP/TCP層是否完全相同
3. 比較Payload的hex數據
4. 檢查封包大小是否一致
"""
        
        # 保存指南到檔案
        guide_filename = f"wireshark_analysis_guide_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(guide_filename, 'w', encoding='utf-8') as f:
            f.write(guide_content)
        
        print(f"📄 Wireshark分析指南已保存: {guide_filename}")
        print("\n💡 建議分析步驟:")
        print("1. 在Wireshark中打開兩個PCAP檔案")
        print("2. 比較相同位置的封包")
        print("3. 使用Follow TCP Stream比較內容")
        print("4. 檢查統計資訊是否相似")
        
        return guide_filename

def main():
    """主程式"""
    print("🔍 Wireshark封包比較工具")
    print("=" * 60)
    print("此工具將幫助您驗證Filter.py攔截的封包與Analyst.py還原的封包是否完全一致")
    
    tool = WiresharkComparisonTool()
    
    print("\n請確保:")
    print("1. Filter.py正在監聽指定端口")
    print("2. Analyst.py正在接收嵌入封包")
    print("3. 有適當的網路流量通過")
    
    # 設定參數
    filter_port = int(input("\n請輸入Filter.py監聽的端口 (預設80): ") or "80")
    embed_port = int(input("請輸入Analyst.py監聽的端口 (預設9090): ") or "9090")
    interface = input("請輸入網路介面 (預設eth0): ") or "eth0"
    duration = int(input("請輸入捕獲時長秒數 (預設30): ") or "30")
    
    try:
        print(f"\n🚀 開始比較測試...")
        
        # 步驟1: 捕獲原始封包
        print(f"\n" + "="*60)
        original_pcap = tool.capture_original_packets(interface, filter_port, duration)
        
        if not original_pcap:
            print("❌ 沒有捕獲到原始封包，請檢查Filter.py是否正在運行")
            return
        
        # 短暫等待
        print(f"\n⏱️  等待5秒讓嵌入封包傳輸...")
        time.sleep(5)
        
        # 步驟2: 捕獲並還原嵌入封包
        print(f"\n" + "="*60)
        restored_pcap = tool.capture_embedded_packets(embed_port, duration)
        
        if not restored_pcap:
            print("❌ 沒有還原任何封包，請檢查Analyst.py是否正在運行")
            return
        
        # 步驟3: 直接比較
        tool.perform_direct_comparison()
        
        # 步驟4: 生成Wireshark分析指南
        print(f"\n" + "="*60)
        guide_file = tool.generate_wireshark_analysis_guide(original_pcap, restored_pcap)
        
        print(f"\n✅ 比較測試完成！")
        print(f"📁 產生的檔案:")
        print(f"   - {original_pcap} (原始封包)")
        print(f"   - {restored_pcap} (還原封包)")
        print(f"   - {guide_file} (Wireshark分析指南)")
        
        print(f"\n🎯 下一步:")
        print(f"1. 在Wireshark中打開兩個PCAP檔案")
        print(f"2. 按照分析指南進行詳細比較")
        print(f"3. 驗證封包內容是否完全一致")
        
    except KeyboardInterrupt:
        print("\n⚠️  測試被中斷")
    except Exception as e:
        print(f"❌ 測試過程發生錯誤: {e}")

if __name__ == "__main__":
    main()