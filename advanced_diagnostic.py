#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import hashlib
from scapy.all import *
from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime

class AdvancedPacketDiagnostic:
    """深入診斷封包流和時間同步問題"""
    
    def __init__(self):
        self.issues_found = []
        self.recommendations = []
    
    def analyze_packet_flow_timing(self, incoming_pcap, embedded_pcap, restored_pcap):
        """分析封包流的時間同步問題"""
        print("🔍 深入診斷封包流時間同步問題...")
        print("=" * 70)
        
        # 讀取PCAP檔案
        try:
            incoming_packets = rdpcap(incoming_pcap)
            embedded_packets = rdpcap(embedded_pcap)
            restored_packets = rdpcap(restored_pcap)
            
            print(f"📂 檔案載入成功:")
            print(f"   來源封包: {len(incoming_packets)} 個")
            print(f"   嵌入封包: {len(embedded_packets)} 個")
            print(f"   還原封包: {len(restored_packets)} 個")
            
        except Exception as e:
            print(f"❌ 檔案載入失敗: {e}")
            return
        
        # 1. 時間分析
        self._analyze_packet_timing(incoming_packets, embedded_packets)
        
        # 2. 封包大小分布分析
        self._analyze_packet_size_distribution(incoming_packets, embedded_packets, restored_packets)
        
        # 3. 封包內容分析
        self._analyze_packet_content_patterns(incoming_packets, embedded_packets)
        
        # 4. 嵌入封包解析分析
        self._analyze_embedded_packet_parsing(embedded_packets)
        
        # 5. 生成改善建議
        self._generate_improvement_recommendations()
        
    def _analyze_packet_timing(self, incoming_packets, embedded_packets):
        """分析封包時間分布"""
        print(f"\n⏰ 時間分析:")
        
        # 獲取時間戳
        incoming_times = []
        embedded_times = []
        
        for packet in incoming_packets:
            if hasattr(packet, 'time'):
                incoming_times.append(float(packet.time))
        
        for packet in embedded_packets:
            if hasattr(packet, 'time'):
                embedded_times.append(float(packet.time))
        
        if incoming_times and embedded_times:
            incoming_start = min(incoming_times)
            incoming_end = max(incoming_times)
            embedded_start = min(embedded_times)
            embedded_end = max(embedded_times)
            
            print(f"   來源封包時間範圍: {datetime.fromtimestamp(incoming_start)} - {datetime.fromtimestamp(incoming_end)}")
            print(f"   嵌入封包時間範圍: {datetime.fromtimestamp(embedded_start)} - {datetime.fromtimestamp(embedded_end)}")
            
            # 計算時間重疊
            overlap_start = max(incoming_start, embedded_start)
            overlap_end = min(incoming_end, embedded_end)
            
            if overlap_start < overlap_end:
                overlap_duration = overlap_end - overlap_start
                total_duration = max(incoming_end, embedded_end) - min(incoming_start, embedded_start)
                overlap_percentage = (overlap_duration / total_duration) * 100
                
                print(f"   時間重疊: {overlap_percentage:.1f}% ({overlap_duration:.1f}秒)")
                
                if overlap_percentage < 80:
                    self.issues_found.append(f"時間重疊不足: {overlap_percentage:.1f}%")
                    self.recommendations.append("增加捕獲時間或確保同時開始捕獲")
            else:
                print(f"   ❌ 沒有時間重疊!")
                self.issues_found.append("來源和嵌入封包沒有時間重疊")
                self.recommendations.append("確保同時捕獲來源和嵌入封包")
        
    def _analyze_packet_size_distribution(self, incoming_packets, embedded_packets, restored_packets):
        """分析封包大小分布"""
        print(f"\n📏 封包大小分布分析:")
        
        # 收集大小資料
        incoming_sizes = [len(bytes(p)) for p in incoming_packets]
        embedded_sizes = [len(bytes(p)) for p in embedded_packets]  
        restored_sizes = [len(bytes(p)) for p in restored_packets]
        
        # 統計分析
        print(f"   來源封包大小:")
        self._print_size_stats(incoming_sizes)
        
        print(f"   嵌入封包大小:")
        self._print_size_stats(embedded_sizes)
        
        print(f"   還原封包大小:")
        self._print_size_stats(restored_sizes)
        
        # 檢查大小分布問題
        incoming_avg = sum(incoming_sizes) / len(incoming_sizes) if incoming_sizes else 0
        restored_avg = sum(restored_sizes) / len(restored_sizes) if restored_sizes else 0
        
        if abs(incoming_avg - restored_avg) > 100:
            self.issues_found.append(f"封包大小差異過大: 來源平均{incoming_avg:.0f} vs 還原平均{restored_avg:.0f}")
            self.recommendations.append("檢查是否捕獲了不同類型的封包")
    
    def _print_size_stats(self, sizes):
        """打印大小統計"""
        if not sizes:
            print("      無數據")
            return
            
        sizes.sort()
        avg = sum(sizes) / len(sizes)
        median = sizes[len(sizes)//2]
        min_size = min(sizes)
        max_size = max(sizes)
        
        print(f"      平均: {avg:.0f} bytes, 中位數: {median} bytes")
        print(f"      範圍: {min_size} - {max_size} bytes")
        
        # 大小分布
        size_ranges = {
            "小封包(<100)": len([s for s in sizes if s < 100]),
            "中封包(100-1000)": len([s for s in sizes if 100 <= s < 1000]),
            "大封包(1000+)": len([s for s in sizes if s >= 1000])
        }
        
        for range_name, count in size_ranges.items():
            percentage = (count / len(sizes)) * 100
            print(f"      {range_name}: {count} 個 ({percentage:.1f}%)")
    
    def _analyze_packet_content_patterns(self, incoming_packets, embedded_packets):
        """分析封包內容模式"""
        print(f"\n🔍 封包內容模式分析:")
        
        # 分析來源封包模式
        print(f"   來源封包模式:")
        incoming_patterns = self._extract_packet_patterns(incoming_packets)
        for pattern, count in incoming_patterns.items():
            print(f"      {pattern}: {count} 個")
        
        # 分析嵌入封包中的原始封包模式
        print(f"   嵌入封包中的原始封包模式:")
        embedded_original_patterns = self._extract_embedded_original_patterns(embedded_packets)
        for pattern, count in embedded_original_patterns.items():
            print(f"      {pattern}: {count} 個")
        
        # 檢查模式匹配
        common_patterns = set(incoming_patterns.keys()) & set(embedded_original_patterns.keys())
        if common_patterns:
            print(f"   ✅ 共同模式: {len(common_patterns)} 個")
            for pattern in common_patterns:
                print(f"      {pattern}: 來源{incoming_patterns[pattern]} vs 嵌入{embedded_original_patterns[pattern]}")
        else:
            print(f"   ❌ 沒有共同的封包模式")
            self.issues_found.append("來源和嵌入封包沒有共同模式")
            self.recommendations.append("檢查是否捕獲了相同來源的封包")
    
    def _extract_packet_patterns(self, packets):
        """提取封包模式"""
        patterns = defaultdict(int)
        
        for packet in packets:
            pattern_key = ""
            
            if IP in packet:
                pattern_key += f"IP({packet[IP].src}->{packet[IP].dst})"
                
            if TCP in packet:
                pattern_key += f"_TCP({packet[TCP].sport}->{packet[TCP].dport})"
                
            if Raw in packet:
                payload_size = len(packet[Raw].load)
                pattern_key += f"_Payload({payload_size})"
            else:
                pattern_key += "_NoPayload"
                
            patterns[pattern_key] += 1
            
        return dict(patterns)
    
    def _extract_embedded_original_patterns(self, embedded_packets):
        """從嵌入封包中提取原始封包模式"""
        patterns = defaultdict(int)
        
        for packet in embedded_packets:
            if Raw not in packet:
                continue
                
            try:
                payload = packet[Raw].load.decode('utf-8')
                data = json.loads(payload)
                
                if "fragment_info" in data:
                    # 跳過分片，只處理完整封包
                    continue
                    
                if "original_packet" in data:
                    orig_data = data["original_packet"]
                    
                    pattern_key = ""
                    pattern_key += f"IP({orig_data.get('original_src', 'unknown')}->{orig_data.get('original_dst', 'unknown')})"
                    
                    if 'tcp_sport' in orig_data and 'tcp_dport' in orig_data:
                        pattern_key += f"_TCP({orig_data['tcp_sport']}->{orig_data['tcp_dport']})"
                    
                    size = orig_data.get('length', 0)
                    pattern_key += f"_Size({size})"
                    
                    patterns[pattern_key] += 1
                    
            except:
                continue
                
        return dict(patterns)
    
    def _analyze_embedded_packet_parsing(self, embedded_packets):
        """分析嵌入封包解析狀況"""
        print(f"\n📦 嵌入封包解析分析:")
        
        total_embedded = len(embedded_packets)
        parseable_count = 0
        fragment_count = 0
        complete_count = 0
        error_count = 0
        
        for packet in embedded_packets:
            if Raw not in packet:
                continue
                
            try:
                payload = packet[Raw].load.decode('utf-8')
                data = json.loads(payload)
                parseable_count += 1
                
                if "fragment_info" in data:
                    fragment_count += 1
                elif "original_packet" in data:
                    complete_count += 1
                    
            except:
                error_count += 1
        
        print(f"   總嵌入封包: {total_embedded}")
        print(f"   可解析: {parseable_count} ({(parseable_count/total_embedded)*100:.1f}%)")
        print(f"   分片封包: {fragment_count} ({(fragment_count/total_embedded)*100:.1f}%)")
        print(f"   完整封包: {complete_count} ({(complete_count/total_embedded)*100:.1f}%)")
        print(f"   解析錯誤: {error_count} ({(error_count/total_embedded)*100:.1f}%)")
        
        if error_count > 0:
            self.issues_found.append(f"有{error_count}個嵌入封包無法解析")
            self.recommendations.append("檢查嵌入封包的JSON格式")
        
        # 分析分片組合狀況
        if fragment_count > 0:
            self._analyze_fragment_completion(embedded_packets)
    
    def _analyze_fragment_completion(self, embedded_packets):
        """分析分片完成狀況"""
        print(f"\n🧩 分片完成狀況分析:")
        
        fragments = defaultdict(dict)
        
        for packet in embedded_packets:
            if Raw not in packet:
                continue
                
            try:
                payload = packet[Raw].load.decode('utf-8')
                data = json.loads(payload)
                
                if "fragment_info" in data:
                    frag_info = data["fragment_info"]
                    frag_uuid = frag_info["fragment_uuid"]
                    frag_index = frag_info["fragment_index"]
                    total_frags = frag_info["total_fragments"]
                    
                    if frag_uuid not in fragments:
                        fragments[frag_uuid] = {
                            'total': total_frags,
                            'received': set(),
                            'expected': set(range(total_frags))
                        }
                    
                    fragments[frag_uuid]['received'].add(frag_index)
                    
            except:
                continue
        
        complete_fragments = 0
        incomplete_fragments = 0
        
        for frag_uuid, frag_data in fragments.items():
            if frag_data['received'] == frag_data['expected']:
                complete_fragments += 1
            else:
                incomplete_fragments += 1
                missing = frag_data['expected'] - frag_data['received']
                print(f"   ❌ 分片 {frag_uuid[:8]}... 缺少: {sorted(missing)}")
        
        print(f"   完整分片組: {complete_fragments}")
        print(f"   不完整分片組: {incomplete_fragments}")
        
        if incomplete_fragments > 0:
            self.issues_found.append(f"有{incomplete_fragments}個分片組不完整")
            self.recommendations.append("檢查網路傳輸是否有封包遺失")
    
    def _generate_improvement_recommendations(self):
        """生成改善建議"""
        print(f"\n" + "=" * 70)
        print("🎯 診斷結果和改善建議")
        print("=" * 70)
        
        if not self.issues_found:
            print("✅ 沒有發現明顯問題")
        else:
            print(f"❌ 發現 {len(self.issues_found)} 個問題:")
            for i, issue in enumerate(self.issues_found, 1):
                print(f"   {i}. {issue}")
        
        print(f"\n🔧 改善建議:")
        if not self.recommendations:
            print("   系統運作正常，無需改善")
        else:
            for i, rec in enumerate(self.recommendations, 1):
                print(f"   {i}. {rec}")
        
        # 額外建議
        print(f"\n💡 進階建議:")
        print("   1. 使用更長的捕獲時間確保數據充足")
        print("   2. 在捕獲前確保流量穩定")
        print("   3. 考慮使用封包內容而非雜湊進行比較")
        print("   4. 檢查網路延遲和封包順序")
        print("   5. 考慮實作即時同步捕獲機制")

def main():
    """主程式"""
    print("🔍 深入封包流診斷工具")
    print("=" * 50)
    
    # 使用最新的PCAP檔案
    incoming_pcap = "incoming_packets_5006_20250526_223159.pcap"
    embedded_pcap = "embedded_packets_20_20250526_223159.pcap"
    restored_pcap = "restored_packets_20250526_223159.pcap"
    
    diagnostic = AdvancedPacketDiagnostic()
    
    try:
        diagnostic.analyze_packet_flow_timing(incoming_pcap, embedded_pcap, restored_pcap)
    except FileNotFoundError as e:
        print(f"❌ 檔案未找到: {e}")
        print("請確認PCAP檔案路徑正確")
    except Exception as e:
        print(f"❌ 診斷過程發生錯誤: {e}")

if __name__ == "__main__":
    main()