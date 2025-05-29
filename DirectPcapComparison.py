#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
from datetime import datetime
from scapy.all import *

class DirectPcapComparison:
    def __init__(self):
        self.comparison_results = {}
    
    def compare_pcap_files(self, original_pcap, restored_pcap):
        """直接比較兩個PCAP檔案"""
        print(f"🔍 直接PCAP檔案比較")
        print(f"   原始封包檔案: {original_pcap}")
        print(f"   還原封包檔案: {restored_pcap}")
        
        try:
            # 讀取PCAP檔案
            print(f"\n📖 讀取PCAP檔案...")
            original_packets = rdpcap(original_pcap)
            restored_packets = rdpcap(restored_pcap)
            
            print(f"   原始封包: {len(original_packets)} 個")
            print(f"   還原封包: {len(restored_packets)} 個")
            
            # 詳細比較
            self._detailed_comparison(original_packets, restored_packets)
            
            # 生成Wireshark指令
            self._generate_wireshark_commands(original_pcap, restored_pcap)
            
            return True
            
        except Exception as e:
            print(f"❌ 讀取PCAP檔案失敗: {e}")
            return False
    
    def _detailed_comparison(self, original_packets, restored_packets):
        """詳細比較封包內容"""
        print(f"\n🔍 詳細封包比較...")
        
        # 建立雜湊索引
        original_hashes = {}
        restored_hashes = {}
        
        print(f"📊 分析原始封包...")
        for i, packet in enumerate(original_packets):
            packet_bytes = bytes(packet)
            packet_hash = hashlib.sha256(packet_bytes).hexdigest()
            original_hashes[packet_hash] = {
                'index': i,
                'packet': packet,
                'size': len(packet_bytes),
                'summary': packet.summary()
            }
        
        print(f"📊 分析還原封包...")
        for i, packet in enumerate(restored_packets):
            packet_bytes = bytes(packet)
            packet_hash = hashlib.sha256(packet_bytes).hexdigest()
            restored_hashes[packet_hash] = {
                'index': i,
                'packet': packet,
                'size': len(packet_bytes),
                'summary': packet.summary()
            }
        
        # 找出匹配關係
        perfect_matches = []
        original_only = []
        restored_only = []
        
        for hash_val, orig_info in original_hashes.items():
            if hash_val in restored_hashes:
                rest_info = restored_hashes[hash_val]
                perfect_matches.append((hash_val, orig_info, rest_info))
            else:
                original_only.append((hash_val, orig_info))
        
        for hash_val, rest_info in restored_hashes.items():
            if hash_val not in original_hashes:
                restored_only.append((hash_val, rest_info))
        
        # 顯示比較結果
        print(f"\n📋 比較結果:")
        print(f"   ✅ 完美匹配: {len(perfect_matches)} 個")
        print(f"   ⚠️  僅在原始: {len(original_only)} 個")
        print(f"   ⚠️  僅在還原: {len(restored_only)} 個")
        
        # 計算成功率
        total_original = len(original_packets)
        success_rate = (len(perfect_matches) / total_original) * 100 if total_original > 0 else 0
        
        print(f"\n📈 Base64轉換成功率: {success_rate:.1f}%")
        
        # 顯示完美匹配的詳細資訊
        if perfect_matches:
            print(f"\n🎯 完美匹配封包範例 (前3個):")
            for i, (hash_val, orig_info, rest_info) in enumerate(perfect_matches[:3]):
                print(f"   匹配 {i+1}:")
                print(f"     雜湊: {hash_val[:16]}...")
                print(f"     原始: #{orig_info['index']+1}, {orig_info['size']} bytes")
                print(f"     還原: #{rest_info['index']+1}, {rest_info['size']} bytes")
                print(f"     摘要: {orig_info['summary']}")
        
        # 顯示不匹配的封包
        if original_only:
            print(f"\n⚠️  僅在原始檔案的封包 (前3個):")
            for i, (hash_val, orig_info) in enumerate(original_only[:3]):
                print(f"   #{orig_info['index']+1}: {orig_info['summary']}")
        
        if restored_only:
            print(f"\n⚠️  僅在還原檔案的封包 (前3個):")
            for i, (hash_val, rest_info) in enumerate(restored_only[:3]):
                print(f"   #{rest_info['index']+1}: {rest_info['summary']}")
        
        # 評估結果
        self._evaluate_comparison_results(success_rate, len(perfect_matches), total_original)
        
        # 保存比較結果
        self.comparison_results = {
            'comparison_timestamp': datetime.now().isoformat(),
            'original_packet_count': len(original_packets),
            'restored_packet_count': len(restored_packets),
            'perfect_matches': len(perfect_matches),
            'success_rate': success_rate,
            'original_only': len(original_only),
            'restored_only': len(restored_only)
        }
    
    def _evaluate_comparison_results(self, success_rate, matches, total):
        """評估比較結果"""
        print(f"\n🎯 Base64轉換評估:")
        
        if success_rate == 100:
            status = "🎉 完美"
            conclusion = "Base64轉換完全正確，所有封包都精確還原"
        elif success_rate >= 95:
            status = "✅ 優秀"
            conclusion = "Base64轉換非常成功，幾乎所有封包都正確還原"
        elif success_rate >= 80:
            status = "✅ 良好"
            conclusion = "Base64轉換基本成功，大部分封包正確還原"
        elif success_rate >= 50:
            status = "⚠️ 需要改善"
            conclusion = "Base64轉換有問題，許多封包未能正確還原"
        else:
            status = "❌ 嚴重問題"
            conclusion = "Base64轉換失敗，系統需要檢查"
        
        print(f"   狀態: {status}")
        print(f"   成功率: {success_rate:.1f}% ({matches}/{total})")
        print(f"   結論: {conclusion}")
    
    def _generate_wireshark_commands(self, original_pcap, restored_pcap):
        """生成Wireshark分析命令"""
        print(f"\n📋 Wireshark分析命令:")
        print(f"```bash")
        print(f"# 比較封包數量")
        print(f"tshark -r {original_pcap} -T fields -e frame.number | wc -l")
        print(f"tshark -r {restored_pcap} -T fields -e frame.number | wc -l")
        print(f"")
        print(f"# 比較封包大小分布")
        print(f"tshark -r {original_pcap} -T fields -e frame.len | sort -n")
        print(f"tshark -r {restored_pcap} -T fields -e frame.len | sort -n")
        print(f"")
        print(f"# 比較IP地址分布")
        print(f"tshark -r {original_pcap} -T fields -e ip.src -e ip.dst | sort | uniq -c")
        print(f"tshark -r {restored_pcap} -T fields -e ip.src -e ip.dst | sort | uniq -c")
        print(f"")
        print(f"# 比較TCP端口分布")
        print(f"tshark -r {original_pcap} -T fields -e tcp.srcport -e tcp.dstport | sort | uniq -c")
        print(f"tshark -r {restored_pcap} -T fields -e tcp.srcport -e tcp.dstport | sort | uniq -c")
        print(f"```")
        
        print(f"\n📋 Wireshark視覺比較步驟:")
        print(f"1. 開啟原始檔案: wireshark {original_pcap}")
        print(f"2. 開啟還原檔案: wireshark {restored_pcap}")
        print(f"3. 比較封包#1的所有欄位")
        print(f"4. 使用Follow TCP Stream比較內容")
        print(f"5. 檢查Statistics → Packet Lengths")
    
    def save_comparison_report(self):
        """保存比較報告"""
        if not self.comparison_results:
            return None
        
        report_filename = f"direct_pcap_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            import json
            json.dump(self.comparison_results, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 比較報告已保存: {report_filename}")
        return report_filename

def main():
    """主程式"""
    print("🔍 直接PCAP檔案比較工具")
    print("=" * 60)
    print("此工具直接比較兩個PCAP檔案，驗證Base64轉換的準確性")
    
    original_pcap = input("\n請輸入原始封包PCAP檔案路徑: ").strip()
    restored_pcap = input("請輸入還原封包PCAP檔案路徑: ").strip()
    
    if not original_pcap or not restored_pcap:
        print("❌ 請提供有效的檔案路徑")
        return
    
    try:
        # 執行比較
        comparator = DirectPcapComparison()
        success = comparator.compare_pcap_files(original_pcap, restored_pcap)
        
        if success:
            # 保存報告
            report_file = comparator.save_comparison_report()
            
            print(f"\n✅ 直接比較完成！")
            print(f"📁 產生的檔案: {report_file}")
            
            # 顯示建議
            results = comparator.comparison_results
            success_rate = results.get('success_rate', 0)
            
            if success_rate == 100:
                print(f"\n🎉 恭喜！您的Agent-Tool-V2系統的Base64轉換完全正確！")
            elif success_rate >= 90:
                print(f"\n✅ 很好！Base64轉換基本正確，只有少量差異")
            else:
                print(f"\n⚠️  Base64轉換需要檢查，成功率較低")
        else:
            print(f"\n❌ 比較失敗")
        
    except Exception as e:
        print(f"❌ 比較過程發生錯誤: {e}")

if __name__ == "__main__":
    main()