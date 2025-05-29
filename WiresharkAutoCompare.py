#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import json
from datetime import datetime

class WiresharkAutoCompare:
    def __init__(self):
        self.comparison_results = {}
    
    def compare_pcap_files(self, original_pcap, restored_pcap):
        """使用tshark自動比較兩個PCAP檔案"""
        print(f"🔍 自動化PCAP檔案比較")
        print(f"   原始檔案: {original_pcap}")
        print(f"   還原檔案: {restored_pcap}")
        
        if not os.path.exists(original_pcap) or not os.path.exists(restored_pcap):
            print("❌ PCAP檔案不存在")
            return False
        
        # 比較封包數量
        self._compare_packet_counts(original_pcap, restored_pcap)
        
        # 比較封包內容
        self._compare_packet_contents(original_pcap, restored_pcap)
        
        # 比較統計資訊
        self._compare_statistics(original_pcap, restored_pcap)
        
        # 生成比較報告
        self._generate_comparison_report()
        
        return True
    
    def _compare_packet_counts(self, original_pcap, restored_pcap):
        """比較封包數量"""
        print(f"\n📊 比較封包數量...")
        
        try:
            # 計算原始封包數量
            original_count = self._get_packet_count(original_pcap)
            restored_count = self._get_packet_count(restored_pcap)
            
            print(f"   原始封包: {original_count} 個")
            print(f"   還原封包: {restored_count} 個")
            
            if original_count == restored_count:
                print(f"   ✅ 封包數量完全匹配")
                count_match = True
            else:
                print(f"   ❌ 封包數量不匹配")
                count_match = False
            
            self.comparison_results['packet_counts'] = {
                'original': original_count,
                'restored': restored_count,
                'match': count_match
            }
            
        except Exception as e:
            print(f"   ❌ 比較封包數量失敗: {e}")
    
    def _compare_packet_contents(self, original_pcap, restored_pcap):
        """比較封包內容"""
        print(f"\n🔍 比較封包內容...")
        
        try:
            # 提取封包摘要資訊
            original_summary = self._extract_packet_summary(original_pcap)
            restored_summary = self._extract_packet_summary(restored_pcap)
            
            if not original_summary or not restored_summary:
                print("   ❌ 無法提取封包摘要")
                return
            
            # 比較每個封包
            matches = 0
            total = min(len(original_summary), len(restored_summary))
            
            content_details = []
            
            for i in range(total):
                orig = original_summary[i]
                rest = restored_summary[i]
                
                # 比較關鍵欄位
                fields_match = (
                    orig.get('ip_src') == rest.get('ip_src') and
                    orig.get('ip_dst') == rest.get('ip_dst') and
                    orig.get('tcp_srcport') == rest.get('tcp_srcport') and
                    orig.get('tcp_dstport') == rest.get('tcp_dstport') and
                    orig.get('frame_len') == rest.get('frame_len')
                )
                
                if fields_match:
                    matches += 1
                
                content_details.append({
                    'packet_number': i + 1,
                    'fields_match': fields_match,
                    'original': orig,
                    'restored': rest
                })
            
            match_rate = (matches / total) * 100 if total > 0 else 0
            
            print(f"   封包內容匹配: {matches}/{total} ({match_rate:.1f}%)")
            
            if match_rate == 100:
                print(f"   ✅ 所有封包內容完全匹配")
            elif match_rate >= 90:
                print(f"   ⚠️  大部分封包匹配，有少量差異")
            else:
                print(f"   ❌ 封包內容有明顯差異")
            
            self.comparison_results['packet_contents'] = {
                'total_compared': total,
                'matches': matches,
                'match_rate': match_rate,
                'details': content_details[:5]  # 只保存前5個詳細資訊
            }
            
        except Exception as e:
            print(f"   ❌ 比較封包內容失敗: {e}")
    
    def _compare_statistics(self, original_pcap, restored_pcap):
        """比較統計資訊"""
        print(f"\n📈 比較統計資訊...")
        
        try:
            # 獲取流量統計
            original_stats = self._get_traffic_stats(original_pcap)
            restored_stats = self._get_traffic_stats(restored_pcap)
            
            print(f"   原始檔案統計:")
            for key, value in original_stats.items():
                print(f"     {key}: {value}")
            
            print(f"   還原檔案統計:")
            for key, value in restored_stats.items():
                print(f"     {key}: {value}")
            
            # 比較關鍵統計指標
            stats_match = (
                original_stats.get('total_bytes') == restored_stats.get('total_bytes') and
                original_stats.get('avg_packet_size') == restored_stats.get('avg_packet_size')
            )
            
            if stats_match:
                print(f"   ✅ 統計資訊匹配")
            else:
                print(f"   ⚠️  統計資訊有差異")
            
            self.comparison_results['statistics'] = {
                'original': original_stats,
                'restored': restored_stats,
                'match': stats_match
            }
            
        except Exception as e:
            print(f"   ❌ 比較統計資訊失敗: {e}")
    
    def _get_packet_count(self, pcap_file):
        """獲取PCAP檔案的封包數量"""
        try:
            result = subprocess.run([
                'tshark', '-r', pcap_file, '-T', 'fields', '-e', 'frame.number'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                return len([line for line in lines if line.strip()])
            else:
                return 0
        except Exception:
            return 0
    
    def _extract_packet_summary(self, pcap_file):
        """提取封包摘要資訊"""
        try:
            result = subprocess.run([
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'ip.src',
                '-e', 'ip.dst', 
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'frame.len'
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                return []
            
            packets = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    fields = line.split('\t')
                    if len(fields) >= 6:
                        packets.append({
                            'frame_number': fields[0],
                            'ip_src': fields[1],
                            'ip_dst': fields[2],
                            'tcp_srcport': fields[3],
                            'tcp_dstport': fields[4],
                            'frame_len': fields[5]
                        })
            
            return packets
            
        except Exception as e:
            print(f"提取封包摘要失敗: {e}")
            return []
    
    def _get_traffic_stats(self, pcap_file):
        """獲取流量統計資訊"""
        try:
            # 獲取基本統計
            result = subprocess.run([
                'tshark', '-r', pcap_file, '-q', '-z', 'io,stat,0'
            ], capture_output=True, text=True, timeout=30)
            
            stats = {}
            
            if result.returncode == 0:
                # 解析統計輸出
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Frames:' in line:
                        stats['total_frames'] = line.split(':')[1].strip()
                    elif 'Bytes:' in line:
                        stats['total_bytes'] = line.split(':')[1].strip()
                    elif 'Avg frame size:' in line:
                        stats['avg_packet_size'] = line.split(':')[1].strip()
            
            return stats
            
        except Exception:
            return {}
    
    def _generate_comparison_report(self):
        """生成比較報告"""
        print(f"\n📄 生成比較報告...")
        
        report = {
            'comparison_timestamp': datetime.now().isoformat(),
            'comparison_results': self.comparison_results,
            'overall_assessment': self._assess_overall_results()
        }
        
        report_filename = f"wireshark_comparison_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ 比較報告已保存: {report_filename}")
        
        # 顯示總結
        assessment = report['overall_assessment']
        print(f"\n🎯 總體評估:")
        print(f"   狀態: {assessment['status']}")
        print(f"   評分: {assessment['score']}/100")
        print(f"   結論: {assessment['conclusion']}")
    
    def _assess_overall_results(self):
        """評估整體結果"""
        scores = []
        
        # 封包數量評分
        if self.comparison_results.get('packet_counts', {}).get('match', False):
            scores.append(30)  # 封包數量匹配得30分
        
        # 封包內容評分
        content_results = self.comparison_results.get('packet_contents', {})
        if content_results:
            match_rate = content_results.get('match_rate', 0)
            scores.append(int(match_rate * 0.5))  # 內容匹配得最多50分
        
        # 統計資訊評分
        if self.comparison_results.get('statistics', {}).get('match', False):
            scores.append(20)  # 統計匹配得20分
        
        total_score = sum(scores)
        
        # 評估狀態
        if total_score >= 90:
            status = "✅ 完美匹配"
            conclusion = "Filter.py攔截的封包與Analyst.py還原的封包完全一致"
        elif total_score >= 80:
            status = "✅ 優秀"
            conclusion = "封包還原非常成功，只有微小差異"
        elif total_score >= 60:
            status = "⚠️ 良好"
            conclusion = "封包還原基本成功，但存在一些差異"
        else:
            status = "❌ 需要改善"
            conclusion = "封包還原存在明顯問題，需要檢查系統"
        
        return {
            'status': status,
            'score': total_score,
            'conclusion': conclusion,
            'detailed_scores': {
                'packet_count_match': scores[0] if len(scores) > 0 else 0,
                'content_match': scores[1] if len(scores) > 1 else 0,
                'statistics_match': scores[2] if len(scores) > 2 else 0
            }
        }

def check_tshark_availability():
    """檢查tshark是否可用"""
    try:
        result = subprocess.run(['tshark', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ tshark可用")
            return True
        else:
            print("❌ tshark不可用")
            return False
    except Exception:
        print("❌ 找不到tshark，請安裝Wireshark")
        print("   Ubuntu/Debian: sudo apt install tshark")
        print("   macOS: brew install wireshark")
        return False

def main():
    """主程式"""
    print("🔍 Wireshark自動化比較工具")
    print("=" * 60)
    
    # 檢查tshark可用性
    if not check_tshark_availability():
        return
    
    print("此工具使用tshark自動比較PCAP檔案")
    
    original_pcap = input("\n請輸入原始封包PCAP檔案路徑: ").strip()
    restored_pcap = input("請輸入還原封包PCAP檔案路徑: ").strip()
    
    if not original_pcap or not restored_pcap:
        print("❌ 請提供有效的檔案路徑")
        return
    
    # 執行比較
    comparator = WiresharkAutoCompare()
    success = comparator.compare_pcap_files(original_pcap, restored_pcap)
    
    if success:
        print("\n✅ 自動化比較完成！")
    else:
        print("\n❌ 比較過程發生錯誤")

if __name__ == "__main__":
    main()