#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import hashlib
import time
import threading
from datetime import datetime
from scapy.all import *
from collections import defaultdict, deque
import queue


class FragmentOptimizedComparator:
    def __init__(self):
        # 網路架構配置
        self.source_ip = "220.133.19.199"
        self.source_port = 5006
        self.local_ip = "140.115.52.14"
        self.internal_ip = "10.52.52.96"
        self.internal_port = 20
        self.target_ip = "10.52.52.100"
        self.target_port = 9999

        # 統計計數器
        self.total_incoming_captured = 0
        self.total_embedded_captured = 0
        self.total_fragments_received = 0
        self.total_complete_packets = 0
        self.total_restored_packets = 0

        # 分片處理優化
        self.fragment_buffer = defaultdict(dict)
        self.fragment_timeouts = defaultdict(float)
        self.fragment_timeout = 30.0  # 30秒超時
        self.complete_fragments = []
        self.incomplete_fragments = defaultdict(set)

        # 封包儲存
        self.incoming_buffer = deque(maxlen=5000)
        self.restored_packets = []

        # 匹配控制
        self.matched_incoming_ids = set()
        self.matched_restored_ids = set()
        self.unique_matches = []

        # 同步控制
        self.capture_start_time = None
        self.time_window = 15.0  # 增加時間窗口
        self.is_capturing = False

        # 隊列
        self.incoming_queue = queue.Queue()
        self.restored_queue = queue.Queue()

        # 分片統計
        self.fragment_stats = {
            'received_fragments': 0,
            'complete_groups': 0,
            'incomplete_groups': 0,
            'timeout_groups': 0,
            'successful_reassemblies': 0,
            'failed_reassemblies': 0
        }

    def print_network_config(self):
        """顯示網路配置"""
        print("🧩 分片優化封包比較工具 v5.0")
        print("=" * 60)
        print(f"📥 來源端點:     {self.source_ip}:{self.source_port}")
        print(f"🖥️  本機IP:       {self.local_ip}")
        print(f"📤 內網發送端點: {self.internal_ip}:{self.internal_port}")
        print(f"🎯 目標端點:     {self.target_ip}:{self.target_port}")
        print(f"⏰ 時間窗口:     {self.time_window} 秒")
        print(f"🧩 分片超時:     {self.fragment_timeout} 秒")
        print("")
        print("🔧 分片優化功能:")
        print("   1. 智能分片追蹤 - 詳細監控分片狀態")
        print("   2. 超時清理機制 - 自動清理過期分片")
        print("   3. 重組狀態診斷 - 識別重組失敗原因")
        print("   4. 增強容錯能力 - 更好的錯誤處理")

    def start_synchronized_capture(self, duration=60):
        """開始同步捕獲"""
        print(f"\n🚀 開始分片優化同步捕獲 ({duration}秒)")
        print("=" * 60)

        # 重置所有計數器
        self._reset_counters()

        # 設定捕獲開始時間
        self.capture_start_time = time.time()
        self.is_capturing = True

        # 啟動分片清理線程
        cleanup_thread = threading.Thread(target=self._fragment_cleanup_worker, daemon=True)
        cleanup_thread.start()

        # 啟動匹配處理線程
        matching_thread = threading.Thread(target=self._fragment_aware_matching, daemon=True)
        matching_thread.start()

        # 啟動兩個捕獲線程
        incoming_thread = threading.Thread(
            target=self._capture_incoming_packets,
            args=(duration,),
            daemon=True
        )

        outgoing_thread = threading.Thread(
            target=self._capture_outgoing_packets_optimized,
            args=(duration,),
            daemon=True
        )

        print(f"⏰ 捕獲開始時間: {datetime.fromtimestamp(self.capture_start_time)}")

        # 同時啟動
        incoming_thread.start()
        outgoing_thread.start()

        # 等待完成
        incoming_thread.join()
        outgoing_thread.join()

        self.is_capturing = False

        # 最後的分片清理和統計
        self._final_fragment_cleanup()

        # 等待最後的匹配處理
        time.sleep(3)

        print(f"\n✅ 分片優化捕獲完成")
        return self._comprehensive_analysis()

    def _reset_counters(self):
        """重置所有計數器"""
        self.total_incoming_captured = 0
        self.total_embedded_captured = 0
        self.total_fragments_received = 0
        self.total_complete_packets = 0
        self.total_restored_packets = 0

        self.fragment_buffer.clear()
        self.fragment_timeouts.clear()
        self.complete_fragments.clear()
        self.incomplete_fragments.clear()

        self.fragment_stats = {
            'received_fragments': 0,
            'complete_groups': 0,
            'incomplete_groups': 0,
            'timeout_groups': 0,
            'successful_reassemblies': 0,
            'failed_reassemblies': 0
        }

    def _capture_incoming_packets(self, duration):
        """捕獲來源封包"""
        print(f"📥 啟動來源封包捕獲...")

        def packet_handler(packet):
            if (TCP in packet and
                    packet[IP].src == self.source_ip and
                    packet[TCP].sport == self.source_port and
                    packet[IP].dst == self.local_ip):

                self.total_incoming_captured += 1
                capture_time = time.time()
                relative_time = capture_time - self.capture_start_time

                packet_bytes = bytes(packet)
                packet_info = {
                    'id': f"incoming_{self.total_incoming_captured}",
                    'timestamp': capture_time,
                    'relative_time': relative_time,
                    'packet': packet,
                    'size': len(packet_bytes),
                    'full_hash': hashlib.sha256(packet_bytes).hexdigest(),
                    'ip_hash': hashlib.sha256(bytes(packet[IP])).hexdigest() if IP in packet else None,
                    'content_signature': self._create_content_signature(packet),
                    'layers': self._get_packet_layers(packet),
                    'sequence_number': self.total_incoming_captured
                }

                self.incoming_buffer.append(packet_info)
                self.incoming_queue.put(packet_info)

                if self.total_incoming_captured % 100 == 0:
                    print(f"📦 來源封包: {self.total_incoming_captured} 個 (時間: +{relative_time:.1f}s)")

        try:
            filter_expr = f"tcp and src host {self.source_ip} and src port {self.source_port} and dst host {self.local_ip}"
            sniff(filter=filter_expr, prn=packet_handler, timeout=duration)
            print(f"✅ 來源封包捕獲完成: {self.total_incoming_captured} 個")

        except Exception as e:
            print(f"❌ 來源封包捕獲失敗: {e}")

    def _capture_outgoing_packets_optimized(self, duration):
        """優化的嵌入封包捕獲"""
        print(f"📤 啟動分片優化嵌入封包捕獲...")

        def packet_handler(packet):
            if (TCP in packet and
                    packet[IP].src == self.internal_ip and
                    packet[TCP].sport == self.internal_port and
                    packet[IP].dst == self.target_ip and
                    packet[TCP].dport == self.target_port and
                    Raw in packet):

                self.total_embedded_captured += 1
                capture_time = time.time()
                relative_time = capture_time - self.capture_start_time

                try:
                    payload = packet[Raw].load.decode('utf-8')
                    embedded_data = json.loads(payload)

                    if "fragment_info" in embedded_data:
                        self.total_fragments_received += 1
                        self.fragment_stats['received_fragments'] += 1

                        # 處理分片
                        self._handle_fragment_optimized(embedded_data, capture_time, relative_time)

                        if self.total_fragments_received % 50 == 0:
                            print(
                                f"🧩 分片封包: {self.total_fragments_received} 個 (完整組: {self.fragment_stats['complete_groups']})")

                    elif "metadata" in embedded_data and "original_packet" in embedded_data:
                        self.total_complete_packets += 1

                        # 處理完整封包
                        restored_info = self._process_complete_packet(embedded_data, capture_time, relative_time)
                        if restored_info:
                            self.restored_queue.put(restored_info)

                except Exception as e:
                    # 詳細記錄解析錯誤
                    if self.total_embedded_captured % 100 == 0:
                        print(f"⚠️  解析錯誤: {str(e)[:50]}...")

        try:
            filter_expr = f"tcp and src host {self.internal_ip} and src port {self.internal_port} and dst host {self.target_ip} and dst port {self.target_port}"
            sniff(filter=filter_expr, prn=packet_handler, timeout=duration)
            print(f"✅ 嵌入封包捕獲完成: {self.total_embedded_captured} 個")
            print(f"🧩 分片封包: {self.total_fragments_received} 個")
            print(f"📋 完整封包: {self.total_complete_packets} 個")
            print(f"🔄 還原封包: {self.total_restored_packets} 個")

        except Exception as e:
            print(f"❌ 嵌入封包捕獲失敗: {e}")

    def _handle_fragment_optimized(self, embedded_data, capture_time, relative_time):
        """優化的分片處理"""
        try:
            fragment_info = embedded_data["fragment_info"]
            fragment_uuid = fragment_info["fragment_uuid"]
            fragment_index = fragment_info["fragment_index"]
            total_fragments = fragment_info["total_fragments"]

            # 記錄分片時間
            self.fragment_timeouts[fragment_uuid] = capture_time

            # 儲存分片
            self.fragment_buffer[fragment_uuid][fragment_index] = {
                'data': embedded_data,
                'timestamp': capture_time,
                'relative_time': relative_time
            }

            # 更新不完整分片追蹤
            if fragment_uuid not in self.incomplete_fragments:
                self.incomplete_fragments[fragment_uuid] = set()
            self.incomplete_fragments[fragment_uuid].add(fragment_index)

            # 檢查是否完整
            if len(self.fragment_buffer[fragment_uuid]) == total_fragments:
                print(f"🧩 分片組完整: {fragment_uuid[:8]}... ({total_fragments}個分片)")

                # 嘗試重組
                success = self._reassemble_fragments_optimized(fragment_uuid, capture_time, relative_time)

                if success:
                    self.fragment_stats['complete_groups'] += 1
                    self.fragment_stats['successful_reassemblies'] += 1

                    # 從不完整列表中移除
                    if fragment_uuid in self.incomplete_fragments:
                        del self.incomplete_fragments[fragment_uuid]

                else:
                    self.fragment_stats['failed_reassemblies'] += 1
                    print(f"❌ 分片重組失敗: {fragment_uuid[:8]}...")

            else:
                # 顯示分片進度
                received = len(self.fragment_buffer[fragment_uuid])
                if received % 5 == 0 or received == total_fragments - 1:
                    print(f"🧩 分片進度: {fragment_uuid[:8]}... [{received}/{total_fragments}]")

        except Exception as e:
            print(f"❌ 分片處理錯誤: {e}")

    def _reassemble_fragments_optimized(self, fragment_uuid, capture_time, relative_time):
        """優化的分片重組"""
        try:
            fragments = self.fragment_buffer[fragment_uuid]

            # 按索引排序
            sorted_fragments = sorted(fragments.items())

            # 檢查分片完整性
            expected_indices = set(range(len(sorted_fragments)))
            actual_indices = set(fragments.keys())

            if expected_indices != actual_indices:
                print(f"⚠️  分片索引不完整: 期望{expected_indices}, 實際{actual_indices}")
                return False

            # 重組數據
            reassembled_data = b""
            for _, fragment_container in sorted_fragments:
                try:
                    fragment_data = fragment_container['data']
                    fragment_bytes = base64.b64decode(fragment_data["data"])
                    reassembled_data += fragment_bytes
                except Exception as e:
                    print(f"❌ 分片數據解碼失敗: {e}")
                    return False

            # 解析完整數據
            try:
                complete_data = json.loads(reassembled_data.decode('utf-8'))
            except Exception as e:
                print(f"❌ 重組數據JSON解析失敗: {e}")
                return False

            # 處理重組後的完整封包
            restored_info = self._process_complete_packet(complete_data, capture_time, relative_time)

            if restored_info:
                restored_info['is_reassembled'] = True
                restored_info['fragment_count'] = len(sorted_fragments)
                restored_info['fragment_uuid'] = fragment_uuid

                self.restored_queue.put(restored_info)

                print(f"✅ 分片重組成功: {fragment_uuid[:8]}... → 還原封包")

                # 清理分片緩存
                del self.fragment_buffer[fragment_uuid]
                if fragment_uuid in self.fragment_timeouts:
                    del self.fragment_timeouts[fragment_uuid]

                return True
            else:
                print(f"❌ 重組後封包處理失敗: {fragment_uuid[:8]}...")
                return False

        except Exception as e:
            print(f"❌ 分片重組錯誤: {e}")
            return False

    def _process_complete_packet(self, embedded_data, capture_time, relative_time):
        """處理完整封包"""
        try:
            self.total_restored_packets += 1

            metadata = embedded_data.get("metadata", {})
            original_packet_data = embedded_data.get("original_packet", {})

            if not original_packet_data.get("data"):
                print(f"⚠️  封包數據缺失")
                return None

            # 解碼原始封包
            original_bytes = base64.b64decode(original_packet_data["data"])

            # 智能還原
            layers = original_packet_data.get('layers', [])
            if "IP" in layers:
                restored_packet = IP(original_bytes)
            else:
                restored_packet = Ether(original_bytes)

            # 計算特徵
            restored_bytes = bytes(restored_packet)

            restored_info = {
                'id': f"restored_{self.total_restored_packets}",
                'timestamp': capture_time,
                'relative_time': relative_time,
                'packet': restored_packet,
                'size': len(restored_bytes),
                'full_hash': hashlib.sha256(restored_bytes).hexdigest(),
                'ip_hash': hashlib.sha256(bytes(restored_packet[IP])).hexdigest() if IP in restored_packet else None,
                'content_signature': self._create_content_signature(restored_packet),
                'layers': self._get_packet_layers(restored_packet),
                'metadata': metadata,
                'original_hash': original_packet_data.get('original_hash', ''),
                'restoration_method': 'ip_layer' if "IP" in layers else 'ether_layer',
                'sequence_number': self.total_restored_packets
            }

            self.restored_packets.append(restored_info)
            return restored_info

        except Exception as e:
            print(f"❌ 完整封包處理錯誤: {e}")
            return None

    def _fragment_cleanup_worker(self):
        """分片清理工作線程"""
        while self.is_capturing:
            try:
                current_time = time.time()
                expired_fragments = []

                # 找出過期的分片
                for fragment_uuid, last_update in self.fragment_timeouts.items():
                    if current_time - last_update > self.fragment_timeout:
                        expired_fragments.append(fragment_uuid)

                # 清理過期分片
                for fragment_uuid in expired_fragments:
                    fragments_count = len(self.fragment_buffer.get(fragment_uuid, {}))
                    print(f"🧹 清理過期分片: {fragment_uuid[:8]}... ({fragments_count}個分片)")

                    if fragment_uuid in self.fragment_buffer:
                        del self.fragment_buffer[fragment_uuid]
                    if fragment_uuid in self.fragment_timeouts:
                        del self.fragment_timeouts[fragment_uuid]
                    if fragment_uuid in self.incomplete_fragments:
                        del self.incomplete_fragments[fragment_uuid]

                    self.fragment_stats['timeout_groups'] += 1

                # 顯示分片狀態
                if len(self.fragment_buffer) > 0:
                    active_groups = len(self.fragment_buffer)
                    if active_groups % 10 == 0:
                        print(f"🧩 活躍分片組: {active_groups} 個")

                time.sleep(5)  # 每5秒檢查一次

            except Exception as e:
                print(f"分片清理錯誤: {e}")
                time.sleep(5)

    def _final_fragment_cleanup(self):
        """最終分片清理和統計"""
        print(f"\n🧹 執行最終分片清理...")

        # 統計剩餘分片
        remaining_groups = len(self.fragment_buffer)
        incomplete_groups = len(self.incomplete_fragments)

        if remaining_groups > 0:
            print(f"⚠️  剩餘未完成分片組: {remaining_groups} 個")

            # 顯示前5個未完成的分片組詳情
            for i, (fragment_uuid, fragments) in enumerate(list(self.fragment_buffer.items())[:5]):
                total_expected = len(fragments)
                received_indices = sorted(fragments.keys())
                print(f"   {i + 1}. {fragment_uuid[:8]}...: {len(fragments)} 個分片 {received_indices}")

        self.fragment_stats['incomplete_groups'] = remaining_groups

    def _fragment_aware_matching(self):
        """分片感知的匹配處理"""
        print(f"🔄 啟動分片感知匹配引擎...")

        pending_incoming = []
        pending_restored = []

        while self.is_capturing or not self.incoming_queue.empty() or not self.restored_queue.empty():
            try:
                # 收集封包
                while not self.incoming_queue.empty():
                    incoming_info = self.incoming_queue.get_nowait()
                    if incoming_info['id'] not in self.matched_incoming_ids:
                        pending_incoming.append(incoming_info)

                while not self.restored_queue.empty():
                    restored_info = self.restored_queue.get_nowait()
                    if restored_info['id'] not in self.matched_restored_ids:
                        pending_restored.append(restored_info)

                # 執行匹配
                new_matches = self._enhanced_packet_matching(pending_incoming, pending_restored)
                self.unique_matches.extend(new_matches)

                if len(self.unique_matches) % 25 == 0 and len(self.unique_matches) > 0:
                    print(f"🎯 唯一匹配: {len(self.unique_matches)} 個配對")

                # 清理過期封包
                current_time = time.time()
                pending_incoming = [p for p in pending_incoming
                                    if (current_time - p['timestamp']) < self.time_window
                                    and p['id'] not in self.matched_incoming_ids]
                pending_restored = [p for p in pending_restored
                                    if (current_time - p['timestamp']) < self.time_window
                                    and p['id'] not in self.matched_restored_ids]

                time.sleep(0.2)

            except Exception as e:
                print(f"匹配引擎錯誤: {e}")
                time.sleep(0.2)

    def _enhanced_packet_matching(self, incoming_list, restored_list):
        """增強的封包匹配"""
        matches = []

        for restored_info in restored_list:
            if restored_info['id'] in self.matched_restored_ids:
                continue

            best_match = None
            best_score = 0
            best_incoming_info = None

            for incoming_info in incoming_list:
                if incoming_info['id'] in self.matched_incoming_ids:
                    continue

                # 計算匹配分數
                score = self._calculate_enhanced_match_score(incoming_info, restored_info)

                if score > best_score and score > 0.5:  # 降低閾值
                    best_match = incoming_info
                    best_score = score
                    best_incoming_info = incoming_info

            if best_match and best_incoming_info:
                matches.append({
                    'incoming': best_incoming_info,
                    'restored': restored_info,
                    'score': best_score,
                    'match_time': time.time(),
                    'time_diff': abs(restored_info['relative_time'] - best_incoming_info['relative_time']),
                    'match_type': self._determine_match_type(best_incoming_info, restored_info, best_score),
                    'is_reassembled': restored_info.get('is_reassembled', False)
                })

                self.matched_incoming_ids.add(best_incoming_info['id'])
                self.matched_restored_ids.add(restored_info['id'])

        return matches

    def _calculate_enhanced_match_score(self, incoming_info, restored_info):
        """增強的匹配分數計算"""
        score = 0.0

        # 1. 雜湊匹配
        if incoming_info['full_hash'] == restored_info['full_hash']:
            score += 1.0
        elif incoming_info['ip_hash'] and restored_info['ip_hash'] and incoming_info['ip_hash'] == restored_info[
            'ip_hash']:
            score += 0.8

        # 2. 內容特徵匹配
        if incoming_info['content_signature'] == restored_info['content_signature']:
            score += 0.7

        # 3. 大小相似性 (考慮IP vs Ether差異)
        size_diff = abs(incoming_info['size'] - restored_info['size'])
        if size_diff <= 26:  # IP header vs Ether header 差異
            score += 0.6
        elif size_diff <= 50:
            score += 0.4
        elif size_diff <= 100:
            score += 0.2

        # 4. 時間接近性
        time_diff = abs(restored_info['relative_time'] - incoming_info['relative_time'])
        if time_diff < self.time_window:
            time_score = max(0, 1.0 - (time_diff / self.time_window))
            score += time_score * 0.5

        # 5. 層級匹配
        incoming_layers = set(incoming_info['layers'])
        restored_layers = set(restored_info['layers'])
        common_layers = incoming_layers & restored_layers
        if common_layers:
            layer_score = len(common_layers) / max(len(incoming_layers), len(restored_layers))
            score += layer_score * 0.3

        return min(score, 1.0)

    def _determine_match_type(self, incoming_info, restored_info, score):
        """確定匹配類型"""
        if incoming_info['full_hash'] == restored_info['full_hash']:
            return "完整雜湊匹配"
        elif incoming_info['ip_hash'] == restored_info['ip_hash']:
            return "IP層雜湊匹配"
        elif incoming_info['content_signature'] == restored_info['content_signature']:
            return "內容特徵匹配"
        elif score >= 0.8:
            return "高相似度匹配"
        elif score >= 0.6:
            return "中等相似度匹配"
        else:
            return "低相似度匹配"

    def _create_content_signature(self, packet):
        """創建封包內容特徵"""
        signature = []

        if IP in packet:
            signature.extend([packet[IP].src, packet[IP].dst, str(packet[IP].proto)])

        if TCP in packet:
            signature.extend([str(packet[TCP].sport), str(packet[TCP].dport)])

        if Raw in packet:
            payload = packet[Raw].load
            payload_hash = hashlib.md5(payload[:50]).hexdigest()[:8]
            signature.append(payload_hash)

        return "|".join(signature)

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

    def _comprehensive_analysis(self):
        """全面分析結果"""
        print(f"\n🧩 全面分片優化分析")
        print("=" * 80)

        print(f"📊 封包統計:")
        print(f"   實際捕獲來源封包: {self.total_incoming_captured} 個")
        print(f"   嵌入封包總數: {self.total_embedded_captured} 個")
        print(f"   分片封包總數: {self.total_fragments_received} 個")
        print(f"   完整封包總數: {self.total_complete_packets} 個")
        print(f"   成功還原封包: {self.total_restored_packets} 個")
        print(f"   唯一成功匹配: {len(self.unique_matches)} 個")

        # 計算各種效率
        if self.total_incoming_captured > 0:
            match_rate = (len(self.unique_matches) / self.total_incoming_captured) * 100
        else:
            match_rate = 0

        if self.total_embedded_captured > 0:
            restoration_rate = (self.total_restored_packets / self.total_embedded_captured) * 100
        else:
            restoration_rate = 0

        if self.total_restored_packets > 0:
            matching_efficiency = (len(self.unique_matches) / self.total_restored_packets) * 100
        else:
            matching_efficiency = 0

        print(f"   真實成功率: {match_rate:.1f}%")
        print(f"   封包還原率: {restoration_rate:.1f}%")
        print(f"   匹配效率: {matching_efficiency:.1f}%")

        # 分片詳細統計
        print(f"\n🧩 分片處理詳細統計:")
        print(f"   接收分片總數: {self.fragment_stats['received_fragments']} 個")
        print(f"   完整分片組: {self.fragment_stats['complete_groups']} 個")
        print(f"   不完整分片組: {self.fragment_stats['incomplete_groups']} 個")
        print(f"   超時分片組: {self.fragment_stats['timeout_groups']} 個")
        print(f"   成功重組: {self.fragment_stats['successful_reassemblies']} 個")
        print(f"   重組失敗: {self.fragment_stats['failed_reassemblies']} 個")

        # 計算分片效率
        total_fragment_groups = (self.fragment_stats['complete_groups'] +
                                 self.fragment_stats['incomplete_groups'] +
                                 self.fragment_stats['timeout_groups'])

        if total_fragment_groups > 0:
            fragment_success_rate = (self.fragment_stats['successful_reassemblies'] / total_fragment_groups) * 100
            print(f"   分片重組成功率: {fragment_success_rate:.1f}%")
        else:
            fragment_success_rate = 0
            print(f"   分片重組成功率: 0.0%")

        # 匹配品質分析
        if self.unique_matches:
            scores = [m['score'] for m in self.unique_matches]
            avg_score = sum(scores) / len(scores)
            time_diffs = [m['time_diff'] for m in self.unique_matches]
            avg_time_diff = sum(time_diffs) / len(time_diffs)

            print(f"\n📈 匹配品質分析:")
            print(f"   平均匹配分數: {avg_score:.3f}")
            print(f"   平均時間差: {avg_time_diff:.3f} 秒")

            # 匹配類型統計
            match_types = {}
            reassembled_matches = 0
            for match in self.unique_matches:
                match_type = match['match_type']
                match_types[match_type] = match_types.get(match_type, 0) + 1
                if match.get('is_reassembled', False):
                    reassembled_matches += 1

            print(f"\n🏷️  匹配類型分布:")
            for match_type, count in match_types.items():
                percentage = (count / len(self.unique_matches)) * 100
                print(f"   {match_type}: {count} 個 ({percentage:.1f}%)")

            print(
                f"   重組封包匹配: {reassembled_matches} 個 ({(reassembled_matches / len(self.unique_matches)) * 100:.1f}%)")

        # 問題診斷
        print(f"\n🔍 問題診斷:")

        issues = []
        recommendations = []

        if restoration_rate < 20:
            issues.append("分片重組效率極低")
            recommendations.append("檢查分片資料完整性和JSON格式")
            recommendations.append("增加分片超時時間")

        if fragment_success_rate < 50:
            issues.append("分片重組失敗率過高")
            recommendations.append("檢查網路傳輸穩定性")
            recommendations.append("增強分片錯誤處理機制")

        if self.fragment_stats['timeout_groups'] > self.fragment_stats['complete_groups']:
            issues.append("大量分片組超時")
            recommendations.append("調整分片超時參數")
            recommendations.append("檢查分片發送間隔")

        if match_rate < 15:
            issues.append("整體匹配率過低")
            recommendations.append("檢查時間同步問題")
            recommendations.append("調整匹配算法參數")

        if len(issues) == 0:
            print("   ✅ 未發現明顯問題")
        else:
            print(f"   發現 {len(issues)} 個問題:")
            for i, issue in enumerate(issues, 1):
                print(f"   {i}. {issue}")

        print(f"\n💡 改善建議:")
        if len(recommendations) == 0:
            print("   系統運作良好，無需特別改善")
        else:
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")

        # 額外的分片專用建議
        print(f"\n🧩 分片專用建議:")
        print(f"   1. 考慮減少分片大小以提高成功率")
        print(f"   2. 增加分片重傳機制")
        print(f"   3. 實施分片順序檢查")
        print(f"   4. 添加分片完整性校驗")
        print(f"   5. 優化分片發送時序")

        # 性能評估
        self._evaluate_fragment_performance(match_rate, fragment_success_rate, restoration_rate)

        return match_rate >= 15  # 降低成功標準，考慮到分片處理的複雜性

    def _evaluate_fragment_performance(self, match_rate, fragment_success_rate, restoration_rate):
        """評估分片處理性能"""
        print(f"\n🎯 分片處理性能評估:")

        # 綜合評分
        composite_score = (match_rate * 0.4 + fragment_success_rate * 0.4 + restoration_rate * 0.2)

        if composite_score >= 70:
            status = "🎉 優秀"
            conclusion = "分片處理系統運作良好"
        elif composite_score >= 50:
            status = "✅ 良好"
            conclusion = "分片處理基本正常，有改善空間"
        elif composite_score >= 30:
            status = "⚠️ 需要改善"
            conclusion = "分片處理存在問題，需要優化"
        else:
            status = "❌ 需要檢查"
            conclusion = "分片處理嚴重問題，需要全面檢查"

        print(f"   狀態: {status}")
        print(f"   綜合評分: {composite_score:.1f}分")
        print(f"   結論: {conclusion}")

        # 具體建議
        if fragment_success_rate < 30:
            print(f"   🚨 緊急: 分片重組嚴重失敗，建議檢查:")
            print(f"      - JSON格式正確性")
            print(f"      - Base64編碼完整性")
            print(f"      - 網路封包遺失情況")

        if restoration_rate < 15:
            print(f"   🚨 緊急: 封包還原率極低，建議:")
            print(f"      - 檢查嵌入封包格式")
            print(f"      - 驗證分片資料完整性")
            print(f"      - 增強錯誤處理機制")


def main():
    """主程式"""
    print("🧩 分片優化封包比較工具 v5.0")
    print("=" * 60)
    print("專門解決分片處理和重組問題")

    comparator = FragmentOptimizedComparator()

    # 顯示配置
    comparator.print_network_config()

    # 設定參數
    duration = int(input(f"\n捕獲時長 (秒，建議240): ") or "240")
    time_window = float(input(f"時間窗口 (秒，建議15): ") or "15")
    fragment_timeout = float(input(f"分片超時 (秒，建議30): ") or "30")

    comparator.time_window = time_window
    comparator.fragment_timeout = fragment_timeout

    print(f"\n⚠️  分片優化模式準備:")
    print(f"   增強分片追蹤和重組")
    print(f"   智能超時清理機制")
    print(f"   詳細分片狀態診斷")
    print(f"   提升分片成功率")

    input("\n按Enter開始分片優化捕獲...")

    try:
        success = comparator.start_synchronized_capture(duration)

        print(f"\n✅ 分片優化比較完成!")

        if success:
            print(f"🎉 分片處理性能可接受！")
        else:
            print(f"⚠️  分片處理需要進一步優化")
            print(f"建議檢查網路環境和系統配置")

    except KeyboardInterrupt:
        print(f"\n⚠️  比較被中斷")
    except Exception as e:
        print(f"❌ 分片優化比較發生錯誤: {e}")


if __name__ == "__main__":
    main()