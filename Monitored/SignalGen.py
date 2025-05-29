import socket
import json
import time
import uuid
from datetime import datetime

class SignalGenerator:
    def __init__(self, target_ip, target_port,current_uuid):
        self.target_ip = target_ip
        self.target_port = target_port
        self.current_uuid = current_uuid


    def generate_signal_packet(self):
        """產生包含當前時間和UUID的信號封包內容"""
        signal_data = {
            "timestamp": datetime.now().isoformat(),
            "uuid": self.current_uuid,
            "signal_type": "packet_detected"
        }
        return json.dumps(signal_data).encode('utf-8')

    def send_tcp_signal(self):
        """發送TCP信號封包到目標主機"""
        try:
            # 建立TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # AF_INET表示使用IPv4, SOCK_STREAM表示使用TCP協定
            sock.settimeout(5)  # 設定5秒超時

            # 連接到目標主機
            sock.connect((self.target_ip, self.target_port))

            # 產生並發送信號封包
            signal_packet = self.generate_signal_packet()
            sock.send(signal_packet)

            print(f"信號封包已發送到 {self.target_ip}:{self.target_port}")
            print(f"封包內容: {signal_packet.decode('utf-8')}")

            sock.close()
            return True

        except socket.timeout:
            print(f"連接到 {self.target_ip}:{self.target_port} 超時")
            return False
        except ConnectionRefusedError:
            print(f"無法連接到 {self.target_ip}:{self.target_port} - 連接被拒絕")
            return False
        except Exception as e:
            print(f"發送信號封包時發生錯誤: {e}")
            return False

def send_signal(target_ip, target_port, current_uuid):
    """外部調用函數"""
    generator = SignalGenerator(target_ip, target_port,current_uuid)
    return generator.send_tcp_signal()


if __name__ == "__main__":
    # 測試用途
    test_ip = "10.52.52.100"
    test_port = 9999
    send_signal(test_ip, test_port)