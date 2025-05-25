import json
import pyshark
import logging

# Static Variable
CONFIG_PATH = "../config.json"

# Global Variable
config = None
interface = None
port = None
service_type = None
time_gap = None


def load_config():
    global config
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        print(f"Config loaded: {config}")
    except FileNotFoundError:
        print(f"Config file not found at {CONFIG_PATH}")
        raise
    except json.JSONDecodeError:
        print("Invalid JSON format in config file")
        raise


def apply_config():
    global config, interface, port, service_type, time_gap

    if config is None:
        raise ValueError("Config not loaded. Call load_config() first.")

    interface = str(config["interface"])
    port = str(config["port"])
    service_type = str(config["service_type"])
    time_gap = str(config["time_gap"])

    print(f"Applied config - Interface: {interface}, Port: {port}")


def catch_package():
    global interface, port

    try:
        display_filter = f"tcp.srcport == {port}"
        print(f"Using display filter: {display_filter}")

        capture_flow = pyshark.LiveCapture(
            interface=interface,
            display_filter=display_filter
        )
        capture_flow.set_debug()

        print(f"Starting packet capture on interface {interface}...")

        for package in capture_flow.sniff_continuously():
            # 檢查封包是否包含 HTTP 層
            if hasattr(package, 'http'):
                print(f"HTTP packet captured: {package}")
                # 可以進一步處理 HTTP 封包
                if hasattr(package.http, 'request_method'):
                    print(f"HTTP Method: {package.http.request_method}")
                if hasattr(package.http, 'host'):
                    print(f"HTTP Host: {package.http.host}")
            else:
                # 顯示其他 TCP 封包的基本資訊
                print(
                    f"TCP packet - Source: {package.ip.src}:{package.tcp.srcport} -> Dest: {package.ip.dst}:{package.tcp.dstport}")

    except KeyboardInterrupt:
        print("\nCapture interrupted by user")
    except Exception as e:
        print(f"Error during packet capture: {e}")
        raise


def main():
    try:
        load_config()
        apply_config()
        catch_package()
    except Exception as e:
        print(f"Error in main: {e}")
        return 1
    return 0


if __name__ == '__main__':
    exit(main())