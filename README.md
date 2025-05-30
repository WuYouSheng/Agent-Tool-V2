# Agent-Tool-V2 網路封包處理系統

這是一個雙模式的網路封包監控和處理系統，支援被監控端和監控端的分散式架構。

## 🏗️ 系統架構

### 被監控端 (Monitored)
- 監控本機指定介面和端口的網路流量
- 首次發現封包時發送Signal給監控端標識來源
- 將捕獲的封包嵌入並轉發給監控端
- 支援大型封包的自動分片處理

### 監控端 (Surveiling) 
- 同時監聽Signal端口和嵌入封包端口
- 接收並記錄來源主機的Signal標識
- 自動重組分片封包並還原原始封包
- 對還原的封包進行分析和處理

## 📁 資料夾結構

```
Agent-Tool-V2/
├── config.json                    # 主配置檔案
├── Monitored/                     # 被監控端模組
│   ├── Filter.py                  # 封包過濾器
│   ├── SignalGen.py               # 信號產生器
│   ├── Embedding.py               # 封包嵌入模組
│   ├── Monitored.py               # 被監控端主程式
│   └── config_monitored.json      # 被監控端專用配置
├── Surveiling/                    # 監控端模組
│   ├── Analyst.py                 # 監控端主程式
│   └── config_surveiling.json     # 監控端專用配置
└── README.md                      # 說明文件
```

## ⚙️ 配置說明

### 被監控端配置 (config_monitored.json)
```json
{
  "interface": "eth0",              # 監聽的網路介面
  "port": "80",                     # 監聽的端口
  "service_type": "Monitored",      # 服務類型
  "time_gap": 1,                    # 處理間隔（秒）
  "signal_target_ip": "192.168.1.200",     # 監控端IP
  "signal_target_port": 8080,       # 監控端Signal端口
  "embed_target_ip": "192.168.1.200",      # 監控端IP
  "embed_target_port": 9090,        # 監控端嵌入封包端口
  "max_packet_size": 1400           # 最大封包大小（bytes）
}
```

### 監控端配置 (config_surveiling.json)
```json
{
  "service_type": "Surveiling",     # 服務類型
  "signal_listen_port": 8080,       # 監聽Signal的端口
  "embed_listen_port": 9090         # 監聽嵌入封包的端口
}
```

## 🚀 安裝與使用

### 安裝依賴
```bash
pip install pyshark scapy
```

### 被監控端部署
```bash
cd Monitored/
cp config_monitored.json ../config.json
# 修改 config.json 中的監控端IP位址
python Monitored.py
```

### 監控端部署
```bash
cd Surveiling/
cp config_surveiling.json ../config.json
python Analyst.py
```

## 🔄 工作流程

### 被監控端流程
1. 🔍 監聽指定介面和端口的封包
2. 📤 首次發現封包時發送Signal給監控端
3. 📦 將封包嵌入、分片（如需要）並發送
4. 🔄 後續封包直接嵌入轉發（不再發送Signal）

### 監控端流程
1. 🔍 同時監聽兩個端口（Signal + 嵌入封包）
2. 🚨 接收Signal並記錄來源主機
3. 📥 接收嵌入封包，重組分片（如需要）
4. 🎯 還原原始封包並進行分析

## 📊 輸出示例

### 被監控端輸出
```
🚀 啟動被監控端系統...
服務模式: Monitored（被監控端）
🔍 開始監聽本機封包流量...

============================================================
處理封包 #1 (被監控端模式)
============================================================
🚀 步驟1: 發送信號封包（首次識別本機）...
   ✅ 信號封包已發送至監控端 192.168.1.200:8080
📦 步驟2: 嵌入並轉發封包到監控端...
   ✅ 封包已嵌入並轉發至監控端 192.168.1.200:9090

📊 處理結果:
   信號發送: ✅ 成功
   封包轉發: ✅ 成功
   已處理封包總數: 1
   標識狀態: ✅ 已標識
```

### 監控端輸出
```
🚀 啟動監控端系統...
服務模式: Surveiling（監控端）
🔍 開始監聽Signal和嵌入封包...

🚨 收到信號封包 #1!
   來源: 192.168.1.100:54321
   時間戳: 2025-01-26T15:30:15.123456
   UUID: 550e8400-e29b-41d4-a716-446655440000
   ✅ 信號已記錄，來源主機 192.168.1.100 已識別

📥 收到嵌入封包
   來源: 192.168.1.100:54322
   大小: 1024 bytes

🎯 還原原始封包:
   嵌入UUID: 123e4567-e89b-12d3-a456-426614174000
   原始來源: 192.168.1.100:12345
   原始目標: 8.8.8.8:80
   ✅ 原始封包重建成功
   🔍 封包分析:
      IP: 192.168.1.100 -> 8.8.8.8
      TCP: Port 12345 -> 80
      HTTP請求: GET / HTTP/1.1...
```

## ✨ 主要功能

### 被監控端功能
- ✅ 本機流量監控
- ✅ 首次Signal標識
- ✅ 封包嵌入和自動分片
- ✅ 可靠的封包轉發
- ✅ 詳細處理日誌

### 監控端功能
- ✅ 多執行緒並行監聽
- ✅ 來源主機自動識別
- ✅ 分片封包自動重組
- ✅ 原始封包完整還原
- ✅ 封包內容深度分析

## 🔧 技術特性

### 分片處理
- 自動檢測大型封包並分片
- 每個分片有唯一UUID和索引
- 監控端自動重組還原
- 預設最大封包大小1400bytes（可調整）

### 錯誤處理
- 完整的異常捕獲和處理
- 網路連接失敗自動重試
- 優雅的系統關閉機制
- 詳細的錯誤日誌記錄

### 效能優化
- 多執行緒並行處理
- 分片間微秒級延遲控制
- 記憶體使用優化
- 網路傳輸效率最佳化

## 🛠️ 進階設定

### 自訂分片大小
在被監控端配置中調整 `max_packet_size` 參數：
```json
"max_packet_size": 1200  // 較小的分片大小
```

### 調整處理間隔
在被監控端配置中調整 `time_gap` 參數：
```json
"time_gap": 0  // 無延遲，最大處理速度
```

### 變更監聽端口
在監控端配置中調整端口設定：
```json
"signal_listen_port": 8081,
"embed_listen_port": 9091
```

## 🔒 安全注意事項

1. **網路權限**: 執行時需要適當的網路監聽權限
2. **防火牆設定**: 確保監控端端口未被防火牆阻擋
3. **資料加密**: 生產環境建議對傳輸資料進行加密
4. **存取控制**: 限制只有授權主機可以連接監控端

## 🐛 疑難排解

### 常見問題

**Q: 被監控端無法捕獲封包**
A: 檢查網路介面名稱是否正確，確認有適當權限

**Q: 監控端收不到Signal**
A: 檢查防火牆設定，確認端口開放

**Q: 分片重組失敗**
A: 檢查網路穩定性，調整max_packet_size參數

**Q: 封包還原失敗**
A: 檢查Scapy版本相容性，確認封包格式正確

## 📝 開發說明

### 模組說明
- **Filter.py**: 純封包過濾功能，支援回調機制
- **SignalGen.py**: TCP信號發送，包含UUID和時間戳
- **Embedding.py**: 封包嵌入和分片，支援完整重組
- **Monitored.py**: 被監控端主控邏輯
- **Analyst.py**: 監控端分析和處理邏輯

### 擴展開發
系統採用模組化設計，可以輕鬆擴展：
- 新增封包分析模組
- 實作資料庫記錄功能
- 增加告警通知機制
- 支援更多協議解析

## 📄 授權

本專案採用 MIT 授權條款。

## 🤝 貢獻

歡迎提交 Issue 和 Pull Request 來改善此專案。