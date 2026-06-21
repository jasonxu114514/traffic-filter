# 接下來的步驟 (遠端 Linux)

代碼已經在本地恢復完成並提交到 git。接下來需要在遠端 Linux 機器上執行：

## 快速開始 (複製貼上即可)

```bash
# 1. 拉取最新代碼
git pull

# 2. 安裝依賴 (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y clang-14 llvm-14 libbpf-dev linux-headers-$(uname -r) golang-go

# 3. 編譯
make clean
make build

# 4. 測試 (需要 sudo)
sudo ./traffic-filter -iface eth0 -domains "example.com"

# 5. 另開一個 terminal 測試效果
curl http://example.com  # 應該失敗 (Connection reset)
curl http://google.com   # 應該正常
```

## 檢查系統需求

```bash
# Kernel 版本 (需要 >= 5.4)
uname -r

# BPF 支持
zgrep CONFIG_BPF /proc/config.gz

# 網卡名稱
ip link show
```

## 如果編譯失敗

查看 `DEPLOY.md` 的「常見問題」章節，包含所有可能的錯誤和解決方法。

## 檔案說明

- `README.md` - 完整的項目文檔和使用說明
- `DEPLOY.md` - 遠端 Linux 部署指南，包含故障排除
- `STATUS.md` - 問題分析和技術背景
- `Makefile` - 新的 eBPF 編譯 Makefile (自動選擇 clang-14/17)
- `bpf/traffic_filter.c` - 596 行 eBPF/XDP C 程序
- `pkg/filter/filter.go` - Go BPF loader
- `pkg/config/config.go` - 配置系統
- `cmd/traffic-filter/main.go` - 主程序

## 為什麼要回歸 eBPF

當前的 AF_PACKET/AF_INET 方案**無法阻擋本機流量**，這是 Linux 網路棧的基本限制：

```
本機發送的封包: 
  App → TCP stack → NIC → 外部網路
          ↑
      AF_PACKET 捕獲到 ✓

我們注入的 RST:
  raw socket → NIC → 外部網路
  ✗ 不會回到本機 TCP stack
  ✗ App 看不到 RST
```

只有 eBPF/XDP 能在封包**進入 TCP stack 之前** DROP 掉：

```
NIC → XDP hook (DROP) ✓ → (封包到不了 TCP stack)
```

## 推送代碼 (如果還沒推送)

```bash
git push origin master
```

然後在遠端 Linux:

```bash
git pull
```

## 預期結果

編譯成功後應該生成:
- `bpf/traffic_filter.o` - eBPF 目標檔
- `pkg/filter/bpf_bpfel.go` - Go bindings (自動生成)
- `traffic-filter` - 可執行檔

運行成功後應該看到:
```
INFO[0000] Traffic Filter — eBPF/XDP mode
INFO[0000] Loaded eBPF objects
INFO[0000] Added domain: example.com
INFO[0000] Attached XDP to eth0
INFO[0000] Filter active. Press Ctrl+C to stop.
```

測試 `curl http://example.com` 應該失敗 (Connection reset 或 timeout)。

## 如果遇到問題

1. 查看 `DEPLOY.md` 的故障排除章節
2. 檢查 kernel 版本和 BPF 支持
3. 檢查依賴是否完整安裝
4. 記錄完整錯誤訊息

祝編譯順利！🚀
