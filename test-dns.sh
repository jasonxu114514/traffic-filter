#!/bin/bash

# DNS 污染測試腳本

echo "=== DNS 污染功能測試 ==="
echo ""

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 檢查是否為 root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}錯誤: 請使用 root 權限運行此腳本${NC}"
    echo "用法: sudo $0"
    exit 1
fi

# 檢查程序是否存在
if [ ! -f "./traffic-filter" ]; then
    echo -e "${RED}錯誤: traffic-filter 程序不存在${NC}"
    echo "請先運行 'make build' 或 './build.sh'"
    exit 1
fi

# 獲取默認網絡接口
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

if [ -z "$DEFAULT_IFACE" ]; then
    echo -e "${RED}錯誤: 無法找到默認網絡接口${NC}"
    exit 1
fi

echo -e "${GREEN}使用網絡接口: $DEFAULT_IFACE${NC}"
echo ""

# 測試域名
TEST_DOMAIN="test-block.example.com"

echo "=== 測試 1: DROP 模式 ==="
echo "啟動過濾器 (DROP 模式)..."

# 在後台啟動過濾器
timeout 10s ./traffic-filter -iface "$DEFAULT_IFACE" \
    -domains "$TEST_DOMAIN" \
    -dns-mode drop &
FILTER_PID=$!

sleep 2

# 測試 DNS 查詢
echo "測試 DNS 查詢: $TEST_DOMAIN"
timeout 3s dig @127.0.0.1 "$TEST_DOMAIN" > /dev/null 2>&1
if [ $? -eq 124 ]; then
    echo -e "${GREEN}✓ DROP 模式工作正常（查詢超時）${NC}"
else
    echo -e "${YELLOW}⚠ DROP 模式可能未生效${NC}"
fi

# 停止過濾器
kill $FILTER_PID 2>/dev/null
wait $FILTER_PID 2>/dev/null

echo ""
echo "=== 測試 2: POISON 模式 ==="
echo "啟動過濾器 (POISON 模式)..."

# 在後台啟動過濾器
timeout 10s ./traffic-filter -iface "$DEFAULT_IFACE" \
    -domains "$TEST_DOMAIN" \
    -dns-mode poison &
FILTER_PID=$!

sleep 2

# 測試 DNS 查詢
echo "測試 DNS 查詢: $TEST_DOMAIN"
RESULT=$(timeout 3s dig @127.0.0.1 "$TEST_DOMAIN" 2>&1)

if echo "$RESULT" | grep -q "NXDOMAIN"; then
    echo -e "${GREEN}✓ POISON 模式工作正常（返回 NXDOMAIN）${NC}"
else
    echo -e "${YELLOW}⚠ POISON 模式可能未生效${NC}"
fi

# 停止過濾器
kill $FILTER_PID 2>/dev/null
wait $FILTER_PID 2>/dev/null

echo ""
echo "=== 測試完成 ==="
echo ""
echo "提示："
echo "1. 這些測試是基本的功能驗證"
echo "2. 實際效果取決於網絡配置和 DNS 服務器設置"
echo "3. 要測試真實場景，請使用實際的域名和客戶端應用"
echo ""
echo "手動測試命令示例："
echo "  sudo ./traffic-filter -iface $DEFAULT_IFACE -domains \"pornhub.com,www.pornhub.com\" -dns-mode poison"
echo ""
echo "在另一個終端測試："
echo "  dig pornhub.com"
echo "  curl -v http://pornhub.com"
echo "  curl -v https://pornhub.com"
