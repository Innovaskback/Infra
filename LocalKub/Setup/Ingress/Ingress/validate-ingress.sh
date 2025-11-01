#!/bin/bash
# ==============================================================================
# Script للتحقق من إعدادات Ingress Controller (READ-ONLY - للتشخيص فقط)
# ==============================================================================
# ⚠️ ملاحظة مهمة: هذا الـ script للتشخيص فقط ولا يعدل أي إعدادات
# الإعدادات الفعلية تتم عبر:
# 1. GitHub Actions workflow (validation + auto-fix)
# 2. Ingress_ip.yaml (تطبيق الموارد)
# ==============================================================================
# استخدم هذا الـ script فقط عند مواجهة مشاكل أو للتحقق اليدوي
# عدم تنفيذه لن يؤثر على عمل الإعدادات
# ==============================================================================

set -e

echo "🔍 التحقق من إعدادات Ingress Controller..."
echo ""

# الألوان للـ output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

# 1. التحقق من وجود Ingress Controller Service
echo "1️⃣  التحقق من Ingress Controller Service..."
if kubectl get svc -n ingress-nginx ingress-nginx-controller > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Ingress Controller Service موجود${NC}"
    
    # التحقق من نوع Service
    INGRESS_TYPE=$(kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.spec.type}')
    if [ "$INGRESS_TYPE" = "LoadBalancer" ]; then
        echo -e "${GREEN}✅ Service من نوع LoadBalancer${NC}"
        
        # التحقق من EXTERNAL-IP
        EXTERNAL_IP=$(kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
        if [ -z "$EXTERNAL_IP" ]; then
            echo -e "${YELLOW}⚠️  WARNING: لا يوجد EXTERNAL-IP معيّن${NC}"
            echo "   تحقق من MetalLB configuration"
            WARNINGS=$((WARNINGS + 1))
        else
            echo -e "${GREEN}✅ EXTERNAL-IP: $EXTERNAL_IP${NC}"
        fi
    else
        echo -e "${RED}❌ ERROR: Service من نوع $INGRESS_TYPE وليس LoadBalancer${NC}"
        echo "   قم بتشغيل:"
        echo "   kubectl patch svc -n ingress-nginx ingress-nginx-controller --type merge -p '{\"spec\":{\"type\":\"LoadBalancer\"}}'"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${RED}❌ ERROR: Ingress Controller Service غير موجود${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 2. التحقق من MetalLB
echo "2️⃣  التحقق من MetalLB..."
METALLB_CONTROLLER=$(kubectl get pods -n metallb-system -l app.kubernetes.io/component=controller --no-headers 2>/dev/null | wc -l)
METALLB_SPEAKER=$(kubectl get pods -n metallb-system -l app.kubernetes.io/component=speaker --no-headers 2>/dev/null | wc -l)

if [ "$METALLB_CONTROLLER" -gt 0 ] && [ "$METALLB_SPEAKER" -gt 0 ]; then
    echo -e "${GREEN}✅ MetalLB Controller و Speaker يعملان${NC}"
    
    # التحقق من IP Address Pool
    if kubectl get ipaddresspool -n metallb-system production-ip-pool > /dev/null 2>&1; then
        echo -e "${GREEN}✅ IP Address Pool موجود${NC}"
        IP_POOL=$(kubectl get ipaddresspool -n metallb-system production-ip-pool -o jsonpath='{.spec.addresses[0]}')
        echo "   IP Pool: $IP_POOL"
    else
        echo -e "${YELLOW}⚠️  WARNING: IP Address Pool غير موجود${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${RED}❌ ERROR: MetalLB غير موجود أو لا يعمل${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 3. التحقق من Ingress Resource
echo "3️⃣  التحقق من Ingress Resource..."
if kubectl get ingress -n production ingress-auth-api > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Ingress Resource موجود${NC}"
    
    INGRESS_ADDRESS=$(kubectl get ingress -n production ingress-auth-api -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    if [ -z "$INGRESS_ADDRESS" ]; then
        echo -e "${YELLOW}⚠️  WARNING: Ingress Address غير معيّن${NC}"
        WARNINGS=$((WARNINGS + 1))
    else
        echo -e "${GREEN}✅ Ingress Address: $INGRESS_ADDRESS${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  WARNING: Ingress Resource غير موجود${NC}"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# 4. التحقق من Service Endpoints
echo "4️⃣  التحقق من Service Endpoints..."
ENDPOINTS=$(kubectl get endpoints -n production ba-auth-api -o jsonpath='{.subsets[0].addresses[*].ip}' 2>/dev/null)
if [ -z "$ENDPOINTS" ]; then
    echo -e "${RED}❌ ERROR: Service Endpoints فارغة${NC}"
    echo "   تحقق من أن Pods تعمل: kubectl get pods -n production -l app=ba-auth-api"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✅ Service Endpoints: $ENDPOINTS${NC}"
fi
echo ""

# 5. التحقق من Pods
echo "5️⃣  التحقق من Pods..."
READY_PODS=$(kubectl get pods -n production -l app=ba-auth-api --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
if [ "$READY_PODS" -gt 0 ]; then
    echo -e "${GREEN}✅ هناك $READY_PODS Pod(s) يعمل(ون)${NC}"
else
    echo -e "${RED}❌ ERROR: لا توجد Pods تعمل${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ملخص
echo "=========================================="
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✅ جميع التحققيات نجحت!${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠️  التحققيات نجحت مع $WARNINGS تحذير(ات)${NC}"
    exit 0
else
    echo -e "${RED}❌ فشل $ERRORS تحقق(ات)${NC}"
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}   و $WARNINGS تحذير(ات)${NC}"
    fi
    exit 1
fi

