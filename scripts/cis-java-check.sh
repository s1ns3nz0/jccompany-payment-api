#!/bin/bash
# CIS Java Benchmark Check - JC Company payment-api
# 근거: CIS Java Benchmark v1.0 + NIST 800-53 통제 매핑
# 통제: CM-7 (최소 기능), SC-8 (전송 보안), SC-13 (암호화),
#       CM-2 (기준선 구성), AU-2 (감사 로깅)

PASS=0
FAIL=0
WARN=0
PROPS="src/main/resources/application.properties"
DOCKERFILE="Dockerfile"

check_pass() { echo "✅ PASS | $1"; PASS=$((PASS+1)); }
check_fail() { echo "❌ FAIL | $1 | $2"; FAIL=$((FAIL+1)); }
check_warn() { echo "⚠️  WARN | $1 | $2"; WARN=$((WARN+1)); }

echo "================================================"
echo " CIS Java Benchmark Check - payment-api"
echo " NIST 800-53 통제 매핑 포함"
echo "================================================"
echo ""

echo "--- §1. JVM 설정 (CM-7: 최소 기능) ---"

# 1.1 원격 디버깅 비활성화
if grep -q "agentlib:jdwp\|jdwp" "$DOCKERFILE" 2>/dev/null; then
  check_fail "원격 디버깅 비활성화" "Dockerfile에 JDWP 설정 발견 (CM-7 위반)"
else
  check_pass "원격 디버깅 비활성화 확인 (CM-7)"
fi

# 1.2 JMX 원격 접속 비활성화
if grep -q "com.sun.management.jmxremote" "$DOCKERFILE" 2>/dev/null; then
  check_fail "JMX 원격 접속 비활성화" "Dockerfile에 JMX remote 설정 발견 (CM-7 위반)"
else
  check_pass "JMX 원격 접속 비활성화 확인 (CM-7)"
fi

# 1.3 비루트 사용자로 JVM 실행
if grep -q "^USER " "$DOCKERFILE" 2>/dev/null; then
  check_pass "비루트 사용자 실행 확인 (CM-7, AC-6)"
else
  check_fail "비루트 사용자 실행" "Dockerfile에 USER 선언 없음 (CM-7 위반)"
fi

echo ""
echo "--- §2. TLS/암호화 설정 (SC-8, SC-13) ---"

# 2.1 TLS 버전 명시
if grep -q "ssl.enabled-protocols" "$PROPS" 2>/dev/null; then
  TLS_VER=$(grep "ssl.enabled-protocols" "$PROPS")
  if echo "$TLS_VER" | grep -q "TLSv1\.2\|TLSv1\.3"; then
    check_pass "TLS 1.2+ 명시적 설정 (SC-8)"
  else
    check_fail "TLS 버전 설정" "TLS 1.2 미만 버전 허용 (SC-8 위반)"
  fi
else
  check_warn "TLS 버전 미명시" "운영환경에서 TLS 1.2+ 명시 필요 (SC-8)"
fi

# 2.2 약한 암호화 알고리즘 확인 (Semgrep과 다른 레이어 - 설정 파일 기준)
if grep -qE "MD5|SHA1|DES|RC4" "$PROPS" 2>/dev/null; then
  check_fail "약한 암호화 알고리즘" "application.properties에 취약한 알고리즘 발견 (SC-13 위반)"
else
  check_pass "약한 암호화 알고리즘 미사용 (SC-13)"
fi

echo ""
echo "--- §3. 불필요한 기능 비활성화 (CM-7) ---"

# 3.1 H2 콘솔 비활성화
if grep -q "h2-console.enabled=true" "$PROPS" 2>/dev/null; then
  check_fail "H2 콘솔 비활성화" "운영환경 H2 콘솔 노출 위험 (CM-7 위반)"
else
  check_pass "H2 콘솔 비활성화 확인 (CM-7)"
fi

# 3.2 디버그 모드 비활성화
if grep -q "^debug=true\|logging.level.root=DEBUG" "$PROPS" 2>/dev/null; then
  check_fail "디버그 모드 비활성화" "디버그 모드 활성화 (CM-7, AU-2 위반)"
else
  check_pass "디버그 모드 비활성화 확인 (CM-7)"
fi

# 3.3 Actuator 노출 최소화
ACTUATOR=$(grep "management.endpoints.web.exposure.include" "$PROPS" 2>/dev/null)
if [ -n "$ACTUATOR" ]; then
  if echo "$ACTUATOR" | grep -q '"*"\|\*'; then
    check_fail "Actuator 엔드포인트 최소화" "모든 엔드포인트 노출 (CM-7 위반)"
  else
    check_warn "Actuator 엔드포인트 노출" "$ACTUATOR - 최소화 권장 (CM-7)"
  fi
else
  check_pass "Actuator 엔드포인트 기본값 (CM-7)"
fi

# 3.4 Spring Boot Admin 비활성화 확인
if grep -q "spring.boot.admin" "$PROPS" 2>/dev/null; then
  check_warn "Spring Boot Admin 설정" "운영환경 노출 여부 확인 필요 (CM-7)"
else
  check_pass "Spring Boot Admin 미사용 (CM-7)"
fi

echo ""
echo "--- §4. 감사 로깅 (AU-2, AU-9) ---"

# 4.1 로깅 설정 존재
if grep -q "logging.level\|logging.file\|logging.pattern" "$PROPS" 2>/dev/null; then
  check_pass "로깅 설정 존재 (AU-2)"
else
  check_warn "로깅 설정 없음" "감사 로깅 설정 필요 (AU-2)"
fi

# 4.2 민감정보 로깅 패턴 확인
if grep -qE "password|secret|token|key" "$PROPS" 2>/dev/null | grep -v "encrypt\|masked"; then
  check_warn "민감정보 로깅 가능성" "설정 파일에 민감정보 패턴 (AU-9)"
else
  check_pass "민감정보 로깅 패턴 미발견 (AU-9)"
fi

echo ""
echo "--- §5. 의존성 보안 (SR-3) ---"

# 5.1 SNAPSHOT 버전 사용 확인
if grep -q "SNAPSHOT" pom.xml 2>/dev/null; then
  check_warn "SNAPSHOT 버전 사용" "운영환경 SNAPSHOT 버전 사용 주의 (SR-3)"
else
  check_pass "SNAPSHOT 버전 미사용 (SR-3)"
fi

# 5.2 의존성 버전 고정 확인
if grep -q "<version>\${" pom.xml 2>/dev/null; then
  check_warn "동적 버전 사용" "일부 의존성 버전 미고정 (SR-3)"
else
  check_pass "의존성 버전 고정 확인 (SR-3)"
fi

echo ""
echo "================================================"
echo " Results: ✅ $PASS passed | ❌ $FAIL failed | ⚠️  $WARN warnings"
echo "================================================"

# FAIL이 있으면 exit 1
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
