# ══════════════════════════════════════════════════════════════
# JC Company Payment API — CIS Docker Hardened (NIST 800-190)
# ══════════════════════════════════════════════════════════════

# ── Stage 1: Build ───────────────────────────────────────────
FROM eclipse-temurin:17-jdk-jammy AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

# ── Stage 2: OTel Agent (SHA-verified / SP 800-204D §5.1.1) ─
FROM eclipse-temurin:17-jdk-jammy AS otel-agent
ARG OTEL_VERSION=2.28.1
ARG OTEL_SHA256=faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN curl -sSfL \
  https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/download/v${OTEL_VERSION}/opentelemetry-javaagent.jar \
  -o /opentelemetry-javaagent.jar && \
  echo "${OTEL_SHA256}  /opentelemetry-javaagent.jar" | sha256sum -c -

# ── Stage 3: Runtime (Alpine minimal / CIS Docker 4.2) ──────
FROM eclipse-temurin:17-jre-alpine

LABEL maintainer="jccompany" \
      description="Payment API — CIS Docker Hardened" \
      org.opencontainers.image.source="https://github.com/s1ns3nz0/payment-api"

WORKDIR /app

# Non-root user (CIS Docker 4.1 / NIST 800-190 §4.1)
RUN addgroup -S appuser && adduser -S -G appuser appuser

# No curl, no bash, no package manager in runtime (CIS Docker 4.7 / NSA/CISA §2.2)
# K8s livenessProbe/readinessProbe handles health checks

USER appuser:appuser

COPY --from=otel-agent --chown=appuser:appuser \
    /opentelemetry-javaagent.jar opentelemetry-javaagent.jar
COPY --from=builder --chown=appuser:appuser \
    /app/target/payment-api-1.0.0-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", \
    "-javaagent:/app/opentelemetry-javaagent.jar", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-Dotel.service.name=payment-api", \
    "-Dotel.exporter.otlp.endpoint=http://localhost:4317", \
    "-Dotel.exporter.otlp.protocol=grpc", \
    "-Dotel.logs.exporter=otlp", \
    "-Dotel.metrics.exporter=otlp", \
    "-Dotel.traces.exporter=otlp", \
    "-Dotel.instrumentation.logback-appender.enabled=true", \
    "-jar", "app.jar"]
