# ── Stage 1: Build ──────────────────────────────────────────
FROM eclipse-temurin:17-jdk-jammy AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests -q

# ── Stage 2: OTel Agent 다운로드 ─────────────────────────────
FROM eclipse-temurin:17-jdk-jammy AS otel-agent
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN curl -sSfL \
  https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/download/v2.2.0/opentelemetry-javaagent.jar \
  -o /opentelemetry-javaagent.jar

# ── Stage 3: Runtime ─────────────────────────────────────────
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser:appuser

COPY --from=otel-agent --chown=appuser:appuser \
    /opentelemetry-javaagent.jar opentelemetry-javaagent.jar

COPY --from=builder --chown=appuser:appuser \
    /app/target/payment-api-1.0.0-SNAPSHOT.jar app.jar

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

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
