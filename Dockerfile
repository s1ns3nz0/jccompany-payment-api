# ── Stage 1: Build ──────────────────────────────────────────
FROM eclipse-temurin:17-jdk-jammy AS builder

WORKDIR /app

# Maven 설치
RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*

COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests -q

# ── Stage 2: Runtime ─────────────────────────────────────────
FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser:appuser

COPY --from=builder --chown=appuser:appuser \
    /app/target/payment-api-1.0.0-SNAPSHOT.jar app.jar

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", "app.jar"]
