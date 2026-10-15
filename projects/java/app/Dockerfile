FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B package -DskipTests

FROM eclipse-temurin:21-jre-jammy

WORKDIR /srv/toolshed

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/toolshed-1.4.2.jar ./toolshed.jar
COPY openapi.yml ./

ENV TOOLSHED_DB=/srv/toolshed/var/toolshed.db \
    TOOLSHED_UPLOADS=/srv/toolshed/var/uploads \
    PORT=8000

RUN mkdir -p /srv/toolshed/var/uploads

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --retries=18 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["java", "-jar", "toolshed.jar"]
