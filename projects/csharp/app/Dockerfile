FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src
COPY Toolshed.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:8.0

WORKDIR /srv/toolshed

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out ./
COPY openapi.yml ./

ENV TOOLSHED_DB=/srv/toolshed/var/toolshed.db \
    TOOLSHED_UPLOADS=/srv/toolshed/var/uploads \
    PORT=8000

RUN mkdir -p /srv/toolshed/var/uploads

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --retries=18 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["dotnet", "Toolshed.dll"]
