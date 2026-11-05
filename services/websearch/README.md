# Web Search Service (SearXNG)

The Web Search service provides a self-hosted, privacy-respecting meta-search engine powered by [SearXNG](https://github.com/searxng/searxng). It is designed to act as a grounded search backend for Open WebUI (`services/llm`) and local/remote LLM workflows without relying on external commercial search APIs.

## Highlights

- **Privacy-First**: No tracking, search history profiling, or external query telemetry.
- **Aggregated Engines**: Queries multiple privacy-friendly search backends (DuckDuckGo, Brave, Wikipedia, Mojeek, Wikidata).
- **JSON API Enabled**: `search.formats: [html, json]` is explicitly configured to enable Open WebUI RAG retrieval.
- **Internal Isolation**: Service is exposed exclusively to the internal Docker network `nginx_network` at static IP `172.22.0.15` (port `8080`) and aliased as `searxng`. No external host ports are published.
- **Limiter Disabled**: Built-in rate limiter is disabled (`server.limiter: false`) to prevent internal concurrent search drops during RAG scraping.

---

## 1. Configuration & Environment

Copy the example environment file if not already created:
```bash
cp .env.example .env
```

Generate a random secret key for `SEARXNG_SECRET`:
```bash
openssl rand -hex 32
```
Update `SEARXNG_SECRET` in `.env` with the generated value.

---

## 2. Managing the Service

Start, stop, or restart the service using the NAL service manager:

```bash
# From repository root
./manage-services.sh start websearch
./manage-services.sh stop websearch
./manage-services.sh restart websearch
```

Alternatively, manage directly with Docker Compose:

```bash
docker compose up -d
docker compose down
```

---

## 3. Testing Endpoint

From any container connected to `nginx_network`:

```bash
curl -s "http://searxng:8080/search?q=test&format=json" | grep -q "results"
```
