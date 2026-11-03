# LiteLLM Gateway Service

The LiteLLM Gateway (`litellm-gateway`) provides a unified, centralized inference proxy and protocol translator for the NAL infrastructure. It bridges downstream applications (such as Open WebUI in `services/llm` and local developer tooling) with bare-metal ML inference engines (such as oMLX running on Atlas; see [`daemons/omlx`](../../daemons/omlx/README.md)).

## Highlights

- **Dual Protocol Support**: Native OpenAI (`/v1/chat/completions`) and Anthropic (`/v1/messages`) compatibility with tool/function calling support.
- **Dynamic Routing**: Routes model requests through environment-driven base URLs (`os.environ/ATLAS_API_BASE`) with wildcard fallback (`*`).
- **SSO & RBAC**: Authentik Generic OIDC SSO integration for the LiteLLM Admin UI.
- **Database Persistence**: Stores keys, team permissions, model metadata, and usage tracking in PostgreSQL (`services/db`).
- **Local Isolation**: Port `4000` is bound locally to `127.0.0.1` and exposed to the internal Docker network `nginx_network` at `172.22.0.14`.

---

## 1. Prerequisites & Database Initialization

LiteLLM requires PostgreSQL database credentials (`LITELLM_DB_USER`, `LITELLM_DB_PASS`, `LITELLM_DB_NAME`).

### Fresh PostgreSQL Deployment
If initializing `services/db` from scratch, PostgreSQL will automatically execute `services/db/init/40-litellm.sh` upon first container startup.

### Existing PostgreSQL Data Volume
If the PostgreSQL container is already running with an existing data volume, `/docker-entrypoint-initdb.d/` scripts will **not** be executed automatically. You must run the provisioning script manually:

```bash
# Execute initialization script against running PostgreSQL container
docker exec -i postgres psql -U postgres < services/db/init/40-litellm.sh
```

Alternatively, run the SQL commands directly via `psql`:

```bash
docker exec -it postgres psql -U postgres -c "CREATE USER litellm WITH PASSWORD 'your_password';"
docker exec -it postgres psql -U postgres -c "CREATE DATABASE litellm OWNER litellm;"
```

---

## 2. Configuration & Environment

Copy the example environment file:
```bash
cp .env.example .env
```

Key configuration variables:
| Variable | Description | Default |
| --- | --- | --- |
| `ATLAS_HOST` | Host IP address of the Atlas inference server | `182.168.0.100` |
| `LITELLM_MASTER_KEY` | Admin master key for key management and LiteLLM dashboard | `sk-master-change-me` |
| `LITELLM_SALT_KEY` | Key salt for database token hashing | `salt-change-me` |
| `LITELLM_DB_USER` | PostgreSQL user | `litellm` |
| `LITELLM_DB_PASS` | PostgreSQL password | `litellm_pass` |
| `LITELLM_DB_NAME` | PostgreSQL database | `litellm` |
| `GENERIC_CLIENT_ID` | Authentik OIDC OAuth Client ID | - |
| `GENERIC_CLIENT_SECRET` | Authentik OIDC OAuth Client Secret | - |
| `GENERIC_AUTHORIZATION_ENDPOINT` | Authentik OIDC Authorization Endpoint | `https://auth.jaewook.dev/application/o/authorize/` |
| `GENERIC_TOKEN_ENDPOINT` | Authentik OIDC Token Endpoint | `https://auth.jaewook.dev/application/o/token/` |
| `GENERIC_USERINFO_ENDPOINT` | Authentik OIDC UserInfo Endpoint | `https://auth.jaewook.dev/application/o/userinfo/` |
| `PROXY_BASE_URL` | Public base URL of LiteLLM Gateway | `https://aigateway.jaewook.dev` |

---

## 3. Deployment

Start the LiteLLM Gateway service:

```bash
docker compose up -d
```

Check healthcheck status:
```bash
docker compose ps
# Inspect container healthiness endpoint
curl -f http://127.0.0.1:4000/health/liveliness
```

---

## 4. Key Bootstrapping

Downstream services (e.g. Open WebUI) use service tokens to communicate with the Gateway. Use `bootstrap-keys.sh` to generate the pre-configured Open WebUI key (`sk-openwebui-service`):

```bash
# Dry run verification
./scripts/bootstrap-keys.sh --dry-run

# Live key bootstrap
./scripts/bootstrap-keys.sh --gateway-url http://127.0.0.1:4000 --master-key "<LITELLM_MASTER_KEY>"
```

---

## 5. Gateway Verification

Run `verify-gateway.sh` to validate the gateway protocols, authentication boundaries, and tool definitions:

```bash
# Offline syntax & schema check
./scripts/verify-gateway.sh --dry-run

# Live end-to-end verification
./scripts/verify-gateway.sh --gateway-url http://127.0.0.1:4000 --api-key "<API_KEY>"
```

Checks performed:
1. `test_unauthorized`: Verifies that unauthorized requests receive `HTTP 401 Unauthorized`.
2. `test_openai_completion`: Validates `/v1/chat/completions` API responses.
3. `test_anthropic_messages`: Validates `/v1/messages` protocol translation.
4. `test_tool_definitions`: Validates OpenAI and Anthropic tool calling schemas and live execution.
