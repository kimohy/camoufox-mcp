# Camoufox MCP-as-a-Service (MaaS) — 설치 가이드 및 실전 활용법

프로덕션 레벨의 **Camoufox(Firefox C++ 레벨 안티봇/핑거프린트 스푸핑 브라우저)** 기반 멀티세션 **MCP-as-a-Service (MaaS)** 클라우드 네이티브 아키텍처, 상세 설치 가이드 및 실전 활용 매뉴얼입니다.

---

## 목차 (Table of Contents)

1. [시스템 아키텍처 및 3중 보안 구조](#1-시스템-아키텍처-및-3중-보안-구조)
2. [사전 준비 사항 (Prerequisites)](#2-사전-준비-사항-prerequisites)
3. [설치 가이드 A: 로컬/단일 서버 빠른 시작 (Docker Compose)](#3-설치-가이드-a-로컬단일-서버-빠른-시작-docker-compose)
4. [설치 가이드 B: 프로덕션 Kubernetes (k3s + Traefik + cert-manager) 배포](#4-설치-가이드-b-프로덕션-kubernetes-k3s--traefik--cert-manager-배포)
5. [클라이언트별 연동 가이드 (Gemini CLI / Gemini Web / Claude / Cursor / Python SDK)](#5-클라이언트별-연동-가이드)
6. [MCP 도구(Tools) 상세 레퍼런스](#6-mcp-도구tools-상세-레퍼런스)
7. [실전 활용법 및 레시피 (Use Cases & Recipes)](#7-실전-활용법-및-레시피-use-cases--recipes)
8. [운영, 모니터링 및 트러블슈팅 (Troubleshooting)](#8-운영-모니터링-및-트러블슈팅-troubleshooting)

---

## 1. 시스템 아키텍처 및 3중 보안 구조

```text
[AI Clients: Gemini CLI / Gemini Web / Claude Desktop / Cursor / LangGraph]
                        │
                        ▼ HTTPS (TLS 1.3 via cert-manager)
              [Traefik Ingress Controller]
         (Sticky Cookie: camoufox_mcp_sticky)
                        │
                        ▼
       ┌─────────────────────────────────┐
       │      mcp-gateway Deployment     │
       │  • Layer 1: Dual AuthMiddleware │
       │    - Bearer Token (MCP_API_KEYS)│
       │    - URL Token (/s/<token>/mcp) │
       │  • Layer 2: App SSRF Guard      │
       │    - Pre-flight DNS/IP Check    │
       │    - Playwright Route Intercept │
       │  • Multi-Session Context Pool   │
       │    - LRU Eviction & TTL GC      │
       │    - Persistent Profile PVC     │
       └────────────────┬────────────────┘
                        │ ws://camoufox-browser-svc:9222/stealth-agent
                        ▼ (ClientIP Session Affinity)
       ┌─────────────────────────────────┐
       │    camoufox-browser Deployment  │
       │  • Xvfb (:99) + Headful Mode    │
       │  • humanize=True, geoip=True    │
       │  • /dev/shm 2Gi Memory Volume   │
       │  • Layer 3: K8s NetworkPolicy   │
       │    - Ingress: Only mcp-gateway  │
       │    - Egress: Block RFC1918 &    │
       │      169.254.0.0/16 Metadata    │
       └─────────────────────────────────┘
```

### 왜 Camoufox MaaS인가?
* **C++ 엔진 레벨 스푸핑**: 일반적인 `playwright-extra-stealth`와 같은 JS 패치 방식은 Cloudflare Turnstile, DataDome, Akamai Bot Manager의 `iframe`/WebWorker/WebGL/AudioContext 검사를 통과하지 못합니다. Camoufox는 Firefox C++ 소스 레벨에서 핑거프린트를 재작성하고 `Xvfb` 위에서 **Headful 모드(`headless=False`)** 및 **인간형 베지어 곡선 마우스 이동(`humanize=True`)**으로 동작합니다.
* **멀티세션 완벽 격리**: 하나의 브라우저 풀 위에 여러 AI 에이전트가 동시 접속하더라도 `session_id`별로 쿠키, 로컬스토리지, 프록시, 뷰포트가 분리된 `BrowserContext`를 할당받습니다.
* **3중 SSRF 및 인증 방어**:
  1. **Dual-Auth (`AuthMiddleware`)**: 정적 `Authorization: Bearer <API_KEY>` 헤더와 URL Path 시크릿(`/s/{SECRET_URL_TOKEN}/mcp`)을 동시에 지원합니다.
  2. **Application & Playwright Route SSRF 차단**: 초기 URL뿐만 아니라 페이지 내부의 JS `fetch`/`XHR`, `<iframe>`, 302 리다이렉트가 사설 IP(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), 루프백(`127.0.0.1`), 클라우드 메타데이터(`169.254.169.254`), 클러스터 내부 도메인(`.svc`, `.cluster.local`)을 향할 경우 즉시 차단합니다.
  3. **Kubernetes `NetworkPolicy`**: CNI 커널 레벨에서 브라우저 파드가 클러스터 내부망으로 패킷을 보내는 것을 원천 차단합니다.

---

## 2. 사전 준비 사항 (Prerequisites)

| 구분 | 요구 사항 | 권장 사양 |
| :--- | :--- | :--- |
| **컨테이너 빌드** | Docker Engine 24.0+ 및 `docker buildx` | `linux/amd64`, `linux/arm64` 크로스 빌드 지원 |
| **쿠버네티스 환경** | Kubernetes 1.27+ (k3s 권장), Helm 3.12+ | 최소 2 vCPU, 4GB RAM 여유 리소스 |
| **인그레스 & TLS** | Traefik Ingress Controller + `cert-manager` | Let's Encrypt `ClusterIssuer` 설정 완료 |
| **네트워크 정책** | NetworkPolicy 지원 CNI | k3s 기본 `flannel` + `kube-router` 또는 `Cilium` / `Calico` |

---

## 3. 설치 가이드 A: 로컬/단일 서버 빠른 시작 (Docker網路/컨테이너 테스트)

Kubernetes에 배포하기 전에 로컬 PC나 단일 Linux VM에서 즉시 동작을 검증하는 방법입니다.

```bash
cd camoufox-mcp-maas

# 1. 전용 브리지 네트워크 생성
docker network create camoufox-net

# 2. Camoufox Browser Pool 이미지 빌드 및 실행 (/dev/shm 2GB 할당 필수!)
docker build -t local/camoufox-pool:1.0.0 ./docker/camoufox-pool
docker run -d \
  --name camoufox-browser-svc \
  --network camoufox-net \
  --shm-size=2g \
  -e PORT=9222 \
  -e WS_PATH=stealth-agent \
  local/camoufox-pool:1.0.0

# 3. MCP Gateway 이미지 빌드 및 실행
docker build -t local/camoufox-mcp-gateway:1.0.0 ./docker/mcp-gateway
docker run -d \
  --name camoufox-mcp-gateway \
  --network camoufox-net \
  -p 8000:8000 \
  -v "$(pwd)/profiles_data:/data/profiles" \
  -e BROWSER_WS_URL="ws://camoufox-browser-svc:9222/stealth-agent" \
  -e MCP_API_KEYS="my-local-api-key-123" \
  -e SECRET_URL_TOKEN="my-local-url-secret-456" \
  -e SESSION_TTL_SECONDS=600 \
  -e MAX_SESSIONS=10 \
  local/camoufox-mcp-gateway:1.0.0

# 4. 헬스체크 및 인증 테스트
curl -s http://localhost:8000/healthz
# 출력 예시: {"status":"healthy","service":"camoufox-mcp-gateway","browser_connected":false,"active_sessions":0,"max_sessions":10}
```

---

## 4. 설치 가이드 B: 프로덕션 Kubernetes (k3s + Traefik + cert-manager) 배포

### Step 1: Docker Buildx 멀티아키텍처(`linux/amd64,linux/arm64`) 빌드 및 레지스트리 푸시

x86_64 서버와 ARM64(Oracle Cloud Ampere, AWS Graviton, Raspberry Pi 클러스터 등) 노드 모두에서 구동되도록 멀티아키텍처 이미지를 빌드합니다.

```bash
cd camoufox-mcp-maas

# 1. Buildx 멀티아키텍처 빌더 생성 및 부트스트랩
docker buildx create --name camoufox-builder --use --bootstrap

# 2. 컨테이너 레지스트리 주소 및 버전 지정 (본인의 GHCR / Docker Hub 계정으로 변경)
export REGISTRY="ghcr.io/your-org"
export TAG="1.0.0"

# 3. Camoufox Browser Pool 이미지 빌드 & 푸시
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "${REGISTRY}/camoufox-pool:${TAG}" \
  --push \
  ./docker/camoufox-pool

# 4. MCP Gateway 이미지 빌드 & 푸시
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "${REGISTRY}/camoufox-mcp-gateway:${TAG}" \
  --push \
  ./docker/mcp-gateway
```

### Step 2: 네임스페이스 및 보안 토큰 준비

```bash
# 1. 전용 네임스페이스 생성
kubectl create namespace camoufox-maas

# 2. 프로덕션용 난수 API Key 및 URL Secret Token 생성
export MCP_API_KEY="$(openssl rand -hex 24)"
export SECRET_URL_TOKEN="$(openssl rand -hex 24)"

echo "MCP_API_KEY      : ${MCP_API_KEY}"
echo "SECRET_URL_TOKEN : ${SECRET_URL_TOKEN}"
```

> **주의**: 프라이빗 컨테이너 레지스트리(GHCR Private 등)를 사용하는 경우 ImagePullSecret을 먼저 생성하세요:
> ```bash
> kubectl create secret docker-registry regcred \
>   --docker-server=ghcr.io \
>   --docker-username=<GITHUB_USER> \
>   --docker-password=<GITHUB_PAT> \
>   -n camoufox-maas
> ```

### Step 3: Helm Chart 배포 및 커스텀 설정

`charts/camoufox-maas/values.yaml`을 직접 수정하거나 `--set` 플래그로 즉시 배포합니다.

```bash
helm upgrade --install camoufox-maas ./charts/camoufox-maas \
  --namespace camoufox-maas \
  --set browserPool.image.repository="${REGISTRY}/camoufox-pool" \
  --set browserPool.image.tag="${TAG}" \
  --set browserPool.replicaCount=2 \
  --set mcpGateway.image.repository="${REGISTRY}/camoufox-mcp-gateway" \
  --set mcpGateway.image.tag="${TAG}" \
  --set mcpGateway.replicaCount=2 \
  --set ingress.host="mcp.yourdomain.com" \
  --set ingress.annotations."cert-manager\.io/cluster-issuer"="letsencrypt-prod" \
  --set auth.mcpApiKeys="${MCP_API_KEY}" \
  --set auth.secretUrlToken="${SECRET_URL_TOKEN}"
```

### Step 4: 배포 상태 및 TLS 인증서 검증

```bash
# 파드, 서비스, 인그레스, PVC, NetworkPolicy 상태 확인
kubectl get pods,svc,ingress,pvc,networkpolicy -n camoufox-maas

# TLS 인증서 발급 완료 여부 확인 (READY = True 확인)
kubectl get certificate -n camoufox-maas

# 외부 도메인 헬스체크 호출
curl -i https://mcp.yourdomain.com/healthz

# 무인증 요청 차단 검증 (401 Unauthorized 반환 확인)
curl -i https://mcp.yourdomain.com/mcp
```

---

## 5. 클라이언트별 연동 가이드

### 5.1. Google Gemini CLI (`gemini mcp add`)

Google Gemini CLI에서는 Streamable HTTP 트랜스포트를 통해 두 가지 방식 중 하나로 등록할 수 있습니다. (`mcp.yourdomain.com` 도메인을 다목적 MCP 허브로 사용할 수 있도록 기본 서비스 경로 `/camoufox`가 삽입되어 있습니다.)

* **방식 1: Bearer 헤더 인증 (권장)**
  ```bash
  gemini mcp add --transport http camoufox-stealth \
    https://mcp.yourdomain.com/camoufox/mcp \
    --header "Authorization: Bearer ${MCP_API_KEY}"
  ```
* **방식 2: URL Path 시크릿 토큰 인증**
  ```bash
  gemini mcp add --transport http camoufox-stealth \
    "https://mcp.yourdomain.com/camoufox/s/${SECRET_URL_TOKEN}/mcp"
  ```

### 5.2. Google Gemini 웹 앱 (`gemini.google.com`) 및 Chrome 확장 (OAuth 2.0 / URL Secret)

Google Gemini 웹 앱 또는 OAuth 2.0/2.1 인증을 요구하는 MCP 커넥터에서는 **OAuth Client ID & Client Secret** 방식과 **URL Path 시크릿 토큰** 방식을 모두 지원합니다.

#### 방식 A: OAuth 2.0 (`Client ID` & `Client Secret`) 연동 (권장)
`mcp-gateway`는 RFC 8414 / RFC 9728 자동 디스커버리(`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`) 및 Authorization Code(+PKCE), Client Credentials, Refresh Token 그랜트를 자체 내장하고 있습니다.

* **MCP Server URL (Endpoint)**:
  ```text
  https://mcp.yourdomain.com/camoufox/mcp
  ```
* **OAuth Client ID**: `OAUTH_CLIENT_ID` 설정값 (기본값: `camoufox-mcp-client`)
* **OAuth Client Secret**: `OAUTH_CLIENT_SECRET` 설정값
* **Authorization URL** (수동 입력 필요 시):
  ```text
  https://mcp.yourdomain.com/camoufox/oauth/authorize
  ```
* **Token URL** (수동 입력 필요 시):
  ```text
  https://mcp.yourdomain.com/camoufox/oauth/token
  ```

#### 방식 B: URL Path 시크릿 토큰 연동 (헤더/OAuth 미지원 클라이언트용)
커스텀 HTTP 헤더(`Authorization`)나 OAuth 설정을 지원하지 않는 웹 기반 클라이언트에서는 `/camoufox/s/{SECRET_URL_TOKEN}/...` 엔드포인트를 사용합니다.

* **Streamable HTTP 엔드포인트**:
  ```text
  https://mcp.yourdomain.com/camoufox/s/<YOUR_SECRET_URL_TOKEN>/mcp
  ```
* **SSE (Server-Sent Events) 호환 엔드포인트**:
  ```text
  https://mcp.yourdomain.com/camoufox/s/<YOUR_SECRET_URL_TOKEN>/sse
  ```

### 5.3. Claude Desktop / Cursor / Windsurf (`mcp.json`) 설정

로컬 IDE나 데스크톱 앱의 `mcp.json` (또는 `claude_desktop_config.json`)에 아래와 같이 등록합니다:

```json
{
  "mcpServers": {
    "camoufox-stealth": {
      "url": "https://mcp.yourdomain.com/camoufox/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_MCP_API_KEY>"
      }
    }
  }
}
```
*(헤더 설정을 지원하지 않는 버전의 클라이언트라면 `"url": "https://mcp.yourdomain.com/camoufox/s/<YOUR_SECRET_URL_TOKEN>/sse"`만 입력하면 즉시 동작합니다.)*

### 5.4. Python `google-genai` SDK 연동 코드

```python
import asyncio
import os
from google import genai
from google.genai import types
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MCP_ENDPOINT = os.getenv("MCP_ENDPOINT", "https://mcp.yourdomain.com/camoufox/mcp")
MCP_API_KEY = os.getenv("MCP_API_KEY", "cfx-prod-key-change-me-1")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "your-gemini-api-key")


async def run_gemini_with_camoufox() -> None:
    client = genai.Client(api_key=GEMINI_API_KEY)

    headers = {
        "Authorization": f"Bearer {MCP_API_KEY}",
        "mcp-session-id": "genai-sdk-user-session-01",
    }

    async with streamablehttp_client(url=MCP_ENDPOINT, headers=headers) as (
        read_stream,
        write_stream,
        _,
    ):
        async with ClientSession(read_stream, write_stream) as mcp_session:
            await mcp_session.initialize()

            prompt = (
                "1. navigate 도구로 'https://news.ycombinator.com'에 접속해줘.\n"
                "2. get_interactive_elements 도구로 상단 주요 링크 목록을 확인해줘.\n"
                "3. 가장 첫 번째 뉴스의 제목과 링크를 요약하고, 마지막에 close_session을 호출해줘."
            )

            response = await client.aio.models.generate_content(
                model="gemini-2.5-pro",
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    tools=[mcp_session],
                ),
            )
            print(response.text)


if __name__ == "__main__":
    asyncio.run(run_gemini_with_camoufox())
```

### 5.5. Python `LangGraph` ReAct 에이전트 연동 코드

```python
import asyncio
import os
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

MCP_ENDPOINT = os.getenv("MCP_ENDPOINT", "https://mcp.yourdomain.com/mcp")
MCP_API_KEY = os.getenv("MCP_API_KEY", "cfx-prod-key-change-me-1")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "your-gemini-api-key")


async def run_langgraph_stealth_agent() -> None:
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-pro",
        google_api_key=GEMINI_API_KEY,
        temperature=0.0,
    )

    mcp_client = MultiServerMCPClient(
        {
            "camoufox": {
                "url": MCP_ENDPOINT,
                "transport": "streamable_http",
                "headers": {
                    "Authorization": f"Bearer {MCP_API_KEY}",
                    "mcp-session-id": "langgraph-agent-session-001",
                },
            }
        }
    )

    tools = await mcp_client.get_tools()
    agent = create_react_agent(llm, tools)

    query = {
        "messages": [
            (
                "user",
                "https://example.com 에 접속해서 페이지 본문과 인터랙티브 요소를 분석한 뒤, "
                "현재 세션을 'example_profile'이라는 이름으로 저장(save_profile)하고 세션을 닫아줘(close_session).",
            )
        ]
    }

    result = await agent.ainvoke(query)
    for message in result["messages"]:
        role = getattr(message, "type", "unknown")
        print(f"[{role.upper()}] {message.content}")


if __name__ == "__main__":
    asyncio.run(run_langgraph_stealth_agent())
```

---

## 6. MCP 도구(Tools) 상세 레퍼런스

| 도구명 | 주요 파라미터 | 반환값 | 상세 설명 |
| :--- | :--- | :--- | :--- |
| `navigate` | `url: str`<br>`session_id?: str`<br>`proxy_server?: str`<br>`wait_until: str = "domcontentloaded"` | JSON 문자열 (`title`, `url`, `http_status`, `content` 최대 15,000자) | SSRF 사전 검증 후 URL로 이동하고 안티봇 챌린지 통과를 위해 2초간 대기합니다. |
| `get_interactive_elements` | `session_id?: str` | JSON 문자열 (`count`, `elements[]`) | 현재 뷰포트에서 실제로 보이는(`width > 0 && height > 0`) 버튼/링크/입력창 목록과 권장 CSS 셀렉터(`selector_hint`), 좌표(`rect`)를 반환합니다. |
| `click` | `selector: str`<br>`session_id?: str` | JSON 문자열 (`current_url`, `title`) | 베지어 곡선 마우스 이동 및 `delay=100`ms로 인간형 클릭을 수행합니다. |
| `fill` | `selector: str`<br>`text: str`<br>`press_enter: bool = False`<br>`session_id?: str` | JSON 문자열 (`typed_length`, `current_url`) | 요소를 클릭한 뒤 `press_sequentially(text, delay=65)`로 사람처럼 한 글자씩 타이핑합니다. |
| `evaluate_js` | `script: str`<br>`session_id?: str` | JSON 문자열 (`result`) | 현재 페이지 DOM 컨텍스트에서 임의의 JavaScript 표현식/함수를 실행합니다. |
| `take_screenshot` | `session_id?: str`<br>`full_page: bool = False` | `mcp.server.fastmcp.Image` (PNG 바이너리) | 멀티모달 LLM이 시각적으로 화면 레이아웃이나 차트, 캡차를 판독할 수 있도록 스크린샷을 반환합니다. |
| `save_profile` | `profile_name: str`<br>`session_id?: str` | JSON 문자열 (`saved_path`) | 현재 세션의 쿠키/로컬스토리지를 `/data/profiles/{profile_name}.json`에 영구 저장합니다. |
| `load_profile` | `profile_name: str`<br>`session_id?: str` | JSON 문자열 (`loaded_from`) | 저장된 프로필 파일로 격리된 `BrowserContext`를 즉시 복원합니다. |
| `close_session` | `session_id?: str` | JSON 문자열 (`closed`, `active_sessions`) | 작업이 끝난 브라우저 컨텍스트를 즉시 닫고 메모리를 반환합니다. |

---

## 7. 실전 활용법 및 레시피 (Use Cases & Recipes)

### 활용법 1: 로그인 세션 영구 유지 및 재사용 (`save_profile` & `load_profile`)

매번 로그인 과정(2FA 등)을 거치지 않고, 한 번 로그인한 쿠키와 로컬스토리지를 Kubernetes PVC(`/data/profiles`)에 영구 저장하여 후속 작업에서 즉시 재사용할 수 있습니다.

**1단계 — 최초 로그인 및 프로필 저장 프롬프트:**
> ```text
> 1. session_id를 "github-bot"으로 지정해서 https://github.com/login 으로 이동해줘.
> 2. get_interactive_elements로 아이디/비밀번호 입력창 셀렉터를 찾고 fill 도구로 로그인 정보를 입력해줘.
> 3. 로그인이 완료되면 save_profile(profile_name="github_auth_session", session_id="github-bot")을 호출해서 세션을 저장해줘.
> ```

**2단계 — 다음 날 저장된 프로필로 즉시 작업 재개 프롬프트:**
> ```text
> 1. load_profile(profile_name="github_auth_session", session_id="daily-worker")를 먼저 호출해줘.
> 2. navigate(url="https://github.com/notifications", session_id="daily-worker")로 이동해서 읽지 않은 알림 목록을 요약해줘.
> 3. 끝나면 close_session(session_id="daily-worker")으로 메모리를 정리해줘.
> ```

---

### 활용법 2: 병렬 멀티세션 격리 크롤링 (`session_id` 분리)

단일 에이전트 또는 여러 에이전트가 동시에 서로 다른 사이트나 계정을 탐색할 때 `session_id`만 다르게 지정하면 쿠키와 탭이 전혀 섞이지 않습니다.

* **세션 A (한국 뉴스 수집)**: `session_id="kr-news-crawler"`
* **세션 B (미국 주가 대시보드 모니터링)**: `session_id="us-finance-monitor"`

**프롬프트 예시:**
> ```text
> 두 개의 독립된 브라우저 세션을 사용해서 비교 분석해줘:
> - 첫 번째 세션(session_id="store-kr")으로는 한국 쇼핑몰 상품 페이지를 열고 가격을 확인해줘.
> - 두 번째 세션(session_id="store-us")으로는 미국 아마존 상품 페이지를 열고 가격을 확인해줘.
> 분석이 끝나면 두 세션 모두 close_session으로 닫아줘.
> ```

---

### 활용법 3: 세션별 동적 프록시 라우팅 (`proxy_server` & `geoip=True`)

Camoufox 풀은 `geoip=True`가 활성화되어 있어, 프록시 서버를 통과할 때 해당 프록시의 출구 IP 국가/시간대(Timezone)/언어(Locale)/위경도(Geolocation)에 맞춰 브라우저 핑거프린트를 자동으로 동기화합니다.

* **전체 기본 프록시 설정**: Helm `values.yaml`의 `proxy.defaultProxyServer`에 지정.
* **특정 세션만 개별 프록시 지정**: `navigate` 호출 시 `proxy_server` 파라미터 전달.

**프롬프트 예시:**
> ```text
> navigate 도구를 호출할 때 proxy_server="socks5://us-proxy.example.com:1080", session_id="us-geo-test"를 전달해서
> https://ipinfo.io/json 에 접속하고 현재 인식된 국가와 시간대 정보를 가져와줘.
> ```

---

### 활용법 4: 멀티모달 시각적 웹 탐색 (Visual Grounding with `take_screenshot`)

DOM 텍스트만으로는 파악하기 어려운 Canvas 기반 차트, 복잡한 SPA 대시보드, 또는 시각적 레이아웃 검증이 필요할 때 `take_screenshot`과 `get_interactive_elements`를 결합합니다.

**프롬프트 예시:**
> ```text
> 1. navigate로 https://tradingview.com 차트 페이지에 접속해줘.
> 2. take_screenshot(full_page=False)으로 현재 차트 화면을 캡처해서 현재 추세와 인터페이스를 시각적으로 분석해줘.
> 3. 화면 우측 상단의 검색 버튼을 클릭하기 위해 get_interactive_elements 결과의 rect 좌표와 스크린샷의 위치를 대조해서 정확한 셀렉터를 click 해줘.
> ```

---

### 활용법 5: 커스텀 JavaScript 실행을 통한 정밀 데이터 추출 (`evaluate_js`)

무한 스크롤 제어, Shadow DOM 탐색, 혹은 페이지 내부 전역 상태(`window.__NEXT_DATA__`, `localStorage`) 추출이 필요할 때 `evaluate_js`를 활용합니다.

**프롬프트 예시:**
> ```text
> 1. 해당 페이지에서 evaluate_js 도구로 `window.scrollTo(0, document.body.scrollHeight)`를 실행해 하단 데이터를 로드해줘.
> 2. 이어서 evaluate_js로 `Array.from(document.querySelectorAll('table tr')).map(r => r.innerText)`를 실행해서 표 데이터를 배열 형태로 깔끔하게 추출해줘.
> ```

---

## 8. 운영, 모니터링 및 트러블슈팅 (Troubleshooting)

### 8.1. 실시간 세션 상태 및 헬스체크 모니터링

`/healthz` 엔드포인트는 현재 브라우저 WebSocket 연결 상태와 활성 세션 수를 실시간으로 반환합니다.

```bash
curl -s https://mcp.yourdomain.com/healthz | jq .
```
```json
{
  "status": "healthy",
  "service": "camoufox-mcp-gateway",
  "browser_connected": true,
  "active_sessions": 3,
  "max_sessions": 20
}
```

### 8.2. 자주 발생하는 문제 및 해결 방법 (FAQ)

#### Q1. 복잡한 웹사이트 접속 시 브라우저 탭이 죽거나 `TargetClosedError`가 발생합니다.
* **원인**: Firefox/Camoufox는 렌더링 파이프라인에서 공유 메모리(`/dev/shm`)를 대량으로 사용합니다. Docker/Kubernetes의 기본 `/dev/shm` 크기(64MB)로 실행하면 메모리 부족으로 탭 프로세스가 즉시 크래시됩니다.
* **해결**:
  * Helm Chart의 [`templates/browser-deployment.yaml`](./charts/camoufox-maas/templates/browser-deployment.yaml)에는 이미 `emptyDir: { medium: Memory, sizeLimit: 2Gi }`가 마운트되어 있습니다.
  * 동시 세션 수(`MAX_SESSIONS`)를 20개 이상으로 늘릴 경우 `values.yaml`에서 `browserPool.shmSize: "4Gi"` 및 `browserPool.resources.limits.memory: "8Gi"`로 상향 조정하세요.

#### Q2. MCP Gateway를 멀티 파드(`replicaCount: 2` 이상)로 스케일 아웃했더니 `Session not found` 오류가 간헐적으로 발생합니다.
* **원인**: Streamable HTTP 또는 SSE 연결 중 후속 요청이 다른 `mcp-gateway` 파드로 로드밸런싱되면 인메모리 `BrowserContext` 세션을 찾지 못합니다.
* **해결**:
  * [`templates/mcp-service.yaml`](./charts/camoufox-maas/templates/mcp-service.yaml)에 설정된 Traefik Sticky Cookie 어노테이션(`traefik.ingress.kubernetes.io/service.sticky.cookie: "true"`)과 `sessionAffinity: ClientIP`가 활성화되어 있는지 확인하세요.
  * Python SDK 등 비브라우저 클라이언트는 쿠키Jar를 유지하거나 단일 게이트웨이 세션을 재사용하도록 구성하고, 코드 레벨에서 항상 동일한 `mcp-session-id` 헤더를 전송하세요.

#### Q3. 사내 인트라넷 웹서버(예: `192.168.1.50`)를 크롤링하려고 하면 `SSRF Security Policy Blocked Navigation` 에러가 발생합니다.
* **원인**: 본 프로젝트는 클라우드 메타데이터 탈취 및 내부망 스캐닝을 막기 위해 2중(애플리케이션 [`app/security.py`](./docker/mcp-gateway/app/security.py) + 쿠버네티스 [`networkpolicy.yaml`](./charts/camoufox-maas/templates/networkpolicy.yaml))으로 RFC1918 사설 IP 대역을 차단합니다.
* **해결**: 신뢰할 수 있는 특정 내부 호스트만 예외적으로 허용해야 한다면:
  1. `charts/camoufox-maas/templates/networkpolicy.yaml`의 `except` 목록에서 해당 서브넷을 제외하거나 허용 규칙을 추가합니다.
  2. `docker/mcp-gateway/app/security.py`의 `_is_ip_blocked` 함수에 화이트리스트 CIDR 검증을 추가합니다.

#### Q4. 파드 로그 확인 명령어
```bash
# Camoufox 브라우저 풀 로그 (Xvfb 및 WebSocket 서버 상태 확인)
kubectl logs -l app.kubernetes.io/name=camoufox-browser -n camoufox-maas -f

# MCP 게이트웨이 로그 (세션 생성/회수 및 SSRF 차단 이력 확인)
kubectl logs -l app.kubernetes.io/name=mcp-gateway -n camoufox-maas -f
```
