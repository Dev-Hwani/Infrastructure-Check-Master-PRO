# Infrastructure Check Master PRO

FastAPI + 단일 HTML 대시보드 기반의 인프라 점검 도구입니다.  
목표는 여러 서버의 포트, Windows 서비스, 로컬/원격 리소스를 비동기 병렬로 빠르게 확인하는 것입니다.

## 1) 실행 방법

```powershell
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

브라우저 접속:

```text
http://localhost:8000
```

## 2) 현재 구현 범위

- 비동기 포트 점검 (`/api/check`)
- TCP/UDP 분리 진단
- errno/WinSock 기반 상세 reason code
- 재시도(`retries`) + 최종 판정
- 앱 프로브
- `http`, `https`, `rdp`
- UDP 프로브
- `dns_a`, `dns_aaaa`, `dns_mx`, `dns_txt`, `dns_srv`, `dns_soa`, `ntp`
- DNS 응답 본문 파싱
- `A/AAAA/MX/TXT/SRV/SOA` 레코드 핵심 필드 파싱/표시
- NTP 응답 `version`, `stratum`, `mode` 파싱
- 결과 일관성 지표
- `STABLE / FLAKY` + 점수(%)
- Windows 서비스 점검
- 로컬/원격 리소스 점검
- 사용자 템플릿 CRUD (조직별 표준 타깃 저장/적용)
- 서버별 자격증명 프로파일 분리 점검
- 대규모 결과 테이블 가상 스크롤 + 검색/필터
- 설정 CRUD + 엑셀 다운로드

## 3) UI 사용 방법

### 3.1 서버 등록

- `서버명`, `IP 또는 Host` 입력
- `포트 목록`은 기본 TCP 포트용(콤마 구분)
- Windows 서비스는 프로그램명이 아니라 서비스명 입력
- 예: `W3SVC`, `Spooler`, `MSSQLSERVER`

### 3.2 고급 포트 타깃 (핵심)

고급 타깃은 `port_targets`로 저장되며 한 행이 하나의 점검 단위입니다.

- `Port`: 1~65535
- `Transport`: `tcp` 또는 `udp`
- `Probe`: transport에 맞는 값만 허용
- TCP 허용: `auto`, `none`, `http`, `https`, `rdp`
- UDP 허용: `auto`, `none`, `dns_a`, `dns_aaaa`, `dns_mx`, `dns_txt`, `dns_srv`, `dns_soa`, `ntp`
- `Retries`: 0~5 (최종 시도 횟수는 `retries + 1`)

지원 UX:

- 행 직접 수정: `수정` 버튼으로 폼에 불러와서 `저장`
- 행 삭제: `삭제`
- 템플릿 원클릭 입력
- `AD 템플릿`
- `WEB 템플릿`
- `DB 템플릿`

### 3.3 사용자 템플릿 CRUD

- 현재 고급 타깃 목록을 사용자 템플릿으로 저장
- 저장된 템플릿 `적용 / 수정 / 삭제`
- 조직/사이트별 표준 점검 세트를 반복 재사용 가능

### 3.4 대규모 결과 조회

- 검색: 서버명, 호스트, reason_code, 상세 텍스트
- 상태 필터, Transport 필터
- 가상 스크롤로 수백~수천 건에서도 DOM 렌더 부하 완화

### 3.5 자격증명 프로파일

- 프로파일별 `도메인/사용자 + Secret Provider` 관리
- 서버마다 `credential_profile_id`를 지정
- Provider
- `dpapi`: 비밀번호 입력 시 즉시 DPAPI 암호화되어 `encrypted_password`로 저장
- `env`: `secret_ref=env:환경변수명`에서 비밀 조회
- `azure_key_vault`: `secret_ref=https://.../secrets/...` 또는 `azurekv:https://...` 지원
- 지정 시 원격 리소스/서비스 점검 PowerShell에 `-Credential` 적용
- 미지정 시 현재 실행 계정 사용

## 4) 결과 해석

### 4.1 상태값

주요 상태:

- `OPEN`: 연결 성공
- `REFUSED`: 대상은 도달되지만 포트 리슨 안 함
- `TIMEOUT`: 시간 내 응답 없음
- `FILTERED`: 정책 드롭 가능성 높음
- `NO_ROUTE`: 라우팅 경로 없음
- `HOST_UNREACHABLE`, `NETWORK_UNREACHABLE`: 도달 불가
- `UNKNOWN_HOST`: DNS/호스트 해석 실패
- `UDP_OPEN_OR_FILTERED`: UDP 무응답(열림 또는 필터링)
- `UDP_CLOSED`: UDP 닫힘 추정(ICMP unreachable 등)
- `PROBE_TIMEOUT`, `PROBE_FAILED`, `INVALID_RESPONSE`: 앱 프로브 레벨 이슈

### 4.2 상세 정보

포트 결과 테이블의 상세 컬럼에는 다음이 포함됩니다.

- `reason_code` (예: `WSAETIMEDOUT`, `WSAENETUNREACH`)
- probe 결과 (`PROBE_OK` 등)
- DNS probe의 경우 응답 레코드 핵심 요약(A/AAAA/MX/TXT/SRV/SOA)
- 재시도 이력 (`1:TIMEOUT / 2:OPEN` 형태)
- 일관성 지표 (`STABLE 100%`, `FLAKY 67%` 등)

`조치 가이드`는 reason code 우선으로 분기합니다.

## 5) 원격 점검 전제 조건

- 앱 실행 호스트가 대상 서버로 네트워크 접근 가능해야 함
- 원격 리소스/서비스 점검은 Windows PowerShell 원격 질의가 가능한 환경이어야 함
- 방화벽/권한/도메인 정책에 따라 원격 지표가 `ERROR`로 나올 수 있음
- 자격증명 프로파일 사용 시, 해당 계정에 원격 조회 권한이 있어야 함
- `azure_key_vault` 사용 시 `AZURE_KEYVAULT_TOKEN` 또는 `AZURE_ACCESS_TOKEN` 환경변수 필요
- 보안 권장
- 운영 환경에서는 `config.json` 접근 권한 최소화
- `env`/`azure_key_vault` 기반 Secret 공급으로 비밀번호 로테이션 자동화

## 6) 설정 파일 예시 (`config.json`)

```json
{
  "timeout_seconds": 2.0,
  "port_check_retries": 2,
  "templates": [
    {
      "name": "HQ-AD-Baseline",
      "description": "본사 AD 표준 점검",
      "port_targets": [
        { "port": 53, "transport": "udp", "probe": "dns_srv", "retries": 2 },
        { "port": 53, "transport": "udp", "probe": "dns_soa", "retries": 2 },
        { "port": 3389, "transport": "tcp", "probe": "rdp", "retries": 2 }
      ]
    }
  ],
  "credential_profiles": [
    {
      "name": "AD-Admin",
      "username": "administrator",
      "secret_provider": "dpapi",
      "encrypted_password": "01000000d08c9ddf...",
      "secret_ref": null,
      "domain": "CORP",
      "description": "AD 운영 점검 계정"
    },
    {
      "name": "DB-Prod",
      "username": "svc_dbcheck",
      "secret_provider": "env",
      "secret_ref": "env:DBCHECK_SECRET",
      "domain": "CORP",
      "description": "운영 DB 점검 계정"
    }
  ],
  "servers": [
    {
      "name": "WEB-01",
      "host": "192.168.0.110",
      "ports": [80, 443],
      "port_targets": [
        { "port": 80, "transport": "tcp", "probe": "http", "retries": 2 },
        { "port": 443, "transport": "tcp", "probe": "https", "retries": 2 },
        { "port": 53, "transport": "udp", "probe": "dns_soa", "retries": 2 }
      ],
      "services": ["W3SVC"],
      "enable_remote_metrics": true,
      "credential_profile_id": null
    }
  ]
}
```

## 7) 주요 API

- `GET /api/check`: 종합 점검
- `GET /api/resources`: 리소스만 조회
- `GET /api/config`: 현재 설정 조회
- `POST /api/servers`: 서버 추가
- `PUT /api/servers/{server_id}`: 서버 수정
- `DELETE /api/servers/{server_id}`: 서버 삭제
- `GET /api/templates`: 사용자 템플릿 목록
- `POST /api/templates`: 사용자 템플릿 추가
- `PUT /api/templates/{template_id}`: 사용자 템플릿 수정
- `DELETE /api/templates/{template_id}`: 사용자 템플릿 삭제
- `GET /api/credential-profiles`: 자격증명 프로파일 목록
- `POST /api/credential-profiles`: 자격증명 프로파일 추가
- `PUT /api/credential-profiles/{profile_id}`: 자격증명 프로파일 수정
- `DELETE /api/credential-profiles/{profile_id}`: 자격증명 프로파일 삭제
- `GET /api/report/download`: 최신 점검 엑셀 다운로드

## 8) 다음 개선 후보

- 역할 기반 접근 제어(RBAC) 및 감사 로그
- 가상 스크롤과 서버사이드 페이징 병행(초대형 데이터셋)
- DNS 추가 타입(NS/CNAME/PTR/CAA) 파싱 확장
- 자격증명 저장소 플러그인 확장(AWS Secrets Manager / HashiCorp Vault)

## 9) Advanced Features (2026-05 Update)

### 9.1 DNS parser v2
- Parse all DNS sections: `Answer`, `Authority`, `Additional`
- Parse `OPT(EDNS0)` metadata (`udp_payload_size`, `edns_version`, `extended_rcode`, options)
- Handle `TC`(truncated) bit and retry over TCP automatically
- Keep raw probe artifacts for replay/debug (`raw_query_hex`, `raw_response_hex`)

### 9.2 Probe policy hardening
- Adaptive retry/backoff by `reason_code` and status category
- Separate `probe_timeout_seconds` from transport timeout
- Weighted final status decision with overridable priority map
- Configurable flakiness threshold (`flaky_threshold_percent`)

### 9.3 Large-scale execution stability
- Concurrency control via `max_concurrency` semaphore
- Batch execution via `batch_size`
- Progress streaming endpoint (SSE): `GET /api/check/stream`
- Server-side latest result pagination/filter endpoint:
  `GET /api/check/results?page=&page_size=&status=&transport=&keyword=`

### 9.4 KMS/Secret provider expansion
- Providers: `dpapi`, `env`, `azure_key_vault`, `aws_secrets_manager`, `hashicorp_vault`
- Examples:
  - `env:MY_SECRET`
  - `azurekv:https://<vault>.vault.azure.net/secrets/<name>`
  - `aws-sm:ap-northeast-2|my/secret#password`
  - `vault:https://vault.company.local|secret/data/app#password`

### 9.5 Operational visibility
- SQLite history persistence (default path): `data/history.sqlite3`
- Endpoints:
  - `GET /api/history/runs`
  - `GET /api/history/runs/{run_id}`
  - `GET /api/history/runs/{run_id}/results`
  - `GET /api/history/trends?days=14`
- Stores per-run summary, per-target result rows, attempt logs, probe metadata for failure replay
