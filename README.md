# Infrastructure Check Master PRO

FastAPI + 단일 HTML 대시보드 기반의 인프라 점검 도구입니다.  
여러 서버의 포트, Windows 서비스, 로컬/원격 리소스를 비동기 병렬로 점검하고 결과를 시각화합니다.

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

- 비동기 포트 점검: `GET /api/check`, `GET /api/check/stream(SSE)`
- TCP/UDP 분리 점검
- 상세 상태 코드/사유 코드 지원
- 재시도 + 최종 판정(일관성 점수: `STABLE/FLAKY`)
- 앱 프로브:
  - TCP: `http`, `https`, `rdp`
  - UDP: `dns_a`, `dns_aaaa`, `dns_mx`, `dns_txt`, `dns_srv`, `dns_soa`, `ntp`
- DNS 응답 파싱(A/AAAA/MX/TXT/SRV/SOA)
- NTP 응답 메타(`version`, `stratum`, `mode`) 파싱
- Windows 서비스 상태 점검
- 로컬 리소스 + 원격(Hyper-V/Windows) 리소스 점검
- 서버/템플릿/자격증명 프로필 CRUD
- 결과 필터/검색/페이지네이션
- 점검 이력 DB 저장 및 추세 API
- 엑셀 리포트 다운로드

## 3) UI 사용 방법

### 3.1 서버 등록

- `서버명`, `IP 또는 Host` 입력
- `포트 목록`은 기본 TCP 포트(콤마 구분)
- `Windows 서비스 목록`은 프로그램명이 아니라 서비스명을 입력
  - 예: `W3SVC`, `Spooler`, `MSSQLSERVER`
- 필요하면 `원격 인증 프로필` 선택

### 3.2 고급 포트 타깃 입력

기본 포트 없이도 고급 타깃(`port_targets`)만으로 점검할 수 있습니다.

- `Port`: 1~65535
- `Transport`: `tcp` 또는 `udp`
- `Probe`: transport와 호환되는 값만 허용
  - TCP: `auto`, `none`, `http`, `https`, `rdp`
  - UDP: `auto`, `none`, `dns_a`, `dns_aaaa`, `dns_mx`, `dns_txt`, `dns_srv`, `dns_soa`, `ntp`
- `Retries`: 0~5

편의 기능:

- AD/WEB/DB 기본 템플릿 원클릭 추가
- 행 직접 수정/삭제
- 현재 타깃 목록을 템플릿으로 저장 가능

### 3.3 점검 실행

1. `[종합 점검 시작]` 클릭
2. 진행률 바(SSE)로 실시간 진행 확인
3. 결과 테이블에서 상태/Transport/검색으로 필터링
4. 필요 시 엑셀 리포트 다운로드

## 4) 상태 해석

주요 상태:

- `OPEN`: 연결 성공
- `REFUSED`: 대상 호스트는 도달했지만 해당 포트에서 서비스가 리슨 중이 아님
- `TIMEOUT`: 제한 시간(2.0초) 내 응답 없음
- `FILTERED`: 방화벽/보안 정책으로 드롭 가능성 높음
- `NO_ROUTE`: 라우팅 경로 없음
- `HOST_UNREACHABLE`, `NETWORK_UNREACHABLE`: 네트워크 도달 불가
- `UNKNOWN_HOST`: DNS/호스트명 해석 실패
- `UDP_OPEN_OR_FILTERED`: UDP 특성상 무응답(열림-무응답 또는 필터링)
- `UDP_CLOSED`: ICMP unreachable 등으로 닫힘 추정
- `PROBE_TIMEOUT`, `PROBE_FAILED`, `INVALID_RESPONSE`: 앱 프로브 단계 실패

상세 컬럼에는 아래 정보가 포함됩니다.

- `reason_code` (예: `WSAETIMEDOUT`, `WSAENETUNREACH`)
- 프로브 결과/메타
- 재시도 이력(`1:TIMEOUT / 2:OPEN` 형태)
- 일관성 지표(`STABLE 100%`, `FLAKY 67%` 등)
- 자동 조치 가이드

## 5) 원격 점검(리소스/서비스) 조건

- 점검 실행 PC에서 대상 서버로 네트워크 접근 가능해야 함
- 원격 점검은 Windows/PowerShell 접근 권한 영향이 큼
- 방화벽/권한/도메인 정책에 따라 일부 대상만 실패할 수 있음
- 자격증명 프로필 사용 시 해당 계정 권한 필요

## 6) 자격증명 프로필(보안 저장)

지원 Provider:

- `dpapi`: 로컬 DPAPI 암호화 저장
- `env`: 환경변수 참조(`secret_ref=env:VAR_NAME`)
- `azure_key_vault`: Azure Key Vault 참조
- `aws_secrets_manager`: AWS Secrets Manager 참조
- `hashicorp_vault`: HashiCorp Vault 참조

예시 `secret_ref`:

- `env:DBCHECK_SECRET`
- `azurekv:https://<vault>.vault.azure.net/secrets/<name>`
- `aws-sm:ap-northeast-2|my/secret#password`
- `vault:https://vault.company.local|secret/data/app#password`

## 7) 설정 파일 예시 (`config.json`)

```json
{
  "timeout_seconds": 2.0,
  "probe_timeout_seconds": 1.5,
  "port_check_retries": 2,
  "max_concurrency": 200,
  "batch_size": 250,
  "retry_backoff_base_ms": 120,
  "retry_backoff_max_ms": 1500,
  "flaky_threshold_percent": 100.0,
  "history_enabled": true,
  "history_retention_days": 30,
  "default_page_size": 200,
  "templates": [
    {
      "name": "HQ-AD-Baseline",
      "description": "본사 AD 점검 기준 템플릿",
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
      "description": "AD 운영 계정"
    }
  ],
  "servers": [
    {
      "name": "WEB-01",
      "host": "192.168.0.110",
      "ports": [80, 443],
      "port_targets": [
        { "port": 80, "transport": "tcp", "probe": "http", "retries": 2 },
        { "port": 443, "transport": "tcp", "probe": "https", "retries": 2 }
      ],
      "services": ["W3SVC"],
      "enable_remote_metrics": true,
      "credential_profile_id": null
    }
  ]
}
```

## 8) 주요 API

- `GET /health`
- `GET /api/config`
- `POST /api/servers`
- `PUT /api/servers/{server_id}`
- `DELETE /api/servers/{server_id}`
- `GET /api/templates`
- `POST /api/templates`
- `PUT /api/templates/{template_id}`
- `DELETE /api/templates/{template_id}`
- `GET /api/credential-profiles`
- `POST /api/credential-profiles`
- `PUT /api/credential-profiles/{profile_id}`
- `DELETE /api/credential-profiles/{profile_id}`
- `GET /api/resources`
- `GET /api/check`
- `GET /api/check/stream`
- `GET /api/check/results?page=&page_size=&status=&transport=&keyword=`
- `GET /api/history/runs`
- `GET /api/history/runs/{run_id}`
- `GET /api/history/runs/{run_id}/results`
- `GET /api/history/trends?days=14`
- `GET /api/report/download`

## 9) 운영 참고

- 포트 상태는 "방화벽 규칙 존재"만으로 결정되지 않습니다.
  - 실제 리슨 상태, 라우팅, ACL, 앱 레벨 응답 여부가 함께 반영됩니다.
- 원격 리소스/서비스 점검 실패 시:
  - 대상 서버 접근성
  - WinRM/PowerShell 권한
  - 자격증명 프로필 매핑
  - 도메인/로컬 정책을 우선 확인하세요.
