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
- `dns_a`, `dns_srv`, `dns_soa`, `ntp`
- NTP 응답 `version`, `stratum`, `mode` 파싱
- 결과 일관성 지표
- `STABLE / FLAKY` + 점수(%)
- Windows 서비스 점검
- 로컬/원격 리소스 점검
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
- UDP 허용: `auto`, `none`, `dns_a`, `dns_srv`, `dns_soa`, `ntp`
- `Retries`: 0~5 (최종 시도 횟수는 `retries + 1`)

지원 UX:

- 행 직접 수정: `수정` 버튼으로 폼에 불러와서 `수정 저장`
- 행 삭제: `삭제`
- 템플릿 원클릭 입력
- `AD 템플릿`
- `WEB 템플릿`
- `DB 템플릿`

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
- 재시도 이력 (`1:TIMEOUT / 2:OPEN` 형태)
- 일관성 지표 (`STABLE 100%`, `FLAKY 67%` 등)

`조치 가이드`는 reason code 우선으로 분기합니다.

## 5) 원격 점검 전제 조건

- 앱 실행 호스트가 대상 서버로 네트워크 접근 가능해야 함
- 원격 리소스/서비스 점검은 Windows PowerShell 원격 질의가 가능한 환경이어야 함
- 방화벽/권한/도메인 정책에 따라 원격 지표가 `ERROR`로 나올 수 있음

## 6) 설정 파일 예시 (`config.json`)

```json
{
  "timeout_seconds": 2.0,
  "port_check_retries": 2,
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
      "enable_remote_metrics": true
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
- `GET /api/report/download`: 최신 점검 엑셀 다운로드

## 8) 다음 개선 후보

- UDP DNS 응답 본문 파싱 확장
- SRV/SOA 레코드 값 표시 고도화
- 템플릿 사용자 정의 저장
- 대규모 타깃에서 페이지네이션/가상 스크롤
