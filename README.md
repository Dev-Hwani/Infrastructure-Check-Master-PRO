# Infrastructure Check Master PRO

FastAPI + 단일 HTML 대시보드 기반의 인프라 점검 도구입니다.

## 핵심 기능

- `asyncio` 기반 비동기 포트 점검 (타임아웃 2.0초 고정)
- `OPEN / REFUSED / TIMEOUT / UNKNOWN_HOST / ERROR` 상태 분류
- 원격 Windows 서비스 상태 점검 (`RUNNING / STOPPED / NOT_FOUND`)
- 로컬 리소스(CPU/RAM/Disk) 실시간 수집 (`psutil`)
- 원격 Windows 리소스 수집 (PowerShell `Get-Counter`, `Get-CimInstance`)
- 점검 대상 서버 설정 CRUD (config.json 즉시 반영)
- 점검 결과 엑셀 다운로드 (`pandas`, `openpyxl`)

## 실행 방법

1. 의존성 설치

```powershell
pip install -r requirements.txt
```

2. 앱 실행

```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

3. 브라우저 접속

```text
http://localhost:8000
```

## 주요 API

- `GET /api/check`: 종합 점검 실행
- `GET /api/resources`: 리소스 정보만 조회
- `GET /api/config`: 설정 조회
- `POST /api/servers`: 서버 추가
- `PUT /api/servers/{server_id}`: 서버 수정
- `DELETE /api/servers/{server_id}`: 서버 삭제
- `GET /api/report/download`: 최근 점검 결과 엑셀 다운로드
