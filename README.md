# Tiny Second-hand Shopping Platform

Flask + SQLite 기반의 간단한 중고거래 플랫폼입니다.

## 주요 기능

- 회원가입 / 로그인 / 로그아웃
- 마이페이지 및 프로필 소개 수정
- 사용자 프로필과 등록 상품 조회
- 상품 등록 / 수정 / 삭제 / 검색
- 전체 채팅 및 1:1 채팅
- 사용자 / 상품 신고
- 신고 누적에 따른 상품 자동 차단 및 사용자 휴면 처리
- 사용자 간 포인트 송금
- 관리자 페이지에서 사용자, 상품, 신고 내역 관리
- CSRF 보호, 비밀번호 해시 저장, 업로드 확장자 제한, 권한 검사

## 실행 방법

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

macOS / Linux:

```bash
source .venv/bin/activate
```

의존성 설치:

```bash
pip install -r requirements.txt
```

실행:

```bash
python app.py
```

브라우저에서 `http://127.0.0.1:5000` 접속.

## 초기 관리자 계정

앱 최초 실행 시 다음 관리자 계정이 생성됩니다.

- 아이디: `admin`
- 비밀번호: 환경 변수 `ADMIN_PASSWORD` 값
- 환경 변수가 없으면 개발용 기본값 `ChangeMe123!`

## 데이터베이스

SQLite 파일은 `instance/market.db`에 생성됩니다.

## 주의

이 프로젝트의 송금 기능은 실제 은행 송금이 아니라 플랫폼 내부 포인트 이동 예제입니다.
실제 결제 시스템을 구현할 때는 PG사, 전자금융 관련 법규, 본인인증, 거래 원장, 이상거래 탐지,
환불 및 분쟁 처리 기능을 별도로 설계해야 합니다.
