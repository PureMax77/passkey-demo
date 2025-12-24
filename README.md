# 🔐 Passkey 로그인 데모

순수 WebAuthn API(`navigator.credentials`)를 사용한 Passkey 로그인 데모 애플리케이션입니다.

## 📋 목차

- [기술 스택](#기술-스택)
- [프로젝트 구조](#프로젝트-구조)
- [설치 및 실행](#설치-및-실행)
- [기능 설명](#기능-설명)
- [WebAuthn API 상세](#webauthn-api-상세)
- [브라우저 호환성](#브라우저-호환성)
- [보안 고려사항](#보안-고려사항)
- [트러블슈팅](#트러블슈팅)

## 🛠 기술 스택

### 프론트엔드
- **React 18** - UI 라이브러리
- **Vite** - 빌드 도구
- **순수 WebAuthn API** - 라이브러리 없이 `navigator.credentials` 직접 사용

### 백엔드
- **Node.js + Express** - REST API 서버
- **메모리 내 데이터 저장소** - 간단한 데모용

## 📁 프로젝트 구조

```
passkey-demo/
├── server/
│   ├── server.js          # Express 백엔드 서버
│   └── package.json       # 서버 의존성
├── client/
│   ├── src/
│   │   ├── App.jsx        # 메인 React 컴포넌트
│   │   ├── main.jsx       # React 진입점
│   │   ├── index.css      # 스타일
│   │   └── utils/
│   │       └── webauthn.js # WebAuthn 유틸리티 함수
│   ├── index.html
│   ├── vite.config.js
│   └── package.json       # 클라이언트 의존성
└── README.md
```

## 🚀 설치 및 실행

### 1. 저장소 클론 또는 다운로드

```bash
cd passkey-demo
```

### 2. 서버 실행

```bash
cd server
npm install
npm start
```

서버가 `http://localhost:3001`에서 실행됩니다.

### 3. 클라이언트 실행 (새 터미널)

```bash
cd client
npm install
npm run dev
```

클라이언트가 `http://localhost:5173`에서 실행됩니다.

### 4. 브라우저에서 접속

```
http://localhost:5173
```

## ✨ 기능 설명

### 1. Passkey 등록 (Registration)

1. 사용자 이름을 입력합니다
2. "Passkey 등록" 버튼을 클릭합니다
3. 브라우저가 생체 인증(Touch ID, Face ID, Windows Hello 등)을 요청합니다
4. 인증 완료 시 Passkey가 디바이스에 저장됩니다

**내부 동작:**
- 서버에서 challenge 생성
- `navigator.credentials.create()` 호출
- 공개키 생성 및 서버 저장
- Credential ID 저장

### 2. Passkey 로그인 (Authentication)

1. "Passkey로 로그인" 버튼을 클릭합니다
2. 저장된 Passkey 목록에서 선택합니다
3. 생체 인증을 진행합니다
4. 로그인 완료!

**내부 동작:**
- 서버에서 challenge 생성
- `navigator.credentials.get()` 호출
- Discoverable credential 사용 (사용자 이름 불필요)
- 서명 검증 및 로그인 처리

### 3. Discoverable Credential

- **사용자 이름 없이 로그인 가능**
- Passkey가 디바이스에 저장되어 있으면 자동으로 표시됩니다
- 여러 계정이 있을 경우 선택할 수 있습니다

## 🔍 WebAuthn API 상세

### 등록 시 PublicKeyCredentialCreationOptions

```javascript
{
  challenge: Uint8Array,           // 서버에서 생성한 랜덤 값
  rp: {
    name: "Passkey Demo",
    id: "localhost"                // 실제 배포 시 도메인으로 변경
  },
  user: {
    id: Uint8Array,                // 사용자 고유 ID
    name: "username",
    displayName: "username"
  },
  pubKeyCredParams: [
    { type: "public-key", alg: -7 },   // ES256 (권장)
    { type: "public-key", alg: -257 }  // RS256
  ],
  authenticatorSelection: {
    authenticatorAttachment: "platform",  // 플랫폼 인증기 사용
    requireResidentKey: true,            // Discoverable credential
    userVerification: "required"         // 생체 인증 필수
  },
  timeout: 60000                         // 60초 타임아웃
}
```

### 로그인 시 PublicKeyCredentialRequestOptions

```javascript
{
  challenge: Uint8Array,
  rpId: "localhost",
  allowCredentials: [],            // 빈 배열 = 모든 등록된 credential 허용
  userVerification: "required",
  timeout: 60000
}
```

### Base64URL 인코딩/디코딩

WebAuthn API는 `ArrayBuffer`를 사용하지만, 서버와의 통신에서는 문자열이 필요합니다.
`utils/webauthn.js`에 변환 함수가 구현되어 있습니다:

```javascript
bufferToBase64url(buffer)   // ArrayBuffer → Base64URL 문자열
base64urlToBuffer(string)   // Base64URL 문자열 → ArrayBuffer
```

## 🌐 브라우저 호환성

### 지원 브라우저

| 브라우저 | 지원 버전 | 플랫폼 인증기 |
|---------|----------|------------|
| Chrome | 67+ | ✅ |
| Firefox | 60+ | ✅ |
| Safari | 13+ | ✅ (Touch ID, Face ID) |
| Edge | 18+ | ✅ (Windows Hello) |

### 플랫폼별 인증기

- **macOS**: Touch ID, Face ID
- **Windows**: Windows Hello (얼굴 인식, 지문, PIN)
- **iOS/iPadOS**: Face ID, Touch ID
- **Android**: 지문, 얼굴 인식, 패턴

### HTTPS 요구사항

⚠️ **중요**: WebAuthn은 보안상의 이유로 다음 환경에서만 동작합니다:

- ✅ `localhost` (HTTP 허용)
- ✅ `https://` (HTTPS)
- ❌ 로컬 IP 주소 (예: `http://192.168.x.x`) - **동작하지 않음**
- ❌ 일반 HTTP 도메인 - **동작하지 않음**

**로컬 네트워크에서 테스트하는 방법:**

1. **hosts 파일 수정** (권장)
   ```bash
   # /etc/hosts (Mac/Linux) 또는 C:\Windows\System32\drivers\etc\hosts (Windows)
   127.0.0.1 passkey-demo.local
   ```
   그 후 `http://passkey-demo.local:5173` 접속

2. **localhost로만 접속**
   ```
   http://localhost:5173
   ```

## 🔒 보안 고려사항

### 현재 구현 (데모용)

이 프로젝트는 **교육 목적의 데모**입니다. 실제 프로덕션 환경에서는 다음이 필요합니다:

### 실제 프로덕션에서 추가해야 할 것들

1. **데이터베이스**
   - 현재: 메모리 저장 (서버 재시작 시 삭제)
   - 필요: PostgreSQL, MongoDB 등 영구 저장소

2. **세션 관리**
   - 필요: JWT 토큰, 세션 쿠키, Refresh token

3. **Rate Limiting**
   - 필요: 무차별 대입 공격 방지

4. **HTTPS**
   - 필요: TLS/SSL 인증서 (Let's Encrypt)

5. **Attestation 검증**
   - 현재: `attestation: 'none'`
   - 필요: 하드웨어 인증기 검증 (선택사항)

### API 엔드포인트

| 메서드 | 엔드포인트 | 설명 |
|--------|-----------|------|
| POST | `/register/start` | 등록용 challenge 생성 |
| POST | `/register/finish` | Credential 검증 및 저장 |
| POST | `/login/start` | 로그인용 challenge 생성 |
| POST | `/login/finish` | 인증 검증 |
| GET | `/users` | 등록된 사용자 목록 (디버깅용) |

## 🐛 트러블슈팅

### 문제: "이 브라우저는 WebAuthn을 지원하지 않습니다"

**해결방법:**
- 최신 버전의 Chrome, Firefox, Safari, Edge로 업데이트
- 브라우저가 최신인데도 안 된다면 `chrome://flags`에서 WebAuthn 기능 확인

### 문제: "플랫폼 인증기를 사용할 수 없습니다"

**해결방법:**
- Touch ID나 Windows Hello가 설정되어 있는지 확인
- 시스템 환경설정 → Touch ID 또는 Windows 설정 → 로그인 옵션 확인
- 외부 보안 키(YubiKey 등)를 사용할 수도 있습니다

### 문제: "잘못된 origin입니다" 오류

**해결방법:**
- `server.js`의 `clientDataJSON.origin` 확인
- 클라이언트 포트가 `5173`인지 확인
- localhost로 접속했는지 확인 (IP 주소 X)

### 문제: CORS 오류

**해결방법:**
- 서버가 `http://localhost:3001`에서 실행 중인지 확인
- 클라이언트가 `http://localhost:5173`에서 실행 중인지 확인
- `server.js`에 CORS 설정이 있는지 확인

### 문제: 등록 후 로그인이 안 됨

**해결방법:**
- 서버를 재시작하면 메모리 데이터가 사라집니다 (정상 동작)
- 다시 등록해주세요
- 실제 환경에서는 데이터베이스 사용 필요

### 문제: 모바일에서 테스트하고 싶음

**해결방법:**
1. 컴퓨터의 IP 주소 확인
2. `/etc/hosts` 파일에 추가:
   ```
   192.168.x.x passkey-demo.local
   ```
3. 모바일에서도 동일하게 hosts 파일 수정 또는 로컬 DNS 서버 사용
4. `http://passkey-demo.local:5173` 접속

## 📚 참고 자료

- [MDN Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [WebAuthn 가이드](https://webauthn.guide/)
- [FIDO Alliance](https://fidoalliance.org/)
- [Can I Use - Web Authentication API](https://caniuse.com/webauthn)

## 📝 라이선스

MIT License - 자유롭게 사용하세요!

