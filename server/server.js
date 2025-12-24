import express from "express";
import cors from "cors";
import crypto from "crypto";
import cbor from "cbor";

const app = express();
const PORT = 3001;

// 미들웨어
app.use(cors());
app.use(express.json());

// 메모리 내 데이터 저장소
const db = {
  users: [],
  challenges: new Map(), // challenge -> { userId, timestamp, type }
};

// === 유틸리티 함수 ===

/**
 * Base64URL 디코딩
 */
function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "="
  );
  return Buffer.from(padded, "base64");
}

/**
 * Buffer를 Base64URL로 인코딩
 * JSON이나 URL로 주고받아야 해서 Base64URL로 변환
 */
function bufferToBase64url(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * 공개키를 Node.js crypto 모듈에서 사용 가능한 형식으로 변환
 *
 * WebAuthn의 getPublicKey()는 브라우저에 따라 다른 형식을 반환합니다:
 * - SPKI (SubjectPublicKeyInfo) 형식: DER 인코딩된 X.509 공개키 (0x30으로 시작)
 * - COSE 형식: CBOR 인코딩된 공개키
 *
 * 이 함수는 두 형식을 모두 지원합니다.
 */
function parsePublicKey(publicKeyBase64url) {
  try {
    const publicKeyBuffer = base64urlToBuffer(publicKeyBase64url);
    const bufferArray = Buffer.from(publicKeyBuffer);

    // 첫 바이트로 형식 판별
    const firstByte = bufferArray[0];

    // SPKI 형식 (DER 인코딩, 0x30으로 시작)
    if (firstByte === 0x30) {
      // SPKI 형식을 직접 KeyObject로 변환
      return crypto.createPublicKey({
        key: bufferArray,
        format: "der",
        type: "spki",
      });
    }

    // COSE 형식 (CBOR 인코딩)
    const coseKey = cbor.decodeFirstSync(publicKeyBuffer);

    // COSE 키 타입 확인
    const kty = coseKey.get(1); // Key Type
    const alg = coseKey.get(3); // Algorithm

    // ES256 (ECDSA with P-256 and SHA-256) 지원
    if (alg === -7) {
      const crv = coseKey.get(-1); // Curve
      const x = coseKey.get(-2); // X coordinate
      const y = coseKey.get(-3); // Y coordinate

      if (crv !== 1) {
        // P-256 = 1
        throw new Error("지원하지 않는 곡선입니다");
      }

      // Node.js crypto 모듈에서 사용할 수 있는 KeyObject 생성
      const jwk = {
        kty: "EC",
        crv: "P-256",
        x: Buffer.from(x).toString("base64url"),
        y: Buffer.from(y).toString("base64url"),
      };

      return crypto.createPublicKey({
        key: jwk,
        format: "jwk",
      });
    }

    // RS256 (RSA with SHA-256) 지원
    if (alg === -257) {
      const n = coseKey.get(-1); // Modulus
      const e = coseKey.get(-2); // Exponent

      return crypto.createPublicKey({
        key: {
          kty: "RSA",
          n: Buffer.from(n).toString("base64url"),
          e: Buffer.from(e).toString("base64url"),
        },
        format: "jwk",
      });
    }

    throw new Error(`지원하지 않는 알고리즘입니다: ${alg}`);
  } catch (error) {
    console.error("공개키 파싱 오류:", error);
    return null;
  }
}

/**
 * AuthenticatorData 파싱
 * @param {Buffer} authData
 * @returns {Object}
 */
function parseAuthenticatorData(authData) {
  // AuthenticatorData 구조:
  // - rpIdHash: 32 bytes (SHA-256 해시)
  // - flags: 1 byte
  // - signCount: 4 bytes (사용하지 않음)

  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];

  return {
    rpIdHash,
    flags,
    userPresent: !!(flags & 0x01), // UP: User Present
    userVerified: !!(flags & 0x04), // UV: User Verified
    attestedData: !!(flags & 0x40), // AT: Attested Credential Data
    extensionData: !!(flags & 0x80), // ED: Extension Data
  };
}

/**
 * 시그니처 검증 (ES256/RS256 알고리즘)
 *
 * 검증 과정:
 * 1. COSE 공개키를 파싱하여 KeyObject로 변환
 * 2. authenticatorData + SHA256(clientDataJSON)을 서명 대상 데이터로 생성
 * 3. 공개키로 서명을 검증
 *
 * @param {string} publicKeyBase64url - Base64URL 인코딩된 COSE 공개키
 * @param {string} signatureBase64url - Base64URL 인코딩된 서명
 * @param {string} authenticatorDataBase64url - Base64URL 인코딩된 인증기 데이터
 * @param {string} clientDataJSONBase64url - Base64URL 인코딩된 클라이언트 데이터
 * @returns {boolean}
 */
function verifySignature(
  publicKeyBase64url,
  signatureBase64url,
  authenticatorDataBase64url,
  clientDataJSONBase64url
) {
  try {
    // 1. Base64URL 디코딩
    const signature = base64urlToBuffer(signatureBase64url);
    const authenticatorData = base64urlToBuffer(authenticatorDataBase64url);
    const clientDataJSON = base64urlToBuffer(clientDataJSONBase64url);

    // 2. ClientDataJSON의 SHA-256 해시 계산
    const clientDataHash = crypto
      .createHash("sha256")
      .update(clientDataJSON)
      .digest();

    // 3. 서명 대상 데이터 생성
    // WebAuthn 스펙에 따라 authenticatorData와 clientDataHash를 연결합니다
    const signedData = Buffer.concat([authenticatorData, clientDataHash]);

    // 4. 공개키를 Node.js KeyObject로 변환
    const publicKey = parsePublicKey(publicKeyBase64url);

    if (!publicKey) {
      return false;
    }

    // 5. 서명 검증
    const isValid = crypto.verify(
      "sha256", // 해시 알고리즘
      signedData, // 서명된 데이터
      publicKey, // 공개키
      signature // 서명
    );

    return isValid;
  } catch (error) {
    console.error("서명 검증 오류:", error);
    return false;
  }
}

/**
 * 랜덤 challenge 생성
 */
function generateChallenge() {
  return bufferToBase64url(crypto.randomBytes(32));
}

/**
 * 사용자 찾기 또는 생성
 */
function findOrCreateUser(username) {
  let user = db.users.find((u) => u.username === username);
  if (!user) {
    user = {
      id: crypto.randomUUID(),
      username,
      credentials: [],
    };
    db.users.push(user);
  }
  return user;
}

// === 등록 엔드포인트 ===

/**
 * POST /register/start
 * 새로운 Passkey 등록을 시작하고 challenge를 생성합니다.
 */
app.post("/register/start", (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: "Username이 필요합니다" });
    }

    const user = findOrCreateUser(username);
    const challenge = generateChallenge();

    // challenge 저장 (10분 유효)
    db.challenges.set(challenge, {
      userId: user.id,
      timestamp: Date.now(),
      type: "register",
    });

    // 10분 후 자동 삭제
    setTimeout(() => db.challenges.delete(challenge), 10 * 60 * 1000);

    // PublicKeyCredentialCreationOptions 생성
    const options = {
      // challenge: 서버에서 생성한 랜덤 값 (32바이트)
      // Replay attack 방지를 위해 일회용으로 사용되며, 클라이언트가 서명에 포함시킵니다
      challenge,

      // rp (Relying Party): 이 웹사이트/서비스의 정보
      rp: {
        name: "Passkey Demo", // 사용자에게 표시될 서비스 이름
        id: "localhost", // 도메인 (실제 배포 시 'example.com' 같은 실제 도메인 사용)
      },

      // user: 등록할 사용자의 정보
      user: {
        id: bufferToBase64url(Buffer.from(user.id)), // 사용자 고유 ID (변경되지 않는 값, UUID 등)
        name: username, // 사용자 이름 (로그인 ID, 이메일 등)
        displayName: username, // 사용자에게 표시될 이름 (실명 등)
      },

      // pubKeyCredParams: 지원할 공개키 알고리즘 목록 (우선순위 순)
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256 (ECDSA with SHA-256) - 권장, 대부분의 인증기 지원
        { type: "public-key", alg: -257 }, // RS256 (RSA with SHA-256) - 호환성을 위한 대안
      ],

      // authenticatorSelection: 인증기 선택 기준
      authenticatorSelection: {
        authenticatorAttachment: "platform", // 'platform': 내장 인증기(Touch ID, Face ID, Windows Hello)
        // 'cross-platform': 외부 보안 키(YubiKey 등)
        // 생략 시: 모두 허용

        requireResidentKey: true, // true: Discoverable Credential (사용자 이름 없이 로그인 가능)
        // false: 서버가 credential ID를 기억해야 함

        userVerification: "required", // 'required': 생체 인증 필수
        // 'preferred': 가능하면 생체 인증
        // 'discouraged': 생체 인증 불필요
      },

      // timeout: 사용자가 인증을 완료할 수 있는 시간 (밀리초)
      timeout: 60000, // 60초

      // attestation: 인증기의 신뢰성 증명 방식
      // 'none': 증명 불필요 (대부분의 경우 사용, 개인정보 보호)
      // 'indirect': 익명화된 증명
      // 'direct': 직접 증명 (하드웨어 인증기 검증 필요 시)
      attestation: "none",
    };

    res.json(options);
  } catch (error) {
    console.error("Register start error:", error);
    res.status(500).json({ error: "서버 오류가 발생했습니다" });
  }
});

/**
 * POST /register/finish
 * 클라이언트로부터 받은 credential을 검증하고 저장합니다.
 */
app.post("/register/finish", (req, res) => {
  try {
    const { username, credential } = req.body;

    if (!username || !credential) {
      return res.status(400).json({ error: "잘못된 요청입니다" });
    }

    const user = db.users.find((u) => u.username === username);
    if (!user) {
      return res.status(404).json({ error: "사용자를 찾을 수 없습니다" });
    }

    // Challenge 검증
    const challengeData = db.challenges.get(
      credential.response.clientDataJSON_challenge
    );
    if (
      !challengeData ||
      challengeData.userId !== user.id ||
      challengeData.type !== "register"
    ) {
      return res.status(400).json({ error: "유효하지 않은 challenge입니다" });
    }

    // Challenge 삭제 (일회용)
    db.challenges.delete(credential.response.clientDataJSON_challenge);

    // ClientDataJSON 검증위해 Buffer로 다시 변환
    const clientDataJSON = JSON.parse(
      Buffer.from(credential.response.clientDataJSON, "base64").toString(
        "utf-8"
      )
    );
    // type 검증
    if (clientDataJSON.type !== "webauthn.create") {
      return res.status(400).json({ error: "잘못된 credential type입니다" });
    }
    // origin 검증
    if (clientDataJSON.origin !== "http://localhost:5173") {
      return res.status(400).json({ error: "잘못된 origin입니다" });
    }

    // AttestationObject에서 공개키 추출
    let publicKey = null;

    // 클라이언트가 publicKey를 직접 보냈다면 사용
    if (credential.response.publicKey) {
      publicKey = credential.response.publicKey;
    } else {
      // 없다면 attestationObject에서 추출
      try {
        const attestationObject = cbor.decodeFirstSync(
          base64urlToBuffer(credential.response.attestationObject)
        );

        // authData에서 공개키 추출
        // authData 구조: rpIdHash(32) + flags(1) + signCount(4) + attestedCredentialData
        const authData = attestationObject.authData;

        // attestedCredentialData가 있는지 확인 (flags의 6번째 비트)
        const flags = authData[32];
        const hasAttestedCredentialData = !!(flags & 0x40);

        if (hasAttestedCredentialData) {
          // attestedCredentialData 시작 위치: 37 (32 + 1 + 4)
          const aaguidStart = 37;
          const credentialIdLengthStart = aaguidStart + 16; // AAGUID는 16바이트

          // Credential ID 길이 (2바이트, big-endian)
          const credentialIdLength =
            (authData[credentialIdLengthStart] << 8) |
            authData[credentialIdLengthStart + 1];

          // 공개키 시작 위치
          const publicKeyStart =
            credentialIdLengthStart + 2 + credentialIdLength;

          // 공개키 추출 (COSE 형식)
          const publicKeyBytes = authData.slice(publicKeyStart);
          publicKey = bufferToBase64url(publicKeyBytes);
        }
      } catch (error) {
        console.error("AttestationObject 파싱 오류:", error);
      }
    }

    if (!publicKey) {
      return res.status(400).json({ error: "공개키를 추출할 수 없습니다" });
    }

    // Credential 저장
    const credentialData = {
      credentialId: credential.id, // Credential의 고유 ID
      publicKey: publicKey, // 공개키 (서명 검증에 사용)
      createdAt: Date.now(), // 등록 시간
    };

    user.credentials.push(credentialData);

    res.json({
      success: true,
      message: "Passkey가 성공적으로 등록되었습니다",
      userId: user.id,
    });
  } catch (error) {
    console.error("Register finish error:", error);
    res.status(500).json({ error: "등록 중 오류가 발생했습니다" });
  }
});

// === 로그인 엔드포인트 ===

/**
 * POST /login/start
 * 로그인을 시작하고 challenge를 생성합니다.
 */
app.post("/login/start", (req, res) => {
  try {
    const { username } = req.body;

    // username은 선택사항 (discoverable credential 사용)
    let user = null;
    if (username) {
      user = db.users.find((u) => u.username === username);
      if (!user) {
        return res.status(404).json({ error: "사용자를 찾을 수 없습니다" });
      }
    }

    const challenge = generateChallenge();

    // challenge 저장
    db.challenges.set(challenge, {
      userId: user ? user.id : null,
      timestamp: Date.now(),
      type: "login",
    });

    // 10분 후 자동 삭제
    setTimeout(() => db.challenges.delete(challenge), 10 * 60 * 1000);

    // PublicKeyCredentialRequestOptions 생성
    const options = {
      challenge,
      rpId: "localhost",
      allowCredentials: [], // 빈 배열 = discoverable credential 사용
      userVerification: "required",
      timeout: 60000,
    };

    res.json(options);
  } catch (error) {
    console.error("Login start error:", error);
    res.status(500).json({ error: "서버 오류가 발생했습니다" });
  }
});

/**
 * POST /login/finish
 * 인증 응답을 검증합니다.
 */
app.post("/login/finish", (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ error: "잘못된 요청입니다" });
    }

    // Challenge 검증
    const challengeData = db.challenges.get(
      credential.response.clientDataJSON_challenge
    );
    if (!challengeData || challengeData.type !== "login") {
      return res.status(400).json({ error: "유효하지 않은 challenge입니다" });
    }

    // Challenge 삭제 (일회용)
    db.challenges.delete(credential.response.clientDataJSON_challenge);

    // ClientDataJSON 검증
    const clientDataJSON = JSON.parse(
      Buffer.from(credential.response.clientDataJSON, "base64").toString(
        "utf-8"
      )
    );

    if (clientDataJSON.type !== "webauthn.get") {
      return res.status(400).json({ error: "잘못된 credential type입니다" });
    }

    if (clientDataJSON.origin !== "http://localhost:5173") {
      return res.status(400).json({ error: "잘못된 origin입니다" });
    }

    // Credential ID로 사용자 찾기
    let user = null;
    let userCredential = null;

    for (const u of db.users) {
      const cred = u.credentials.find((c) => c.credentialId === credential.id);
      if (cred) {
        user = u;
        userCredential = cred;
        break;
      }
    }

    if (!user || !userCredential) {
      return res
        .status(404)
        .json({ error: "등록된 credential을 찾을 수 없습니다" });
    }

    // === 시그니처 검증 ===
    // 1. AuthenticatorData 파싱 및 검증
    const authData = parseAuthenticatorData(
      base64urlToBuffer(credential.response.authenticatorData)
    );

    // User Present (사용자가 인증기와 상호작용함) 확인
    if (!authData.userPresent) {
      return res.status(400).json({ error: "사용자 인증 실패 (User Present)" });
    }

    // User Verified (생체 인증 완료) 확인
    if (!authData.userVerified) {
      return res
        .status(400)
        .json({ error: "사용자 인증 실패 (User Verified)" });
    }

    // 2. RP ID 해시 검증
    const expectedRpIdHash = crypto
      .createHash("sha256")
      .update("localhost")
      .digest();

    if (!authData.rpIdHash.equals(expectedRpIdHash)) {
      return res.status(400).json({ error: "RP ID 검증 실패" });
    }

    // 3. 시그니처 검증
    // 공개키로 서명을 검증하여 인증기가 실제로 개인키를 소유하고 있는지 확인
    const isValidSignature = verifySignature(
      userCredential.publicKey,
      credential.response.signature,
      credential.response.authenticatorData,
      credential.response.clientDataJSON
    );

    if (!isValidSignature) {
      return res.status(400).json({ error: "시그니처 검증 실패" });
    }

    res.json({
      success: true,
      message: "로그인 성공",
      user: {
        id: user.id,
        username: user.username,
      },
    });
  } catch (error) {
    console.error("Login finish error:", error);
    res.status(500).json({ error: "로그인 중 오류가 발생했습니다" });
  }
});

// === 유틸리티 엔드포인트 ===

/**
 * GET /users
 * 등록된 사용자 목록 조회 (디버깅용)
 */
app.get("/users", (req, res) => {
  res.json({
    users: db.users.map((u) => ({
      id: u.id,
      username: u.username,
      credentialCount: u.credentials.length,
    })),
  });
});

// 서버 시작
app.listen(PORT, () => {
  console.log(
    `✅ Passkey 데모 서버가 http://localhost:${PORT} 에서 실행 중입니다`
  );
  console.log(`📝 등록된 사용자: ${db.users.length}명`);
});
