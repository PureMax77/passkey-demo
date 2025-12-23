import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
const PORT = 3001;

// 미들웨어
app.use(cors());
app.use(express.json());

// 메모리 내 데이터 저장소
const db = {
  users: [],
  challenges: new Map() // challenge -> { userId, timestamp, type }
};

// === 유틸리티 함수 ===

/**
 * Base64URL 디코딩
 */
function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  return Buffer.from(padded, 'base64');
}

/**
 * Buffer를 Base64URL로 인코딩
 */
function bufferToBase64url(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
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
  let user = db.users.find(u => u.username === username);
  if (!user) {
    user = {
      id: crypto.randomUUID(),
      username,
      credentials: []
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
app.post('/register/start', (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: 'Username이 필요합니다' });
    }

    const user = findOrCreateUser(username);
    const challenge = generateChallenge();

    // challenge 저장 (10분 유효)
    db.challenges.set(challenge, {
      userId: user.id,
      timestamp: Date.now(),
      type: 'register'
    });

    // 10분 후 자동 삭제
    setTimeout(() => db.challenges.delete(challenge), 10 * 60 * 1000);

    // PublicKeyCredentialCreationOptions 생성
    const options = {
      challenge,
      rp: {
        name: 'Passkey Demo',
        id: 'localhost'
      },
      user: {
        id: bufferToBase64url(Buffer.from(user.id)),
        name: username,
        displayName: username
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },  // ES256
        { type: 'public-key', alg: -257 } // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        requireResidentKey: true,
        userVerification: 'required'
      },
      timeout: 60000,
      attestation: 'none'
    };

    res.json(options);
  } catch (error) {
    console.error('Register start error:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  }
});

/**
 * POST /register/finish
 * 클라이언트로부터 받은 credential을 검증하고 저장합니다.
 */
app.post('/register/finish', (req, res) => {
  try {
    const { username, credential } = req.body;

    if (!username || !credential) {
      return res.status(400).json({ error: '잘못된 요청입니다' });
    }

    const user = db.users.find(u => u.username === username);
    if (!user) {
      return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
    }

    // Challenge 검증
    const challengeData = db.challenges.get(credential.response.clientDataJSON_challenge);
    if (!challengeData || challengeData.userId !== user.id || challengeData.type !== 'register') {
      return res.status(400).json({ error: '유효하지 않은 challenge입니다' });
    }

    // Challenge 삭제 (일회용)
    db.challenges.delete(credential.response.clientDataJSON_challenge);

    // ClientDataJSON 검증
    const clientDataJSON = JSON.parse(
      Buffer.from(credential.response.clientDataJSON, 'base64').toString('utf-8')
    );

    if (clientDataJSON.type !== 'webauthn.create') {
      return res.status(400).json({ error: '잘못된 credential type입니다' });
    }

    if (clientDataJSON.origin !== 'http://localhost:5173') {
      return res.status(400).json({ error: '잘못된 origin입니다' });
    }

    // Credential 저장
    const credentialData = {
      credentialId: credential.id,
      publicKey: credential.response.publicKey,
      counter: 0,
      createdAt: Date.now()
    };

    user.credentials.push(credentialData);

    res.json({ 
      success: true, 
      message: 'Passkey가 성공적으로 등록되었습니다',
      userId: user.id
    });
  } catch (error) {
    console.error('Register finish error:', error);
    res.status(500).json({ error: '등록 중 오류가 발생했습니다' });
  }
});

// === 로그인 엔드포인트 ===

/**
 * POST /login/start
 * 로그인을 시작하고 challenge를 생성합니다.
 */
app.post('/login/start', (req, res) => {
  try {
    const { username } = req.body;

    // username은 선택사항 (discoverable credential 사용)
    let user = null;
    if (username) {
      user = db.users.find(u => u.username === username);
      if (!user) {
        return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
      }
    }

    const challenge = generateChallenge();

    // challenge 저장
    db.challenges.set(challenge, {
      userId: user ? user.id : null,
      timestamp: Date.now(),
      type: 'login'
    });

    // 10분 후 자동 삭제
    setTimeout(() => db.challenges.delete(challenge), 10 * 60 * 1000);

    // PublicKeyCredentialRequestOptions 생성
    const options = {
      challenge,
      rpId: 'localhost',
      allowCredentials: [], // 빈 배열 = discoverable credential 사용
      userVerification: 'required',
      timeout: 60000
    };

    res.json(options);
  } catch (error) {
    console.error('Login start error:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  }
});

/**
 * POST /login/finish
 * 인증 응답을 검증합니다.
 */
app.post('/login/finish', (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ error: '잘못된 요청입니다' });
    }

    // Challenge 검증
    const challengeData = db.challenges.get(credential.response.clientDataJSON_challenge);
    if (!challengeData || challengeData.type !== 'login') {
      return res.status(400).json({ error: '유효하지 않은 challenge입니다' });
    }

    // Challenge 삭제 (일회용)
    db.challenges.delete(credential.response.clientDataJSON_challenge);

    // ClientDataJSON 검증
    const clientDataJSON = JSON.parse(
      Buffer.from(credential.response.clientDataJSON, 'base64').toString('utf-8')
    );

    if (clientDataJSON.type !== 'webauthn.get') {
      return res.status(400).json({ error: '잘못된 credential type입니다' });
    }

    if (clientDataJSON.origin !== 'http://localhost:5173') {
      return res.status(400).json({ error: '잘못된 origin입니다' });
    }

    // Credential ID로 사용자 찾기
    let user = null;
    let userCredential = null;

    for (const u of db.users) {
      const cred = u.credentials.find(c => c.credentialId === credential.id);
      if (cred) {
        user = u;
        userCredential = cred;
        break;
      }
    }

    if (!user || !userCredential) {
      return res.status(404).json({ error: '등록된 credential을 찾을 수 없습니다' });
    }

    // 실제 구현에서는 여기서 signature를 검증해야 합니다
    // 이 데모에서는 간단히 credential 존재 여부만 확인합니다

    // Counter 업데이트 (replay attack 방지)
    userCredential.counter++;

    res.json({ 
      success: true,
      message: '로그인 성공',
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (error) {
    console.error('Login finish error:', error);
    res.status(500).json({ error: '로그인 중 오류가 발생했습니다' });
  }
});

// === 유틸리티 엔드포인트 ===

/**
 * GET /users
 * 등록된 사용자 목록 조회 (디버깅용)
 */
app.get('/users', (req, res) => {
  res.json({
    users: db.users.map(u => ({
      id: u.id,
      username: u.username,
      credentialCount: u.credentials.length
    }))
  });
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`✅ Passkey 데모 서버가 http://localhost:${PORT} 에서 실행 중입니다`);
  console.log(`📝 등록된 사용자: ${db.users.length}명`);
});

