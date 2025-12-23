/**
 * WebAuthn 유틸리티 함수들
 * 순수 navigator.credentials API를 사용합니다.
 */

const API_URL = 'http://localhost:3001';

// === Base64URL 인코딩/디코딩 함수 ===

/**
 * ArrayBuffer를 Base64URL 문자열로 변환
 * @param {ArrayBuffer} buffer 
 * @returns {string} Base64URL 인코딩된 문자열
 */
export function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64URL 문자열을 ArrayBuffer로 변환
 * @param {string} base64url Base64URL 인코딩된 문자열
 * @returns {ArrayBuffer}
 */
export function base64urlToBuffer(base64url) {
  const base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  
  // 패딩 추가
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// === Passkey 등록 함수 ===

/**
 * 새로운 Passkey를 등록합니다.
 * @param {string} username 사용자 이름
 * @returns {Promise<{success: boolean, message: string}>}
 */
export async function registerPasskey(username) {
  try {
    // 1단계: 서버로부터 challenge와 옵션 받기
    const startResponse = await fetch(`${API_URL}/register/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });

    if (!startResponse.ok) {
      const error = await startResponse.json();
      throw new Error(error.error || '등록 시작 실패');
    }

    const options = await startResponse.json();

    // 2단계: Base64URL 문자열을 ArrayBuffer로 변환
    const publicKeyOptions = {
      ...options,
      challenge: base64urlToBuffer(options.challenge),
      user: {
        ...options.user,
        id: base64urlToBuffer(options.user.id)
      }
    };

    // 3단계: 브라우저의 WebAuthn API를 호출하여 새 credential 생성
    // 이 과정에서 사용자에게 생체 인증을 요청합니다 (Touch ID, Face ID 등)
    console.log('📱 WebAuthn credential 생성 중...', publicKeyOptions);
    
    const credential = await navigator.credentials.create({
      publicKey: publicKeyOptions
    });

    if (!credential) {
      throw new Error('Credential 생성 실패');
    }

    console.log('✅ Credential 생성 완료:', credential);

    // 4단계: Credential을 서버로 전송하기 위해 직렬화
    const credentialJSON = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        attestationObject: bufferToBase64url(credential.response.attestationObject),
        // 서버에서 challenge 검증을 위해 추가
        clientDataJSON_challenge: JSON.parse(
          new TextDecoder().decode(credential.response.clientDataJSON)
        ).challenge
      }
    };

    // AuthenticatorAttestationResponse에서 공개키 추출
    if (credential.response.getPublicKey) {
      const publicKeyBuffer = credential.response.getPublicKey();
      if (publicKeyBuffer) {
        credentialJSON.response.publicKey = bufferToBase64url(publicKeyBuffer);
      }
    }

    // 5단계: 서버로 credential 전송하여 저장
    const finishResponse = await fetch(`${API_URL}/register/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        credential: credentialJSON
      })
    });

    if (!finishResponse.ok) {
      const error = await finishResponse.json();
      throw new Error(error.error || '등록 완료 실패');
    }

    const result = await finishResponse.json();
    return {
      success: true,
      message: result.message || 'Passkey가 성공적으로 등록되었습니다!',
      userId: result.userId
    };

  } catch (error) {
    console.error('❌ Passkey 등록 오류:', error);
    
    // 사용자 친화적인 오류 메시지 반환
    if (error.name === 'NotAllowedError') {
      return {
        success: false,
        message: '사용자가 등록을 취소했습니다.'
      };
    } else if (error.name === 'NotSupportedError') {
      return {
        success: false,
        message: '이 브라우저는 Passkey를 지원하지 않습니다.'
      };
    } else if (error.name === 'InvalidStateError') {
      return {
        success: false,
        message: '이미 등록된 인증기입니다.'
      };
    }
    
    return {
      success: false,
      message: error.message || 'Passkey 등록 중 오류가 발생했습니다.'
    };
  }
}

// === Passkey 로그인 함수 ===

/**
 * Passkey를 사용하여 로그인합니다.
 * @param {string} username 사용자 이름 (선택사항, discoverable credential 사용 시)
 * @returns {Promise<{success: boolean, message: string, user?: object}>}
 */
export async function loginPasskey(username = '') {
  try {
    // 1단계: 서버로부터 challenge와 옵션 받기
    const startResponse = await fetch(`${API_URL}/login/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username || undefined })
    });

    if (!startResponse.ok) {
      const error = await startResponse.json();
      throw new Error(error.error || '로그인 시작 실패');
    }

    const options = await startResponse.json();

    // 2단계: Base64URL 문자열을 ArrayBuffer로 변환
    const publicKeyOptions = {
      ...options,
      challenge: base64urlToBuffer(options.challenge)
    };

    // allowCredentials가 있으면 변환
    if (options.allowCredentials && options.allowCredentials.length > 0) {
      publicKeyOptions.allowCredentials = options.allowCredentials.map(cred => ({
        ...cred,
        id: base64urlToBuffer(cred.id)
      }));
    }

    // 3단계: 브라우저의 WebAuthn API를 호출하여 인증
    // Discoverable credential을 사용하면 사용자가 저장된 Passkey 목록에서 선택할 수 있습니다
    console.log('🔐 WebAuthn 인증 시작...', publicKeyOptions);
    
    const credential = await navigator.credentials.get({
      publicKey: publicKeyOptions
    });

    if (!credential) {
      throw new Error('인증 실패');
    }

    console.log('✅ 인증 완료:', credential);

    // 4단계: Credential을 서버로 전송하기 위해 직렬화
    const credentialJSON = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        authenticatorData: bufferToBase64url(credential.response.authenticatorData),
        signature: bufferToBase64url(credential.response.signature),
        userHandle: credential.response.userHandle 
          ? bufferToBase64url(credential.response.userHandle)
          : null,
        // 서버에서 challenge 검증을 위해 추가
        clientDataJSON_challenge: JSON.parse(
          new TextDecoder().decode(base64urlToBuffer(
            bufferToBase64url(credential.response.clientDataJSON)
          ))
        ).challenge
      }
    };

    // 5단계: 서버로 credential 전송하여 검증
    const finishResponse = await fetch(`${API_URL}/login/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential: credentialJSON
      })
    });

    if (!finishResponse.ok) {
      const error = await finishResponse.json();
      throw new Error(error.error || '로그인 완료 실패');
    }

    const result = await finishResponse.json();
    return {
      success: true,
      message: result.message || '로그인 성공!',
      user: result.user
    };

  } catch (error) {
    console.error('❌ Passkey 로그인 오류:', error);
    
    // 사용자 친화적인 오류 메시지 반환
    if (error.name === 'NotAllowedError') {
      return {
        success: false,
        message: '사용자가 로그인을 취소했습니다.'
      };
    } else if (error.name === 'NotSupportedError') {
      return {
        success: false,
        message: '이 브라우저는 Passkey를 지원하지 않습니다.'
      };
    }
    
    return {
      success: false,
      message: error.message || 'Passkey 로그인 중 오류가 발생했습니다.'
    };
  }
}

/**
 * 브라우저가 WebAuthn을 지원하는지 확인
 * @returns {boolean}
 */
export function isWebAuthnSupported() {
  return window.PublicKeyCredential !== undefined &&
         navigator.credentials !== undefined;
}

/**
 * 플랫폼 인증기(Touch ID, Face ID 등)가 사용 가능한지 확인
 * @returns {Promise<boolean>}
 */
export async function isPlatformAuthenticatorAvailable() {
  if (!isWebAuthnSupported()) {
    return false;
  }
  
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch (error) {
    console.error('플랫폼 인증기 확인 실패:', error);
    return false;
  }
}

