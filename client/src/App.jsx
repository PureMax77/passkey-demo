import { useState, useEffect } from 'react';
import { 
  registerPasskey, 
  loginPasskey, 
  isWebAuthnSupported, 
  isPlatformAuthenticatorAvailable 
} from './utils/webauthn';

function App() {
  const [username, setUsername] = useState('');
  const [user, setUser] = useState(null);
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isSupported, setIsSupported] = useState(true);

  // 브라우저 지원 확인
  useEffect(() => {
    const checkSupport = async () => {
      const supported = isWebAuthnSupported();
      setIsSupported(supported);
      
      if (supported) {
        const platformAvailable = await isPlatformAuthenticatorAvailable();
        if (!platformAvailable) {
          setMessage({
            type: 'info',
            text: '플랫폼 인증기(Touch ID, Face ID 등)를 사용할 수 없습니다. 외부 보안 키를 사용하세요.'
          });
        }
      } else {
        setMessage({
          type: 'error',
          text: '이 브라우저는 WebAuthn을 지원하지 않습니다. Chrome, Firefox, Safari, Edge를 사용하세요.'
        });
      }
    };
    
    checkSupport();
  }, []);

  // Passkey 등록 핸들러
  const handleRegister = async () => {
    if (!username.trim()) {
      setMessage({
        type: 'error',
        text: '사용자 이름을 입력하세요.'
      });
      return;
    }

    setLoading(true);
    setMessage({
      type: 'info',
      text: '🔐 생체 인증을 진행해주세요...'
    });

    try {
      const result = await registerPasskey(username.trim());
      
      if (result.success) {
        setMessage({
          type: 'success',
          text: result.message
        });
        // 등록 후 자동으로 로그인된 상태로 설정
        setUser({
          id: result.userId,
          username: username.trim()
        });
      } else {
        setMessage({
          type: 'error',
          text: result.message
        });
      }
    } catch (error) {
      setMessage({
        type: 'error',
        text: '등록 중 예상치 못한 오류가 발생했습니다.'
      });
    } finally {
      setLoading(false);
    }
  };

  // Passkey 로그인 핸들러
  const handleLogin = async () => {
    setLoading(true);
    setMessage({
      type: 'info',
      text: '🔐 생체 인증을 진행해주세요...'
    });

    try {
      // username을 전달하지 않으면 discoverable credential 사용
      const result = await loginPasskey(username.trim());
      
      if (result.success) {
        setMessage({
          type: 'success',
          text: result.message
        });
        setUser(result.user);
      } else {
        setMessage({
          type: 'error',
          text: result.message
        });
      }
    } catch (error) {
      setMessage({
        type: 'error',
        text: '로그인 중 예상치 못한 오류가 발생했습니다.'
      });
    } finally {
      setLoading(false);
    }
  };

  // 로그아웃 핸들러
  const handleLogout = () => {
    setUser(null);
    setUsername('');
    setMessage({
      type: 'success',
      text: '로그아웃되었습니다.'
    });
  };

  // Enter 키 핸들러
  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !loading && username.trim()) {
      handleRegister();
    }
  };

  // 로그인된 상태 UI
  if (user) {
    return (
      <div className="container">
        <div className="user-info">
          <h2>👋 안녕하세요, {user.username}님!</h2>
          <p>Passkey로 안전하게 로그인되었습니다.</p>
        </div>
        
        <div className="button-group">
          <button 
            className="btn-logout"
            onClick={handleLogout}
          >
            로그아웃
          </button>
        </div>

        {message && (
          <div className={`message ${message.type}`}>
            {message.text}
          </div>
        )}
      </div>
    );
  }

  // 로그인 전 UI
  return (
    <div className="container">
      <div className="header">
        <h1>🔐 Passkey 데모</h1>
        <p>생체 인증으로 안전하게 로그인하세요</p>
      </div>

      {!isSupported && (
        <div className="browser-support">
          ⚠️ 이 브라우저는 WebAuthn을 지원하지 않습니다. 
          최신 버전의 Chrome, Firefox, Safari, Edge를 사용하세요.
        </div>
      )}

      <div className="form-group">
        <label htmlFor="username">사용자 이름</label>
        <input
          id="username"
          type="text"
          placeholder="홍길동"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          onKeyPress={handleKeyPress}
          disabled={loading || !isSupported}
          autoComplete="username webauthn"
        />
      </div>

      <div className="button-group">
        <button
          className="btn-primary"
          onClick={handleRegister}
          disabled={loading || !isSupported || !username.trim()}
        >
          {loading ? (
            <>
              <span className="spinner"></span>
              처리 중...
            </>
          ) : (
            <>
              ✨ Passkey 등록
            </>
          )}
        </button>

        <div className="divider">
          <span>또는</span>
        </div>

        <button
          className="btn-secondary"
          onClick={handleLogin}
          disabled={loading || !isSupported}
        >
          {loading ? (
            <>
              <span className="spinner"></span>
              처리 중...
            </>
          ) : (
            <>
              🔑 Passkey로 로그인
            </>
          )}
        </button>
      </div>

      {message && (
        <div className={`message ${message.type}`}>
          {message.text}
        </div>
      )}

      <div className="browser-support" style={{ marginTop: '24px' }}>
        <strong>💡 참고:</strong>
        <ul style={{ marginTop: '8px', marginLeft: '20px' }}>
          <li>처음 방문 시 "Passkey 등록"을 눌러 생체 인증을 등록하세요.</li>
          <li>등록 후 "Passkey로 로그인"으로 간편하게 로그인할 수 있습니다.</li>
          <li>사용자 이름 없이도 로그인할 수 있습니다 (Discoverable Credential).</li>
        </ul>
      </div>
    </div>
  );
}

export default App;

