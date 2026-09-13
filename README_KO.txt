SJ DONA COMPLETE — 설치 및 실행

이 버전은 화면만 있는 데모가 아니라 서버를 포함한 실행형 프로젝트입니다.

포함 기능
- OpenAI Responses API 실제 대화
- DONA 전용 시스템 역할
- 업무/개인 할 일과 일정
- AI 아침 브리핑
- 음성 입력 / 음성 읽기
- Google OAuth 연결
- Gmail 최근 메일 읽기
- Google Calendar 향후 일정 읽기
- Google Drive 최근 문서 읽기
- Google 정보 + 내부 업무정보를 AI가 함께 참고
- 개인/사업 장기 기억 메모
- 알림 시간 설정
- PWA 홈 화면 설치

1. 준비
- Node.js 20 이상
- OpenAI API Key
- Google Cloud OAuth Web Application Client ID / Secret

2. 설치
압축을 풀고 터미널에서:
npm install

3. 환경설정
.env.example 을 .env 로 복사한 뒤 값을 입력:
OPENAI_API_KEY=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
TOKEN_ENCRYPTION_KEY=...

TOKEN_ENCRYPTION_KEY 생성 예:
openssl rand -hex 32

4. Google Cloud 설정
- Gmail API, Google Calendar API, Google Drive API 활성화
- OAuth Web Application 생성
- Authorized redirect URI:
  http://localhost:8787/auth/google/callback
  실제 배포 시: https://내도메인/auth/google/callback
- 앱을 개인 테스트 용도로 쓸 때는 본인 Google 계정을 Test user에 추가

5. 실행
npm start
브라우저에서:
http://localhost:8787

6. 휴대폰 설치
HTTPS 주소로 배포한 뒤 Android Chrome에서
메뉴 → 앱 설치 / 홈 화면에 추가

7. 중요 보안
- OpenAI API Key는 브라우저 코드에 넣지 않습니다.
- Google refresh token은 TOKEN_ENCRYPTION_KEY로 서버 파일에 암호화 저장합니다.
- 이 프로젝트는 1인 개인 사용 기준입니다. 여러 사용자가 쓰는 공개 서비스로 바꾸려면 계정별 인증/DB/권한분리/CSRF/세션 보안을 추가해야 합니다.
- .env와 data/google.tokens.enc는 절대 공개 저장소에 올리지 마세요.

8. 완전 백그라운드 알림
현재 브라우저 알림은 앱이 실행 중일 때 동작합니다.
앱이 완전히 종료된 상태에서도 자동 푸시를 받으려면 Web Push(Firebase/FCM 등) 서버 구성이 추가로 필요합니다.
