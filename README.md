# 과제 8 — 소개 페이지에 패스키 비공개 자리

> 이 브랜치는 과제 1의 `index.html`을 보존하고 하단에 비공개 영역을 추가한 **검토용 구현**이다. 변경 결과물의 미리보기는 <https://1-portfolio-git-feature-passkey-private-space-dabin4.vercel.app/>이다. 기존 공개 운영 사이트 <https://skt-aleph-01.vercel.app/>에는 아직 이 브랜치를 반영하지 않았다. 심사자 시크릿 창 접근과 실제 계정 간 양방향 격리 기록까지 마쳐야 완주 제출물이다.

## 설치·배포 전제

- Vercel 프로젝트가 이 저장소를 배포해야 한다. 정적 `index.html`은 누구나 열리고, `api/gateway.js`는 서버 함수다. 원래 세 카드의 글과 뒤집기 동작은 그대로 뒀다.
- Vercel 미리보기 브랜치의 `SITE_ORIGIN`은 `https://1-portfolio-git-feature-passkey-private-space-dabin4.vercel.app`로 설정한다(끝에 `/` 없음). Upstash for Redis를 `1-portfolio`의 Preview에 연결하면 `KV_REST_API_URL`과 `KV_REST_API_TOKEN`이 자동으로 추가된다. 다른 연동 방식을 쓸 때는 `UPSTASH_REDIS_REST_URL`과 `UPSTASH_REDIS_REST_TOKEN`도 지원한다. 토큰은 **Vercel의 서버 환경 변수에만** 넣고 저장소·페이지·제출문에 적지 않는다. Production에 배포한다면 `SITE_ORIGIN`을 실제 운영 도메인으로 별도로 설정한다.
- 배포 뒤 첫 패스키는 본인 기기에서 등록한다. 계정명을 먼저 다른 사람이 등록하는 것을 현재 막지 못하므로, 최초 등록 전에 배포 공개 범위와 계정 선점 위험을 판단해야 한다. 두 번째 계정은 계정 격리 검사용 가상 계정이다.
- 로컬의 `npm test`는 Node.js 22 이상에서 돌아간다. 실제 Redis 서비스와 휴대폰·보안 키 패스키 창은 이 자동 검사에 포함되지 않는다.
- `SITE_ORIGIN`이나 저장소 값이 없으면 비공개 API가 **503**을 내며, 공개 소개는 계속 열린다. 이 상태에서 등록을 시도해도 저장되지 않는다.

## 인증 구현 설명서

### ① 무엇으로 붙였나

브라우저 WebAuthn API와 Node.js `node:crypto`를 사용해 **직접 구현**했다. 등록 질문·로그인 질문·세션·공개키·가상 자료는 영속 Redis REST 저장소에 저장한다. `tests/evidence.json`의 `storedPublicKeyJWK`는 테스트 과정에서 서버 저장소 모형에 실제 저장한 `kty`, `crv`, `x`, `y` 공개키 좌표다. 비밀번호가 아니다. 등록 요청 본문은 `ceremony`, `credential.id`, `response.clientDataJSON`, `response.attestationObject`로 구성되고 개인키 필드가 없다. 실제 기기에서는 개인키로 서명하지만 개인키 자체를 API에 전송하지 않는다. 자동 검사에서만 테스트 프로세스가 임시 개인키를 만든다. **실기기 저장 위치**: `sample_a`의 첫 키 `노트북`은 Google 비밀번호 관리자, 둘째 키 `Windows Hello`는 Windows 장치에 저장했다. 첫 키를 서버에서 삭제하고 Windows Hello로 재로그인한 뒤 Google 비밀번호 관리자에 `Google 백업` 키를 추가했다. 별도 가상 계정 `sample_b`의 `노트북` 키도 Google 비밀번호 관리자에 등록했다. 공개키 원문은 테스트 저장소 모형에서만 확인했으며 운영 Redis의 공개키 덤프는 아직 남기지 못했다.

### ② 왜 그걸 골랐나

원본이 단일 정적 HTML이라 공개 페이지의 디자인을 유지하며 서버 API를 추가할 수 있고, WebAuthn은 비밀번호 입력 없이 매번 새 질문에 대한 서명을 공개키로 확인할 수 있다. 패스키는 ES256과 `fmt: none`만 처리한다. 정식 서비스라면 검증된 WebAuthn 라이브러리와 보안 검토가 더 적합하다.

### ③ 어디를 어떻게 고쳤나

| 흐름 | 코드 | 서버 판단 |
| --- | --- | --- |
| 등록 | `index.html`의 등록 폼 → `passkey.js` `register()` → `api/gateway.js`의 `register-options`/`register-verify` → `lib/webauthn.mjs` | 난수 질문을 120초 보관, `GETDEL`로 1회 소진, 출처·RP·사용자 확인 후 `lib/redis.mjs`에서 공개키·이름·등록 시각 저장 |
| 로그인 | `passkey.js` `login()` → `login-options`/`login-verify` | 새 질문과 저장 공개키로 서명 검증, 성공 시 무작위 세션 쿠키 발급 |
| 로그아웃 | `passkey.js` 버튼 → `logout` | 서버 세션 삭제·브라우저 쿠키 만료 |
| 비공개 조회 | `passkey.js` `refresh()` → `GET /api/gateway?view=notes` | 서버 세션으로 계정을 정하고 해당 계정의 자료만 조회; `account`가 다른 계정이면 403, 임의 `owner` 값은 소유자를 바꾸지 못함 |
| 키 관리 | `me`와 `passkey` 분기 | 이름·등록일 목록, 소유권 검사, 마지막 키 삭제 409 |

처음 받은 `index.html`과 `passkey.js`에는 메모 **본문**이 없다. 메모 세 건은 등록 시 계정별로 서버 저장소에 만들어지고 인증 성공 뒤에만 내려온다. 세션 원문은 `HttpOnly; Secure; SameSite=Strict` 쿠키로 전송하고 서버에는 해시만 보관한다. 개발용 `localhost`에서만 `Secure`를 생략한다.

### ④ 안 열리는 것을 확인한 기록

`npm test`는 **합성 P-256 키와 Redis 모형**으로 아래 HTTP 요청·응답을 확인했다. `tests/evidence.json`에는 등록 질문·로그인 질문의 서로 다른 앞자리, 저장된 공개키, 결과 코드와 자료 건수가 있다. `ceremony`, credential ID, 세션 쿠키의 원문은 제출하지 않는다.

**실제 Preview 화면 확인(2026-09-25, 화면 관찰)**: 로그인 전 `GET /api/gateway?view=me`에서 `{ "handle": null }` 표시; Google 비밀번호 관리자에 `sample_a`의 `노트북` 등록 후 패스키 로그인하여 가상 메모 3건과 키 이름·날짜 표시. 두 번째 등록 창 취소 뒤 목록에 새 키가 없고 취소 안내 표시. Windows Hello에 같은 계정의 두 번째 키를 등록하여 목록에 2건과 날짜 표시. 서버 목록에서 첫 키 `노트북` 삭제 후 1건만 표시; 로그아웃 시 가상 메모가 화면에서 사라지고 남은 Windows Hello로 로그인 후 다시 3건 표시. `Google 백업` 키를 추가해 `sample_a`에 다시 키 2개를 마련했다. 별도 계정 `sample_b`의 `노트북` 키를 등록하고 로그인하여 `sample_b` 메모 3건을 확인했다. 세션 없는 탭에서 `notes`를 요청하니 `패스키로 로그인한 뒤 볼 수 있습니다.`가 표시됐고, `sample_b` 로그인 상태의 같은 탭에서 `?view=notes&account=sample_a`를 요청하니 `다른 계정의 자료는 볼 수 없습니다.`가 표시됐다. 전자는 코드상 401, 후자는 403 분기이며 **화면에는 HTTP 상태 코드가 표시되지 않아 직접 계측한 것은 아니다**. 이어서 `sample_a` 페이지의 개발자 도구 Console에서 `fetch('/api/gateway?view=notes&account=sample_b')`를 실행했고, Network 오류와 `response.status`가 모두 **403 Forbidden**이었다. 이는 반대 방향의 실제 HTTP 상태 코드 확인이다. 개인 이메일이 보이는 인증기 선택 창은 제출 증거에 넣지 않는다. **삭제한 키로 서버 로그인 거절과 질문 재사용의 실서비스 HTTP 요청·응답은 아직 따로 수집하지 않았다.**

| 검사 | 통과 요청 → 응답 | 거절 요청 → 응답 |
| --- | --- | --- |
| 로그인 없이 열기 | 세션을 가진 `GET /api/gateway?view=notes` → **200**, 3건 | 쿠키 없는 동일 GET → **401**; HTML 응답에는 메모 본문 없음 |
| 남의 패스키·자료 | alpha 패스키로 alpha 자료 → **200**, beta도 자기 자료 → **200** | alpha 로그인 질문에 beta 패스키, beta 질문에 alpha 패스키 → 각각 **403**. alpha에서 `?view=notes&account=beta`, beta에서 `account=alpha` → 각각 **403** |
| 이미 쓴 질문 | 새 `ceremony`와 올바른 서명 → **200** | 같은 `ceremony`·서명 재전송 → **403**, 일부러 바꾼 서명 → **403** |
| 삭제 뒤 로그인 | alpha에 2개 등록 → 첫 키 삭제 **200**, 남은 키 로그인 **200** | 삭제한 키 로그인 **403**, 마지막 키 삭제 **409** |

격리 전후 자료 건수는 alpha **3→3**, beta **3→3**. `?view=notes&owner=beta`를 alpha 세션으로 보내도 응답 `handle`은 **alpha**, 반대 방향도 **beta**였다. 로그아웃 전 쿠키 `[가림]`으로 로그아웃 후 자료 요청은 **401**. 등록 창 취소에 해당하는 질문을 검증하지 않으면 계정 저장이 없어서 로그인 질문 요청은 **403**. 거절 코드 위치는 `api/gateway.js`의 `login-verify`에서 패스키 소유자 확인, `notes`에서 세션 계정 비교, `lib/redis.mjs`의 소유권 삭제 조건이다.

### ⑤ AI와 나

AI가 공개 페이지에 잠긴 영역과 서버 흐름, 합성 키 테스트, 설명서 초안을 작성했다. 사용자는 과제용 가상 계정명, Upstash Free와 Preview 연결, Google 비밀번호 관리자 및 Windows Hello의 사용을 직접 선택하고 실제 화면을 확인했다. 첫 키를 Windows Hello에 저장하라는 AI 제안과 달리 Google 비밀번호 관리자를 먼저 선택했다.

### ⑥ 아직 못 막은 것

**최초 계정명 선점**을 막는 신뢰할 만한 소유자 등록 절차가 없다. 복구할 기기를 모두 잃어버렸을 때 계정을 되찾는 절차도 없다. 로그인 요청 횟수 제한, 운영 Redis 장애·백업, WebAuthn 직접 구현의 외부 보안 검토가 필요하다. 마지막 패스키 삭제는 막지만 실제 인증기 외부에서 모든 키가 사라지는 경우는 막지 못한다.

## 짧은 확인 방법 · 4줄

1. 어디로: 변경 미리보기 <https://1-portfolio-git-feature-passkey-private-space-dabin4.vercel.app/> (심사자 시크릿 창 접근은 별도 확인 필요). 운영 사이트 <https://skt-aleph-01.vercel.app/>은 기존 공개판.
2. 세 단계: 공개 소개 보기 → 본인 테스트 계정으로 패스키 로그인 → 가상 메모 세 건 보기(심사자는 잠긴 자리를 열 필요 없음).
3. 통과 모습: 공개 카드 세 장은 누구나 보고, 메모 본문과 패스키 이름·등록일은 로그인한 계정에만 보인다.
4. 안 될 때: 등록 취소 안내, 미인증 **401**, 남의 계정 **403**, 마지막 키 삭제 **409**, 설정 누락 **503**이 보인다.

## AI와 내 판단 · 3줄

1. AI에게 맡긴 일: 원본 카드 보존, 패스키 API/UI 작성, 합성 키와 요청·응답 자동 검사.
2. 내가 직접 판단한 일: 가상 계정명 `sample_a`·`sample_b`, Upstash Free, Google 비밀번호 관리자와 Windows Hello에 키 저장, 첫 키 삭제 뒤 재로그인 및 백업 키 복원.
3. AI 제안을 따르지 않은 일: 첫 키에 Windows Hello를 권한 제안 대신 Google 비밀번호 관리자를 골랐다.

## 완주 체크리스트

| 항목 | 상태 |
| --- | --- |
| 과제 1 공개 카드와 동작 유지, 별도 비공개 경계 | Preview 공개 카드와 비공개 경계를 실제 화면에서 확인; 시크릿 창 미검증 |
| 비공개 가상 항목 3건, 미인증 401/HTML 미노출 | 실제 로그인 뒤 3건과 로그아웃 뒤 화면 비노출 확인; 401/HTML 응답은 합성 테스트 |
| 등록·로그인 질문 매번 새 값, 1회 소진, 서명 성공/실패 | 합성 테스트 통과 |
| 공개키 저장, 이름·등록일 목록, 취소 시 미저장 | 실제 등록/키 목록/취소 화면 확인; 운영 Redis의 공개키 값 별도 수집 필요 |
| 계정 2개·한 계정 키 2개·삭제 후 로그인·양방향 격리 | 실제 `sample_a`의 2키 등록·1키 삭제·남은 키 로그인·백업 키 복원과 `sample_b`의 등록·로그인 확인; `sample_b` → `sample_a` 자료 차단 응답 본문 관찰, `sample_a` → `sample_b` 실제 HTTP 403 확인 |
| 세션 무효화, 비밀번호 칸 없음, 실제 개인정보·비밀값 없음 | 코드 검사/합성 테스트 통과; 내용은 과제용 가상 자료 |
| 공개 HTTPS 결과물·소스 URL 무로그인 확인 | 저장소는 공개 상태; 변경 결과물 배포와 시크릿 창 검사는 미완료 |

남은 작업: 양쪽 자료 건수 유지와 `sample_b` → `sample_a` HTTP 상태 코드 확인, 질문 재사용/삭제 키 거절의 운영 응답, 시크릿 창 공개 접근 및 운영 사이트 반영 여부 결정. 화면 캡처에는 이메일·세션·토큰·PIN을 포함하지 않는다.
