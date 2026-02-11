![Image](https://github.com/user-attachments/assets/bf67fe15-c1a2-4918-83c8-8b3a0f3d5e13)
# Pingo

Pingo는 위치 기반으로 주변 사용자를 추천하고, 키워드 필터링을 통해 이상형을 찾을 수 있는 소개팅 앱입니다. </br>
이용자가 서로 좋아요를 누르면 매칭되어 채팅할 수 있으며, 연애 팁과 데이트 장소를 공유하는 커뮤니티도 제공하고 있습니다.


## 📌 제작 기간
- 2025년 01월 20일 ~ 2025년 03월 06일

## 📌 기술 스택
- **Frontend**: Flutter
- **Backend**: Java, Spring Boot
- **Database**: Oracle, MongoDB

## 📌 깃허브 주소
- [Frontend Repository](https://github.com/2Shiro/pingo_front)
- [Backend Repository](https://github.com/2Shiro/pingo_back)

## 📌 담당 역할
- **회원가입**: 이메일 인증을 통한 회원가입 기능 구현
- **아이디 / 비밀번호 찾기**: 이메일 인증을 통한 계정 정보 찾는 기능 구현
- **로그인**: JWT 기반 로그인 기능 구현
- **마이페이지**: 내 정보 조회 및 수정 기능 구현

---
![Image](https://github.com/user-attachments/assets/eb6eea15-2e93-40ab-ba69-b5455b39d446)
**🏷️ 회원가입**
- 유저의 기본 정보를 입력받아, 맞춤형 서비스 제공 및 이용을 가능하게 하는 기능

**📌 주요 기능**
- **이메일 인증**
    - 구글 SMTP 를 활용하여 인증코드 발송
    - 인증코드 일치여부 확인

- **주소 정보 활용**
    - 카카오 주소 API를 사용하여 주소 입력

- **프로필 이미지 등록**
    - 이미지를 업로드하여 프로필 등록
 ---
 ![ID PW 찾기](https://github.com/user-attachments/assets/9a1bd3bc-2f52-4b79-84c4-0cbc027d8fc0)
**🏷️ 아이디 / 비밀번호 찾기**
- 이메일 인증을 통해 해당하는 아이디 또는 비밀번호 찾는 기능이 가능하다

**📌 주요 기능**
- **아이디 찾기**
    - 이메일 인증과 이름 정보를 받아서 해당하는 아이디가 있다면 출력된다.

- **비밀번호 찾기**
    - 비밀번호는 암호화가 되어 데이터베이스에 저장되기에 복호화가 불가능하고, 가능하더라도 고객의 정보를 복호화 하는 것은 불법이기에 비밀번호 재설정으로 해결할 수 있다.
---
![Image](https://github.com/user-attachments/assets/b8cf8913-8280-4ebe-884b-9383e62c599d)
**🏷️ 로그인**
- 입력받은 아이디와 비밀번호가 일치하는지 확인하여 로그인 여부를 결정할 수 있다.

**📌 주요 기능**
- 비밀번호는 복호화가 불가능하기에 입력받은 비밀번호를 암호화 한 뒤 데이터베이스에 저장된 암호화 되어 있는 비밀번호와 일치하는지 확인한다.
- 아이디와 비밀번호가 일치한다면 메인페이지로 이동한다.
- 메인페이지에서는 로그인한 유저의 반대 성별에 해당하는 유저들을 조회하여 출력한다.
---
![Pingo 포폴](https://github.com/user-attachments/assets/9d6f1945-7d62-41ff-adf5-6d6aaef2b0e2)
**🏷️ 마이페이지**
- 유저의 정보를 수정할 수 있다.

**📌 주요 기능**
- **사진 변경**
    - 사진을 최대 6장까지 추가할 수 있다.
    - 추가한 이미지는 대표이미지로 설정하거나 삭제가 가능하다

- **프로필 수정**
    - 이메일 인증을 해야만 수정 완료 버튼이 활성화 된다.
---
**🏷️ Spring 서버의 전역 예외처리 로직 구현**
- 서버에서 발생 가능한 예외를 전역적으로 처리하기 위한 예외처리 클래스 구현
- 비즈니스 로직에서 CustomException을 발생시키고, @RestControllerAdvice
를 활용해 예외를 감지하여 적절한 응답 반환
- 예외 코드 및 메시지를 Enum으로 관리하여 유지보수성과 확장성을 높임
---
**📌 자료**

OracleDB 덤프 : [pingoOracleDump.json](https://github.com/user-attachments/files/19244824/pingoOracleDump.json)

몽고DB 덤프 : [pingochat.chatMsg.json](https://github.com/user-attachments/files/19104292/pingochat.chatMsg.json)
