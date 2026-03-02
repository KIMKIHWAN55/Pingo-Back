package com.pingo.service.userService;

import com.pingo.dto.ResponseDTO;
import com.pingo.entity.keywords.Keyword;
import com.pingo.entity.users.UserImage;
import com.pingo.entity.users.UserKeyword;
import com.pingo.entity.users.UserMypageInfo;
import com.pingo.exception.BusinessException;
import com.pingo.exception.ExceptionCode;
import com.pingo.mapper.UserMapper;
import com.pingo.service.ImageService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.ArrayList; // ArrayList 추가됨
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserService {

    final private ImageService imageService;
    final private UserMapper userMapper;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    // DetailPage를 위한 회원 상세정보 조회
    public ResponseEntity<?> getInfo(String userNo) {
        try {
            // 유저 마이페이지 상세 정보 조회
            UserMypageInfo userMypageInfo = userMapper.getUserMypageInfo(userNo);

            if (userMypageInfo == null) {
                throw new BusinessException(ExceptionCode.USER_INFO_NOT_FOUND);
            }
            log.info("userMypageInfo : " + userMypageInfo);

            // 유저 소개 정보 조회
            String userIntroduction = userMapper.selectUserIntroduction(userNo);
            // 소개글이 없으면 빈 문자열 처리
            userMypageInfo.inputUserIntroduction(userIntroduction != null ? userIntroduction : "");

            log.info("userMypageInfo : " + userMypageInfo);

            return ResponseEntity.ok().body(ResponseDTO.of("1","성공", userMypageInfo));
        } catch (Exception e) {
            log.error("[getInfo 오류] " + e.getMessage());
            throw new BusinessException(ExceptionCode.USER_INFO_NOT_FOUND);
        }
    }

    // 마이페이지를 위한 회원 정보 조회
    @Transactional
    public ResponseEntity<?> getUserInfo(String userNo) {
        try {
            // 유저 마이페이지 상세 정보 조회
            UserMypageInfo userMypageInfo = userMapper.getUserMypageInfo(userNo);

            if (userMypageInfo == null) {
                throw new BusinessException(ExceptionCode.USER_INFO_NOT_FOUND);
            }
            log.info("userMypageInfo : " + userMypageInfo);

            // 유저 소개 정보 조회
            String userIntroduction = userMapper.selectUserIntroduction(userNo);
            userMypageInfo.inputUserIntroduction(userIntroduction != null ? userIntroduction : "");

            // 유저 이미지 조회
            List<UserImage> userImages = userMapper.getUserImages(userNo);
            userMypageInfo.inputUserImage(userImages != null ? userImages : new ArrayList<>());

            // 유저 키워드 정보 조회
            UserKeyword userKeyword = userMapper.getUserKeyword(userNo);
            // ★ 여기서 에러가 났었습니다. 안전한 메서드로 교체함
            Map<String, List<Keyword>> userKeywordList = parseUserKeyword(userKeyword);
            userMypageInfo.inputUserKeyword(userKeywordList);

            log.info("userMypageInfo 최종 반환 : " + userMypageInfo);

            return ResponseEntity.ok().body(ResponseDTO.of("1","성공", userMypageInfo));
        } catch (Exception e) {
            log.error("[getUserInfo 오류] " + e.getMessage());
            throw new BusinessException(ExceptionCode.USER_INFO_NOT_FOUND);
        }
    }

    // ★ [수정됨] 유저 키워드 정보 파싱 (Null Safety 적용)
    private Map<String, List<Keyword>> parseUserKeyword(UserKeyword userKeyword) {
        Map<String, List<Keyword>> resultMap = new HashMap<>();

        // 1. 유저 키워드 데이터가 아예 없는 경우 (신규 회원 등) -> 빈 리스트 반환
        if (userKeyword == null) {
            resultMap.put("my", new ArrayList<>());
            resultMap.put("favorite", new ArrayList<>());
            return resultMap;
        }

        // 2. '나의 키워드'가 null이거나 비어있지 않은지 확인 후 처리
        if (userKeyword.getMy() != null && !userKeyword.getMy().trim().isEmpty()) {
            String[] myKeywords = userKeyword.getMy().split("_");
            List<Keyword> myKeywordList = userMapper.getUserKeywordDetail(myKeywords);
            resultMap.put("my", myKeywordList);
        } else {
            resultMap.put("my", new ArrayList<>());
        }

        // 3. '관심 키워드'가 null이거나 비어있지 않은지 확인 후 처리
        if (userKeyword.getFavorite() != null && !userKeyword.getFavorite().trim().isEmpty()) {
            String[] favoriteKeywords = userKeyword.getFavorite().split("_");
            List<Keyword> favoriteKeywordList = userMapper.getUserKeywordDetail(favoriteKeywords);
            resultMap.put("favorite", favoriteKeywordList);
        } else {
            resultMap.put("favorite", new ArrayList<>());
        }

        return resultMap;
    }

    // 유저 이미지 추가
    public ResponseEntity<?> addUserImage(String userNo, MultipartFile userImageForAdd) {
        // 유저 번호에 해당하는 이미지 호출
        List<UserImage> userImages = userMapper.getUserImages(userNo);
        if (userImages == null) {
            userImages = new ArrayList<>();
        }

        // 리스트에 담긴 사진 수
        int userImagecount = userImages.size();
        log.info("userImagecount : " + userImagecount);

        if (userImagecount < 6 ) {
            // 이미지 서버에 저장하기
            UserImage userImage = new UserImage();
            userImage.makeImageNo();
            String imageNo = userImage.getImageNo();

            // 이미지 경로 호출 후 업로드 로직
            String userImagePath = "users" + File.separator + userNo;
            String imageUrl = imageService.imageUpload(userImageForAdd, userImagePath, imageNo);

            // 이미지 디비에 저장하기
            userMapper.addUserImage(imageNo, imageUrl, "F", userNo);

            return ResponseEntity.ok().body(ResponseDTO.of("1","성공", true));
        } else {
            throw new BusinessException(ExceptionCode.FILE_UPLOAD_FAIL);
        }
    }

    // 유저의 서브이미지를 메인이미지로 설정
    @Transactional
    public ResponseEntity<?> setMainImage(String currentMainImageNo, String newMainImageNo) {
        userMapper.setMainImageAsSubImage(currentMainImageNo);
        userMapper.setSubImageAsMainImage(newMainImageNo);
        return ResponseEntity.ok().body(ResponseDTO.of("1","성공", true));
    }

    // 유저 이미지 삭제
    public ResponseEntity<?> deleteUserImage(String ImageNoForDelete) {
        userMapper.deleteUserImage(ImageNoForDelete);
        return ResponseEntity.ok().body(ResponseDTO.of("1","성공", true));
    }

    // 유저 정보 수정
    @Transactional
    public ResponseEntity<?> updateUserInfo(UserMypageInfo userMypageInfo) {
        try {
            // 1. users 의 이메일 저장
            userMapper.updateUserEmail(userMypageInfo.getUsers().getUserNo(), userMypageInfo.getUsers().getUserEmail());

            // 2. userInfo 저장
            userMapper.updateUserInfo(userMypageInfo.getUserInfo());

            // 3. userKeyword 저장 (Null 방지 처리된 메서드 사용)
            String myKeyword = parseKeywordToString(userMypageInfo.getMyKeywordList());
            String favoriteKeyword = parseKeywordToString(userMypageInfo.getFavoriteKeywordList());
            userMapper.updateUserKeyword(userMypageInfo.getUsers().getUserNo(), myKeyword, favoriteKeyword);

            // 4. 자기 소개 저장
            userMapper.updateUserIntro(userMypageInfo.getUsers().getUserNo(), userMypageInfo.getUserIntroduction());

            return ResponseEntity.ok().body(ResponseDTO.of("1","성공",true));
        }catch (Exception e) {
            log.error(e.getMessage());
            throw new BusinessException(ExceptionCode.UPDATE_USER_INFO_FAIL);
        }
    }

    // ★ [수정됨] 회원 키워드 리스트 문자열로 전환 (Null Safety)
    public String parseKeywordToString(List<Keyword> keywordList) {
        if (keywordList == null || keywordList.isEmpty()) {
            return null; // DB에 null로 저장하거나 ""로 저장 선택 (보통 null)
        }

        StringBuilder keywordStr = new StringBuilder();
        for (Keyword each : keywordList) {
            if (each == null || each.getKwId() == null) continue; // 안전장치

            if (keywordStr.length() > 0) { // 첫 번째가 아니면 앞에 _ 붙임
                keywordStr.append("_");
            }
            keywordStr.append(each.getKwId());
        }
        return keywordStr.toString();
    }

    // 이메일 인증코드 발송
    public ResponseEntity<?> verifyEmail(String userEmail, HttpSession session) throws MessagingException {
        String sessionId = emailService.sendVerificationEmail(userEmail, session);
        return ResponseEntity.ok().body(ResponseDTO.of("1","성공",sessionId));
    }

    // 이메일 인증코드 확인
    public ResponseEntity<?> checkCode(String userEmail, String code, String sessionId) {
        return emailService.checkCode(userEmail, code, sessionId);
    }

    // 유저 아이디 찾기
    public ResponseEntity<?> findUserId(String userName, String userEmail) {
        try {
            String userId = userMapper.findUserId(userName, userEmail);
            return ResponseEntity.ok().body(ResponseDTO.of("1","성공", userId));
        } catch (Exception e) {
            throw new BusinessException(ExceptionCode.FIND_USER_ID_FAIL);
        }
    }

    // 유저 비밀번호 재설정으로 이동
    public ResponseEntity<?> findUserPw(String userId, String userEmail) {
        try {
            String userNo = userMapper.findUserPw(userId, userEmail);
            return ResponseEntity.ok().body(ResponseDTO.of("1","성공", userNo));
        } catch (Exception e) {
            throw new BusinessException(ExceptionCode.FIND_USER_PW_FAIL);
        }
    }

    // 유저 비밀번호 재설정
    public ResponseEntity<?> resetUserPw(String userNo, String userPw) {
        try {
            String encodedPw = passwordEncoder.encode(userPw);
            userMapper.resetUserPw(userNo, encodedPw);
            return ResponseEntity.ok().body(ResponseDTO.of("1","성공", true));
        } catch (Exception e) {
            throw new BusinessException(ExceptionCode.RESET_USER_PW_FAIL);
        }
    }
}