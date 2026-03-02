package com.pingo.controller;

import com.pingo.service.keywordServices.KeywordService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController // 💡 팁: 데이터를 JSON으로 반환하는 API 서버이므로 @Controller 대신 @RestController가 더 적합합니다!
public class KeywordController {

    private final KeywordService keywordService;

    // [1] 메인 키워드 페이지 - 1, 2차 키워드 카테고리 그룹 조회
    @GetMapping("/keyword")
    public ResponseEntity<?> selectKeywordListFor2ndCategory() {
        log.info("메인 키워드 그룹 조회 요청");
        return keywordService.selectKeywordListFor2ndCategory();
    }

    // [2] 메인 키워드 페이지 - 선택한 키워드 기반 유저 추천 (반경 10km)
    @GetMapping("/recommend")
    public ResponseEntity<?> recommendBasedOnKeywords(
            @RequestParam("userNo") String userNo,
            @RequestParam("sKwId") String sKwId) {

        log.info("키워드 기반 추천 요청 - userNo: {}, 선택한 키워드: {}", userNo, sKwId);
        int distanceKm = 10; // 기본 반경 10km 설정

        return keywordService.recommendBasedOnKeywords(userNo, sKwId, distanceKm);
    }

    // [3] 회원가입 시 3차 키워드 목록 조회
    @GetMapping("/signup/keyword")
    public ResponseEntity<?> select3ndKeywordForSignup() {
        log.info("회원가입 페이지 3차 키워드 목록 조회 요청");
        return keywordService.select3ndKeywordForSignup();
    }
}