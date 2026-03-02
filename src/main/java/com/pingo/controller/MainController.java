package com.pingo.controller;

import com.pingo.service.mainService.MainService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
public class MainController {

    private final MainService mainService;

    /**
     * 메인 페이지 - 주변 유저 추천 리스트 조회
     * 프론트엔드 파싱 에러(Null 에러) 방지를 위해 공통 응답 포맷으로 감싸서 반환합니다.
     */
    @GetMapping("/user/nearby")
    public ResponseEntity<?> getNearbyUsers(@RequestParam("userNo") String userNo,
                                            @RequestParam("distanceKm") int distanceKm) {
        log.info("주변 유저 조회 요청: userNo={}, distance={}km", userNo, distanceKm);

        // 1. 서비스에서 유저 리스트 가져오기 (이미 5건 조회 확인됨)
        Object userList = mainService.getNearbyUsers(userNo, distanceKm);

        // 2. 프론트엔드가 기대하는 { "status": 1, "message": "...", "data": [...] } 구조 생성
        Map<String, Object> response = new HashMap<>();
        response.put("status", 1);
        response.put("message", "주변 유저 조회 성공");
        response.put("data", userList); // 여기가 핵심: data 키 안에 리스트가 들어가야 함

        return ResponseEntity.ok(response);
    }
}