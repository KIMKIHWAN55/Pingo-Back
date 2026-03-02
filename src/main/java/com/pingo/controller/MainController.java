package com.pingo.controller;

import com.pingo.service.mainService.MainService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController // @Controller 대신 @RestController 사용 (JSON 반환)
@RequiredArgsConstructor
public class MainController {

    private final MainService mainService;

    // 메인 페이지 - 주변 유저 추천 리스트 조회
    @GetMapping("/user/nearby")
    public ResponseEntity<?> getNearbyUsers(@RequestParam("userNo") String userNo,
                                            @RequestParam("distanceKm") int distanceKm) {
        log.info("주변 유저 조회 요청: userNo={}, distance={}km", userNo, distanceKm);
        return mainService.getNearbyUsers(userNo, distanceKm);
    }
}