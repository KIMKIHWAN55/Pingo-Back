package com.pingo.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/pingo/map")
public class MapController {

    // application.yml 파일에서 kakao.rest-api-key 값을 가져옵니다.
    @Value("${kakao.rest-api-key}")
    private String kakaoRestApiKey;

    @GetMapping("/search")
    public ResponseEntity<String> searchAddress(@RequestParam String keyword,
                                                @RequestParam(defaultValue = "1") int page,
                                                @RequestParam(defaultValue = "10") int size) {

        // 1. 카카오 API URL 생성 (UriComponentsBuilder 사용 권장 - 한글 인코딩 자동 처리)
        String url = "https://dapi.kakao.com/v2/local/search/keyword.json";

        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url)
                .queryParam("query", keyword)
                .queryParam("page", page)
                .queryParam("size", size);

        // 2. 헤더 설정 (KakaoAK 인증 키)
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "KakaoAK " + kakaoRestApiKey);

        // 3. 요청 엔티티 생성 (헤더 포함)
        HttpEntity<String> entity = new HttpEntity<>(headers);

        // 4. RestTemplate을 사용하여 카카오 서버에 요청 전송
        RestTemplate restTemplate = new RestTemplate();

        try {
            // 카카오 서버로부터 받은 JSON 응답을 그대로 프론트엔드에 전달 (String.class)
            ResponseEntity<String> response = restTemplate.exchange(
                    builder.toUriString(),
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            return ResponseEntity.ok(response.getBody());

        } catch (Exception e) {
            log.error("카카오 맵 API 호출 중 오류 발생: ", e);
            return ResponseEntity.status(500).body("카카오 검색 API 호출 실패");
        }
    }
}