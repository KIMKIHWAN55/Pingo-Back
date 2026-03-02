package com.pingo.service.mainService;

import com.pingo.dto.profile.MainProfileResponseDTO;
import com.pingo.mapper.MainMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class MainService {

    private final MainMapper mainMapper;

    public ResponseEntity<?> getNearbyUsers(String userNo, int distanceKm) {
        // 1. DB에서 조건에 맞는 유저 조회
        List<MainProfileResponseDTO> nearbyUsers = mainMapper.selectNearbyUsers(userNo, distanceKm);

        // 2. 나이 계산 및 이미지 리스트 변환
        for (MainProfileResponseDTO user : nearbyUsers) {
            try {
                // 생년월일로 만나이 계산
                user.calculateAge(user.getUserBirth());
                // 쉼표로 구분된 이미지 문자열을 리스트로 변환
                user.getImagesAsList();

                // 거리 포맷팅 (예: "3.5km") - DB에서 숫자로 가져왔다면 여기서 문자열 처리
                if (user.getDistance() != null) {
                    double dist = Double.parseDouble(user.getDistance());
                    user.setDistance(String.format("%.1fkm", dist));
                }
            } catch (Exception e) {
                log.warn("유저 데이터 가공 중 오류 (userNo={}): {}", user.getUserNo(), e.getMessage());
            }
        }

        log.info("조회된 유저 수: {}명", nearbyUsers.size());
        return ResponseEntity.ok(nearbyUsers);
    }
}