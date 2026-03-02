package com.pingo.mapper;

import com.pingo.dto.profile.MainProfileResponseDTO;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface MainMapper {
    // 주변 유저 조회 (나 제외, 이미 스와이프한 사람 제외, 차단 제외)
    List<MainProfileResponseDTO> selectNearbyUsers(@Param("userNo") String userNo,
                                                   @Param("distanceKm") int distanceKm);
}