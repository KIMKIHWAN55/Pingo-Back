package com.pingo.dto;

import com.pingo.dto.swipe.SwipeRequest;
import com.pingo.entity.swipe.Swipe;
import org.springframework.stereotype.Component;

@Component
public class TransferDtoToEntity {

    public Swipe swipeDtoToEntity(SwipeRequest swipeRequest) {
        // Builder 대신, 이미 만들어두신 안전한 생성자를 사용하세요!
        // 내부에서 자동으로 createSwipeNo()가 호출되어 PK가 생성됩니다.
        return new Swipe(swipeRequest);
    }
}