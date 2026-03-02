package com.pingo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.*;
import org.springframework.web.socket.server.support.DefaultHandshakeHandler;

@Configuration
@EnableWebSocketMessageBroker // STOMP를 사용하기 위한 필수 어노테이션
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    /**
     * 메세지 브로커(우체국 역할)를 설정하는 메서드입니다.
     * 클라이언트(프론트엔드)가 어디로 메세지를 보내고, 어디서 메세지를 받을지 경로(Prefix)를 정해줍니다.
     */
    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // 1. 구독(Subscribe) 경로 설정
        // 프론트엔드에서 특정 방의 메세지를 '수신'할 때 사용할 경로의 접두사입니다.
        // 예: 프론트에서 "/topic/msg/방번호"를 구독하고 있으면, 서버가 이 경로로 메세지를 뿌려줍니다.
        config.enableSimpleBroker("/topic");

        // 2. 발행(Publish) 경로 설정
        // 프론트엔드에서 서버로 메세지를 '발송'할 때 사용할 경로의 접두사입니다.
        // 예: 프론트에서 "/pub/msg/방번호"로 메세지를 보내면, 컨트롤러의 @MessageMapping("/msg/{roomId}")가 받습니다.
        config.setApplicationDestinationPrefixes("/pub");
    }

    /**
     * 클라이언트가 웹소켓 서버에 처음 접속하는 '현관문(Endpoint)'을 설정하는 메서드입니다.
     * 이 문을 통과해야 본격적인 통신(STOMP)을 시작할 수 있습니다.
     */
    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws") // 프론트엔드가 접속할 엔드포인트 URL (예: ws://서버IP:포트/ws)
                .setAllowedOriginPatterns("*") // CORS 설정: 현재는 모든 도메인(*)에서의 접속을 허용 (개발용)
                .setHandshakeHandler(new DefaultHandshakeHandler()); // 초기 HTTP 요청을 웹소켓 통신으로 업그레이드 해주는 핸들러
    }
}