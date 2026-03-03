package com.pingo.config;

import com.pingo.mapper.MembershipMapper;
import com.pingo.security.jwt.JwtAuthenticationFilter;
import com.pingo.security.jwt.JwtProvider;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration; // 추가됨
import org.springframework.web.cors.CorsConfigurationSource; // 추가됨
import org.springframework.web.cors.UrlBasedCorsConfigurationSource; // 추가됨

import java.util.Arrays; // 추가됨
import java.util.Collections; // 추가됨

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {
    private final JwtProvider jwtProvider;
    private final MembershipMapper membershipMapper;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // [1] CORS 설정 활성화 (가장 먼저 설정하는 것이 좋음)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                .csrf(csrf -> csrf.disable()) // CSRF 비활성화

                // 토큰 검사 필터 등록
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider, membershipMapper), UsernamePasswordAuthenticationFilter.class)

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/permit/**").permitAll()
                        .requestMatchers("/auto-signin").authenticated()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    // [2] CORS 허용 규칙을 정의하는 Bean
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 허용할 프론트엔드 도메인 (S3 주소 및 로컬 테스트용)
        configuration.setAllowedOrigins(Arrays.asList(
                "http://pingo-front-hosting.s3-website.ap-northeast-2.amazonaws.com", // S3 주소 (필수)
                "http://localhost:3000", // 로컬 리액트/웹 테스트용 (필요시)
                "http://localhost:8080"  // 로컬 테스트용
        ));

        // 허용할 HTTP 메서드
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));

        // 허용할 헤더 (모두 허용)
        configuration.setAllowedHeaders(Collections.singletonList("*"));

        // [중요] 클라이언트(프론트)에서 헤더를 읽을 수 있게 허용 (JWT 토큰 등)
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Authorization-refresh"));

        // 자격 증명 허용 (쿠키, 인증 헤더 등)
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 모든 경로(/**)에 대해 위 설정을 적용
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}