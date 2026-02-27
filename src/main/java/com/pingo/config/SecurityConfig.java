package com.pingo.config;

import com.pingo.mapper.MembershipMapper;
import com.pingo.security.jwt.JwtAuthenticationFilter;
import com.pingo.security.jwt.JwtProvider;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {
    private final JwtProvider jwtProvider;
    private final MembershipMapper membershipMapper;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. CORS 설정 활성화 (이 부분이 없어서 문제였습니다!)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                .csrf(csrf -> csrf.disable()) // CSRF 비활성화

                // 토큰 필터 등 기존 설정 유지
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider, membershipMapper), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/permit/**").permitAll()
                        .requestMatchers("/auto-signin").authenticated()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    // 2. CORS 허용 규칙을 정의하는 Bean 추가
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 프론트엔드 주소 허용 (S3 버킷 주소나 도메인)
        // 테스트를 위해 모든 도메인(*) 허용, 실제 배포 시에는 구체적인 주소(예: http://pingo-front.s3...com)로 바꾸는 것이 좋습니다.
        configuration.setAllowedOriginPatterns(List.of("*"));

        // 허용할 HTTP 메서드 (GET, POST, PUT, DELETE 등)
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        // 허용할 헤더
        configuration.setAllowedHeaders(List.of("*"));

        // 인증 정보(쿠키, 토큰 등) 포함 허용
        configuration.setAllowCredentials(true);

        // 클라이언트가 응답 헤더에서 Authorization(토큰)을 읽을 수 있게 허용
        configuration.addExposedHeader("Authorization");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
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