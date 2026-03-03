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
import org.springframework.web.cors.CorsUtils;

import java.util.Arrays;
import java.util.Collections;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {
    private final JwtProvider jwtProvider;
    private final MembershipMapper membershipMapper;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                // JWT 필터가 /permit/ 경로를 건너뛰도록 로직이 되어있는지 확인이 필요하지만,
                // 일단 시큐리티 설정에서 최우선 순위로 개방합니다.
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider, membershipMapper), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        // 1. 브라우저의 OPTIONS(Preflight) 요청은 무조건 통과
                        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()

                        // 2. 가장 확실한 매칭 규칙 (AntPathRequestMatcher 사용 권장되나 기본문자열로 충분)
                        // context-path 설정이 /pingo라면, 시큐리티는 그 하위인 /permit/만 봅니다.
                        // 혹시 몰라 두 경우를 모두 확실하게 등록합니다.
                        .requestMatchers("/permit/**").permitAll()
                        .requestMatchers("/pingo/permit/**").permitAll()

                        // 3. 정적 리소스나 에러 페이지 허용 (필요시)
                        .requestMatchers("/error").permitAll()

                        // 4. 인증이 필요한 경로
                        .requestMatchers("/auto-signin").authenticated()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    // CORS 상세 설정 Bean
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 프론트엔드 S3 주소 허용
        configuration.setAllowedOrigins(Arrays.asList(
                "http://pingo-front-hosting.s3-website.ap-northeast-2.amazonaws.com",
                "http://localhost:3000",
                "http://localhost:8080"
        ));

        // 모든 HTTP 메서드 허용
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));

        // 모든 헤더 허용
        configuration.setAllowedHeaders(Collections.singletonList("*"));

        // 프론트에서 Authorization 헤더를 읽을 수 있도록 노출
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Authorization-refresh"));

        // 쿠키 및 자격 증명 허용
        configuration.setAllowCredentials(true);

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