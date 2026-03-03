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
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider, membershipMapper), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        // 1. OPTIONS 요청 무조건 허용 (CORS 필수)
                        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()

                        // 2. 로그인/회원가입 경로 허용 (가장 안전한 매칭 방식)
                        // context-path 설정 유무와 관계없이 permit 폴더 하위는 모두 열어둡니다.
                        .requestMatchers("/pingo/permit/**").permitAll()
                        .requestMatchers("/permit/**").permitAll()

                        // 3. 특정 인증 필요 경로
                        .requestMatchers("/auto-signin").authenticated()

                        // 4. 그 외 모든 요청
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