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
                // 1. CORS 설정 연결
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 2. CSRF 비활성화 (Stateless API이므로)
                .csrf(csrf -> csrf.disable())

                // 3. JWT 필터 설정
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider, membershipMapper), UsernamePasswordAuthenticationFilter.class)

                // 4. 세션 정책: 사용 안 함
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 5. 요청 권한 설정
                .authorizeHttpRequests(auth -> auth
                        // 브라우저의 Preflight(OPTIONS) 요청은 무조건 허용
                        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()

                        // /pingo/permit/이나 /permit/으로 시작하는 경로는 로그인 없이 허용
                        .requestMatchers("/**/permit/**", "/permit/**").permitAll()

                        // 자동 로그인은 필터에서 걸러지므로 인증 필요로 설정
                        .requestMatchers("/auto-signin").authenticated()

                        // 나머지는 모두 인증 필요
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