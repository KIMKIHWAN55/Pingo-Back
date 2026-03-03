package com.pingo.security.jwt;

import com.pingo.entity.membership.UserMembership;
import com.pingo.entity.users.Users;
import com.pingo.mapper.MembershipMapper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtProvider jwtProvider;
    private final MembershipMapper membershipMapper;

    private static final String AUTH_HEADER = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String uri = request.getRequestURI();

        // [1] 안전장치: 인증이 필요 없는 경로(로그인, 웹소켓, 이미지, 정적파일)는 필터 로직을 태우지 않고 즉시 통과
        // 이 코드가 있어야 S3 웹 접속 시 500 에러나 403 에러가 발생하지 않습니다.
        if (uri.contains("/permit/") || uri.contains("/ws") || uri.contains("/images/") || uri.contains("/static/") || uri.contains("/css/") || uri.contains("/js/")) {
            filterChain.doFilter(request, response);
            return;
        }

        // [2] 경로 추출 로직 (안전하게 수정됨)
        // uri가 "/pingo/auto-signin" 일 때 "/auto-signin"만 추출하기 위함
        String path = "";
        int lastSlashIndex = uri.lastIndexOf("/");
        if (lastSlashIndex != -1) {
            path = uri.substring(lastSlashIndex);
        }

        // 토큰 추출
        String token = request.getHeader(AUTH_HEADER);

        // 토큰이 있는 경우만 검증 로직 수행
        if (token != null && !token.isEmpty()) {
            try {
                // 토큰 유효성 검사
                jwtProvider.validateToken(token);

                // [3] 자동 로그인 로직
                if (path.equals("/auto-signin")) {
                    log.info("doFilterInternal...자동 로그인 체크 감지");

                    Claims claims = jwtProvider.getClaims(token);
                    String userNo = (String) claims.get("userNo");
                    String userRole = (String) claims.get("userRole");

                    Optional<UserMembership> userMembership = membershipMapper.selectUserMembership(userNo);

                    // JSON 응답 설정
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");

                    String jsonResponse;

                    // [수정 포인트] expDate가 있을 때와 없을 때를 명확히 분기하여 jsonResponse 생성
                    if (userMembership.isPresent()) {
                        LocalDateTime expDate = userMembership.get().getExpDate();
                        // expDate 변수를 여기서 바로 사용
                        jsonResponse = String.format(
                                "{ \"data\": { \"message\": \"자동 로그인 성공\", \"userNo\": \"%s\", \"userRole\": \"%s\", \"expDate\": \"%s\" } }",
                                userNo, userRole, expDate.toString()
                        );
                    } else {
                        // expDate가 없는 경우
                        jsonResponse = String.format(
                                "{ \"data\": { \"message\": \"자동 로그인 성공\", \"userNo\": \"%s\", \"userRole\": \"%s\" } }",
                                userNo, userRole
                        );
                    }

                    // 응답 후 종료
                    response.getWriter().write(jsonResponse);
                    return;
                }

                // ---------------------------------------------------------
                // [4] 리프레쉬 토큰 로직 (기존 기능 유지)
                // ---------------------------------------------------------
                if (path.equals("/refresh")) {
                    log.info("doFilterInternal...리프레쉬 토큰 감지");

                    Claims claims = jwtProvider.getClaims(token);
                    String userNo = (String) claims.get("userNo");
                    String userRole = (String) claims.get("userRole");

                    Users users = Users.builder()
                            .userNo(userNo)
                            .userRole(userRole)
                            .build();

                    String accessToken = jwtProvider.createToken(users, 1);

                    response.setStatus(HttpServletResponse.SC_CREATED);
                    response.getWriter().println(accessToken);
                    return;
                }

                // [5] 시큐리티 인증 처리 (일반 요청일 때)
                Authentication authentication = jwtProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("doFilterInternal...시큐리티 인증 객체 저장 완료: {}", path);

            } catch (JwtMyException e) {
                // 토큰 에러 발생 시 응답 처리
                e.sendResponseError(response);
                return;
            }
        }

        // 다음 필터로 진행
        filterChain.doFilter(request, response);
    }
}