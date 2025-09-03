package com.kh.projectAuth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kh.projectAuth.member.MemberDto;
import com.kh.projectAuth.security.MyJwtUtil;
import com.kh.projectAuth.security.MyUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import jakarta.servlet.http.Cookie;

import java.io.IOException;
import java.time.LocalDateTime;

@RequiredArgsConstructor
public class MyLoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final MyJwtUtil myJwtUtil;


    //로그인 시도
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        try{
            System.out.println("MyLoginFilter.attemptAuthentication");

            ObjectMapper om = new ObjectMapper();

            //MyLoginFilter에서 브라우저로부터의 로그인 요청에 대해서 dto형태로 받아옴
            MemberDto dto = om.readValue(request.getInputStream(), MemberDto.class);

            System.out.println("dto.getUserId() = " + dto.getUserId());
            System.out.println("dto.getUserPwd() = " + dto.getUserPwd());

            //UsernamePasswordAuthenticationtoken 메서드를 통해서 아이디와 비밀번호를 통한 미인증 토큰 생성
            Authentication authToken = new UsernamePasswordAuthenticationToken(dto.getUserId(), dto.getUserPwd());
            
            
            //실제 인증로직을 수행하는 AuthenticationManager의 authenticate(토큰)을 통해서 인증로직 작업을 반환
            //성공하게되면 아래의 successfulAuthentication()을 호출하게됨 실패하면 unsuccessfulAuthentication() 메서드를 호출
            return authenticationManager.authenticate(authToken);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    //로그인 성공 (성공했으니까 JWT를 생성해서 발급)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {

        System.out.println("MyLoginFilter.successfulAuthentication");

        MyUserDetails userDetails = (MyUserDetails) authResult.getPrincipal();

        String userId = userDetails.getUsername();
        String userNick = userDetails.getUserNick();
        String userRoleName = userDetails.getUserRoleName();
        String userDepartmentName = userDetails.getUserDepartmentName();

        LocalDateTime userCreatedAt = userDetails.getUserCreatedAt();

        String jwt = myJwtUtil.createJwt(userId, userNick, userRoleName);
        
        //js측에서 따로 Authorization 헤더 기반 인증을 유지하고 싶다면 남겨놔두 댐 + 그리고 Bearer 빠짐 JSON이 알아보려고 달았던거임
//        response.addHeader("Authorization", "Bearer " + jwt);

        // 쿠키로 JWT 전달 (HttpOnly + Secure 옵션 추가 가능)
        
        Cookie cookie = new Cookie("accessToken", jwt);
        cookie.setHttpOnly(true);              // JS에서 접근 불가
        cookie.setSecure(false);                // HTTPS에서만 전송 (개발 시 false로 가능)
        cookie.setPath("/");                   // 전체 경로에서 접근 가능
        cookie.setMaxAge(30 * 60);             // 15분 유지 (초 단위)
        response.addCookie(cookie);
    }

    //로그인 실패
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException
    failed) throws IOException {
        System.out.println("MyLoginFilter.unsuccessfulAuthentication");
        response.setStatus(HttpServletResponse.SC_CONFLICT); // 409
        response.getWriter().write("Login failed"); // 메시지도 직접 작성 가능
    }

}
