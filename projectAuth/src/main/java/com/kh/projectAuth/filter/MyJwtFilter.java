package com.kh.projectAuth.filter;

import com.kh.projectAuth.member.MemberDto;
import com.kh.projectAuth.security.MyJwtUtil;
import com.kh.projectAuth.security.MyUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

@RequiredArgsConstructor
public class MyJwtFilter extends OncePerRequestFilter {

    private final MyJwtUtil myJwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        
        //신분증 검사 -> 인증이나 인가 가능한지??
        MemberDto dto = new MemberDto();

        String accessToken = null;

        if(request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    accessToken = cookie.getValue();
                    break;
                }
            }

        }
        
        if(myJwtUtil.isExpired(accessToken)) {
            System.out.println("토큰 만료 ㅇㅇ");
            filterChain.doFilter(request,response);
            return;
        }
        
        String userId = myJwtUtil.getUserId(accessToken);
        String userNick = myJwtUtil.getUserNick(accessToken);
        String userRole = myJwtUtil.getUserRole(accessToken);

        dto.loginAuth(userId, userNick, userRole);

        MyUserDetails principal = new MyUserDetails(dto);
        String credentials = null;
        Collection authorities = principal.getAuthorities();

        Authentication authToken = new UsernamePasswordAuthenticationToken(principal, credentials, authorities);

        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }

}
