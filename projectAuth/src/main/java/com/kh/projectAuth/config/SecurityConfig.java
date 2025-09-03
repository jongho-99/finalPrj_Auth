package com.kh.projectAuth.config;

import com.kh.projectAuth.filter.MyLoginFilter;
import com.kh.projectAuth.filter.MyUserDetailsService;
import com.kh.projectAuth.security.MyJwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final MyUserDetailsService myUserDetailsService;
    private final MyJwtUtil myJwtUtil;


    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disable
        http.csrf(auth -> auth.disable());
        //form 로그인 방식 disable
        http.formLogin(auth -> auth.disable());
        //http basic 인증 방식 disable
        http.httpBasic(auth -> auth.disable());
        //세션 설정
        http.sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        //경로별 인가 작업
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/member/login", "/", "/api/member/join").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated());
        //필터 갈아끼우기
        AuthenticationManager authenticationManager = authenticationManager(authenticationConfiguration);

        //MyLoginFilter를 SecurityFilterChain에 등록해주는 작업
        MyLoginFilter myLoginFilter = new MyLoginFilter(authenticationManager, myJwtUtil);
        myLoginFilter.setFilterProcessesUrl("/api/member/login");
        http.addFilterAt(myLoginFilter, UsernamePasswordAuthenticationFilter.class);

        //CORS
        http.cors(
                corsConfigurer -> corsConfigurer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration conf = new CorsConfiguration();
                        conf.addAllowedOrigin("*");
                        conf.addAllowedMethod("*");

                        //클라가 서버한테 헤더에 담는 내용에 대해서 커스터마이징해서 값을 담아서 요청가능
                        conf.addAllowedHeader("*");

                        //응답헤더보면 여러가지있음 (포스트맨 참조) 추가하면 모든 헤더값 출력
                        conf.addExposedHeader("*");
                        return conf;
                    }
                })
        );


        return http.build();
    }
}
