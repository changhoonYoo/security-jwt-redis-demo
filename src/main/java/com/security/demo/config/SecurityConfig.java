package com.security.demo.config;

import com.security.demo.jwt.JwtAuthenticationFilter;
import com.security.demo.jwt.JwtEntryPoint;
import com.security.demo.service.CustomUserDetailService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtEntryPoint jwtEntryPoint; // 1
    private final JwtAuthenticationFilter jwtAuthenticationFilter; // 1
    /*
     * 1. 시큐리티는 각종 권한 인증 등등 보안과 관련된 것들을 체크하기 위해 여러 필터들이 존재한다.
     *    - JWT 기반 구현을 위해 JwtAuthenticationFilter 클래스 구현
     *    - 시큐리티 필터 과정 중 에러가 발생할 경우 JwtEntryPoint 에서 처리하도록 구현
     */
    private final CustomUserDetailService customUserDetailService; // 2
    /*
     * 2. 시큐리티에서는 UserDetailsService 라는 유저의 정보를 가져오기 위한 클래스를 제공,
     *   - JWT 기반 구현을 위해 커스터마이징
     */

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // 3
    }
    /*
     * 3. 비밀번호 암호화 클래스
     *    사용자가 회원 가입 시 입력한 비밀번호를 BCrypt strong hashing function 을 통해 단방향 암호화
     */

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/h2-console/**", "/favicon.ico"); // 4
    }
    /*
     * 4. h2 관련 url ignore 설정
     */

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()

                .csrf().disable()
                .authorizeRequests() // 5
                .antMatchers("/", "/join/**", "/login", "/health").permitAll()
                .anyRequest().hasRole("USER")

                .and()
                .exceptionHandling()
                .authenticationEntryPoint(jwtEntryPoint)

                .and()
                .logout().disable() // 6
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 6

                .and() // 7
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
    /*
     * 5. antMatchers("/", "/join/**", "/login", "/health").permitAll() 메서드를 통해 표기된 url 권한에 제한 없이 요청 가능
     * 6. JWT 기반으로 로그인 / 로그아웃을 처리할 것이기 때문에 logout() 은 disable, Redis 를 사용하기 때문에 상태를 저장하지 않는 STATELESS 설정
     * 7. 앞에서 만들었던 JwtAuthenticationFilter 를 UsernamePasswordAuthenticationFilter 전에 필터를 추가하겠다는 의미
     */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailService).passwordEncoder(passwordEncoder());
    }
}
