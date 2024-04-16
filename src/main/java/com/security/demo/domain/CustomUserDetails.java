package com.security.demo.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CustomUserDetails implements UserDetails {

    /*
     * CustomUserDeatails 클래스를 따로 만든 이유는 Redis 에 캐싱할 때, 기본적인 UserDetails 로 저장할 경우 역직렬화가 안되는 이슈가 있기 때문에,
     * 인증과 권한체크를 위한 필드들을 설정하고, 저장할 때 관련없는 나머지 필드는 @JsonIgnore 처리
     */

    private String username;
    private String password;
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    public static UserDetails of(Member member) {
        return CustomUserDetails.builder()
                .username(member.getUsername())
                .password(member.getPassword())
                .roles(member.getRoles())
                .build();
    }

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
