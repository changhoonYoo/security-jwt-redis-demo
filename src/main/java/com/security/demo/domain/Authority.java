package com.security.demo.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Authority implements GrantedAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "authority_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    private String role;

    public static Authority ofUser(Member member) {
        return Authority.builder()
                .role("ROLE_USER")
                .member(member)
                .build();
    }

    public static Authority ofAdmin(Member member) {
        return Authority.builder()
                .role("ROLE_ADMIN")
                .member(member)
                .build();
    }

    @Override
    public String getAuthority() {
        return role;
    }
}
