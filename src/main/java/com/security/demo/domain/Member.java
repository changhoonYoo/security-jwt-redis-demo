package com.security.demo.domain;

import com.security.demo.dto.JoinDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    @Column(unique = true)
    private String username;

    @Column(unique = true)
    private String email;

    private String password;

    @Column(unique = true)
    private String nickname;

    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<Authority> authorities = new HashSet<>();

    public static Member ofUser(JoinDto joinDto) {
        Member member = Member.builder()
                .username(UUID.randomUUID().toString())
                .email(joinDto.getEmail())
                .password(joinDto.getPassword())
                .nickname(joinDto.getNickname())
                .build();

        member.addAuthority(Authority.ofUser(member));

        return member;
    }

    public static Member ofAdmin(JoinDto joinDto) {
        Member member = Member.builder()
                .username(UUID.randomUUID().toString())
                .email(joinDto.getEmail())
                .password(joinDto.getPassword())
                .nickname(joinDto.getNickname())
                .build();

        member.addAuthority(Authority.ofAdmin(member));

        return member;
    }

    private void addAuthority(Authority authority) {
        authorities.add(authority);
    }

    public List<String> getRoles() {
        return authorities.stream()
                .map(Authority::getRole)
                .toList();
    }
}
