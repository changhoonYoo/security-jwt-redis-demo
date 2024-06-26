package com.security.demo.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum JwtHeaderUtilEnums {

    GRANT_TYPE("JWT 타입 / Bearer ", "Bearer ");

    private String description;
    private String value;
}
