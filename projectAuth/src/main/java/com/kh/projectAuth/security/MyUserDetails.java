package com.kh.projectAuth.security;

import com.kh.projectAuth.member.MemberDto;
import com.kh.projectAuth.member.MemberEntity;
import com.kh.projectAuth.role.RoleEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.cglib.core.Local;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class MyUserDetails implements UserDetails {

    private final MemberDto dto;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return dto.getUserPwd();
    }

    @Override
    public String getUsername() {
        return dto.getUserId();
    }

    public String getUserNick() {
        return dto.getUserNick();
    }

    public String getUserRoleName() {
        return dto.getRoleName();
    }

    public String getUserDepartmentName() {
        return dto.getDepartmentName();
    }

    public LocalDateTime getUserCreatedAt() {
        return dto.getCreatedAt();
    }

    public String getUserCompanyToken() {
        return dto.getCompanyToken();
    }



}
