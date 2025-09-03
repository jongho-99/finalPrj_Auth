package com.kh.projectAuth.filter;

import com.kh.projectAuth.member.MemberDto;
import com.kh.projectAuth.member.MemberEntity;
import com.kh.projectAuth.member.MemberRepository;
import com.kh.projectAuth.security.MyUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        MemberEntity find_entity = memberRepository.findByUserIdAndDelYn(username, "N");

        if(find_entity == null) {
            throw new UsernameNotFoundException("user not found");
        }

        //dto로 변환과정에 있어서 안에서 비밀번호 Bcrypt encoding이 진행되어있음
        MemberDto dto = MemberDto.from(find_entity);
        MyUserDetails myUserDetails = new MyUserDetails(dto);
        return myUserDetails;
    }
}