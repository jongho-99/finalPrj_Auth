package com.kh.projectAuth.member;

import com.kh.projectAuth.department.DepartmentEntity;
import com.kh.projectAuth.department.DepartmentRepository;
import com.kh.projectAuth.role.RoleEntity;
import com.kh.projectAuth.role.RoleRepository;
import com.kh.projectAuth.security.MyUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;

@Service
@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final DepartmentRepository departmentRepository;
    private final RoleRepository roleRepository;

//    @Override
//    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
//
//        //1. repo에 가서 Entity 추출해오는넘
//        MemberEntity res_entity = memberRepository.findByUserIdAndDelYn(name, "N");
//
//        //예외처리
//        if(res_entity == null) throw new UsernameNotFoundException("User not found: " + name);
//
//        MemberDto dto = MemberDto.from(res_entity);
//
//        //2. 추출된 새끼로 MyUserDetails 객체 생성 후 반환
//        return new MyUserDetails(dto);
//    }

    public int join(MemberDto dto) {
        try{
            DepartmentEntity dEntity = departmentRepository.findById(dto.getDepartmentNo()).get();
            RoleEntity rEntity = roleRepository.findById(dto.getRoleNo()).get();

            // 영속성 컨텍스트에 등록되기 직전 dto로 받아온 회원가입 정보에 대해서
            // entity로의 변환과정에 사용되는 from() 메서드 내에서
            // BCrypt를 통해서 비밀번호 암호화를 거치고 DB에 저장
            MemberEntity entity = MemberEntity.from(dto, dEntity, rEntity);

            System.out.println("entity = " + entity);
            memberRepository.save(entity);

        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        return 1;

    }
}
