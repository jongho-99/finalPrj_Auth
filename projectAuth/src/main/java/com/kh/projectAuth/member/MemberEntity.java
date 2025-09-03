package com.kh.projectAuth.member;

import com.kh.projectAuth.department.DepartmentEntity;
import com.kh.projectAuth.role.RoleEntity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;

@Entity
@Table(name = "MEMBER")
@Getter
@ToString
public class MemberEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long no;

    @Column(nullable = false, length = 50)
    private String userId;

    @Column(nullable = false, length = 100)
    private String userPwd;

    @Column(nullable = false, length = 50)
    private String userNick;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="roleNo", nullable = false)
    private RoleEntity role;

    //부서코드
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="departmentNo", nullable = false)
    private DepartmentEntity department;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @Column(nullable = false)
    private String delYn;

    //업체 고유토큰
    @Column(nullable = false)
    private String companyToken;



    public MemberEntity() {
        delYn = "N";
        createdAt = LocalDateTime.now();
    }

    public static MemberEntity from(MemberDto dto, DepartmentEntity dEntity, RoleEntity rEntity) {

        MemberEntity entity = new MemberEntity();


        //Bcrpt 암호화를 위한 객체생성
        BCryptPasswordEncoder bc = new BCryptPasswordEncoder();

        entity.userId = dto.getUserId();
        //Bcrpt 클래스의 encode 메서드를 통해서 입력받은 dto 객체에서 비밀번호만 암호화 하면서
        //JPA 형식에 맞춘 Entity 타입으로 변환
        entity.userPwd = bc.encode(dto.getUserPwd());
        entity.userNick = dto.getUserNick();

        entity.companyToken = dto.getCompanyToken();

        entity.department = dEntity;
        entity.role = rEntity;
        return entity;
    }

}
