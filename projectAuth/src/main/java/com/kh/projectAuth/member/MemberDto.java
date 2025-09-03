package com.kh.projectAuth.member;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;

@Getter
public class MemberDto {

    private Long no;
    private String userId;
    private String userPwd;
    private String userNick;

    private String companyToken;

    private Long roleNo;
    private Long departmentNo;

    private String roleName;
    private String departmentName;

    private String delYn;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime updatedAt;

    public static MemberDto from(MemberEntity entity) {
        MemberDto dto = new MemberDto();

        dto.no = entity.getNo();
        dto.userId = entity.getUserId();
        dto.userPwd = entity.getUserPwd();
        dto.userNick = entity.getUserPwd();

        dto.companyToken = entity.getCompanyToken();;

        dto.roleNo = entity.getNo();
        dto.departmentNo = entity.getNo();

        dto.roleName = entity.getRole().getRoleName();
        dto.departmentName = entity.getDepartment().getDepartmentName();

        return dto;
    }


}
