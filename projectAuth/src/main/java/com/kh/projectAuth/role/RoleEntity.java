package com.kh.projectAuth.role;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name="ROLE")
@Getter
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long roleNo;

    @Column(nullable = false)
    private String roleName;

}
