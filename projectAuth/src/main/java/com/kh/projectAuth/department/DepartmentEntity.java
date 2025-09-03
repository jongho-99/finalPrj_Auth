package com.kh.projectAuth.department;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name = "DEPARTMENT")
@Getter
public class DepartmentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long departmentNo;

    @Column(nullable = false)
    private String departmentName;


}
