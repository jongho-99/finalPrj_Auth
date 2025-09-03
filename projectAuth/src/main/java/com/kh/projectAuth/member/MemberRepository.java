package com.kh.projectAuth.member;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

public interface MemberRepository extends JpaRepository<MemberEntity, Long> {

    MemberEntity findByUserIdAndDelYn(String userId, String delYn);
}
