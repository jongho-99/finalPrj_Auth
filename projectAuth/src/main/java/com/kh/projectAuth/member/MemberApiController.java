package com.kh.projectAuth.member;

import com.kh.projectAuth.filter.MyUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.graphql.GraphQlProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/member")
public class MemberApiController {

    private final MemberService memberService;

    @PostMapping("join")
    public ResponseEntity<Integer> join(@RequestBody MemberDto dto) {
         int result = memberService.join(dto);

         if(result == 1) {
             return ResponseEntity.ok().body(1);
         } else {
             return ResponseEntity.badRequest().body(0);
         }
    }

    @GetMapping("test")
    public ResponseEntity<String> test() {

        return ResponseEntity.ok().body("성공이에요");
    }


//    @PostMapping("login")
//    public ResponseEntity<MemberEntity> login(@RequestBody MemberDto dto) {
//        MemberEntity entity = memberService.login(dto);
//
//        if(entity == null) {
//            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(entity);
//        } else {
//            return ResponseEntity.ok().body(entity);
//        }
//    }
}
