package com.example.springsecurity.security;

import com.google.common.collect.Sets;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Set;

import static com.example.springsecurity.security.ApplicationUserPermission.COURSE_READ;
import static com.example.springsecurity.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.springsecurity.security.ApplicationUserPermission.STRUDENT_READ;
import static com.example.springsecurity.security.ApplicationUserPermission.STRUDENT_WRITE;

@RequiredArgsConstructor
@Getter
public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STRUDENT_READ, STRUDENT_WRITE)),
    ADMIN_TRAINEE(Sets.newHashSet(COURSE_READ, STRUDENT_READ));

    private final Set<ApplicationUserPermission> permissions;
}
