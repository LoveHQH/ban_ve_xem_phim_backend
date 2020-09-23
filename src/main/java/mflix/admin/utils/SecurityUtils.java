package mflix.admin.utils;

import mflix.api.models.User;
import mflix.api.daos.UserDao;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public final class SecurityUtils {

    private static UserDao userDao;

    private SecurityUtils(UserDao repo){
        userDao = repo;
    }

//    public static User getCurrentUser(){
//        String username = SecurityContextHolder.getContext().getAuthentication().getName();
//        return userDao.get
//    }

    public static boolean isCurrentUserInRole(String authority) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return Optional.ofNullable(securityContext.getAuthentication())
                .map(authentication -> authentication.getAuthorities().stream()
                        .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(authority)))
                .orElse(false);
    }

}