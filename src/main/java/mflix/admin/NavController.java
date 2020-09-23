package mflix.admin;


import mflix.admin.constant.AuthoritiesConstants;
import mflix.admin.utils.SecurityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class NavController {

    @GetMapping("/")
    public String mainnavcontroller() {
        if (SecurityUtils.isCurrentUserInRole(AuthoritiesConstants.ADMIN)) {
            return "redirect:/admin/dashboard";
        } else {
//            if (SecurityUtils.isCurrentUserInRole(AuthoritiesConstants.SALE)) {
//                return "redirect:/employee/sale";
//            } else {
//                if (SecurityUtils.isCurrentUserInRole(AuthoritiesConstants.WAREHOUSE)) {
//                    return "redirect:/employee/warehouse";
//                } else
//                    return "/home/index";
//            }
            return "/login/login";
        }
    }

    @GetMapping("/password")
    public String password() {
        return "common/password";
    }

    @GetMapping("/403")
    public String accessDenied() {
        return "common/403";
    }

    @GetMapping("/profile")
    public String profile() {
        if (SecurityUtils.isCurrentUserInRole(AuthoritiesConstants.ADMIN)) {
            return "redirect:/admin/index";
        } else {
            return "/";
        }
    }
}