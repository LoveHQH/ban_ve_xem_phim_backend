package mflix.admin.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;


@Controller
public class AdminDashboardController {
    @RequestMapping(value = {"/admin/dashboard","/admin"}, method = RequestMethod.GET)
    public ModelAndView dashboard() {

        ModelAndView modelAndView = new ModelAndView("admin/dashboard/index");

        return modelAndView;
    }
}