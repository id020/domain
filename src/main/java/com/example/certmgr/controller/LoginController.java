package com.example.certmgr.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 登录页控制器。
 *
 * <p>仅负责 GET 渲染登录页，并把“登录失败 / 已退出”的提示信息带回到页面。
 * 真正的账号密码校验由 Spring Security 的 {@code /login} 处理。</p>
 */
@Controller
public class LoginController {

    /**
     * 展示登录页。
     *
     * @param error  登录失败标记（Spring Security 跳转时携带）
     * @param logout 已退出标记
     * @param model 视图模型
     * @return 登录页视图名
     */
    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error,
                        @RequestParam(required = false) String logout,
                        Model model) {
        model.addAttribute("pageTitle", "登录");
        if (error != null) {
            model.addAttribute("loginError", "用户名或密码错误");
        }
        if (logout != null) {
            model.addAttribute("logoutMsg", "您已安全退出");
        }
        return "login";
    }
}
