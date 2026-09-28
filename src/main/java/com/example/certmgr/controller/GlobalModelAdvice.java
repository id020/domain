package com.example.certmgr.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.util.Collection;

/**
 * 全局模型增强：为所有页面注入当前登录用户信息。
 *
 * <p>通过 {@link ControllerAdvice} 在每个请求进入控制器后、渲染前，
 * 向模型写入 {@code currentUser}（用户名）与 {@code isLoggedIn}（是否已登录），
 * 供顶部导航栏显示“你好，xxx”与“退出”按钮使用。</p>
 */
@ControllerAdvice
public class GlobalModelAdvice {

    /**
     * 向模型注入当前用户状态。
     *
     * @param model 视图模型
     */
    @ModelAttribute
    public void populateUser(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // 已认证且非匿名用户时才视为已登录
        if (auth != null && auth.isAuthenticated()
                && !"anonymousUser".equals(auth.getName())) {
            model.addAttribute("currentUser", auth.getName());
            model.addAttribute("isLoggedIn", true);
            // 解析当前用户角色与权限，供顶部导航按需展示“用户管理”入口
            Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
            boolean isAdmin = authorities.stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
            boolean canManageUsers = isAdmin
                    || authorities.stream().anyMatch(a -> "PERM_USER_VIEW".equals(a.getAuthority()));
            model.addAttribute("isAdmin", isAdmin);
            model.addAttribute("canManageUsers", canManageUsers);
        } else {
            model.addAttribute("currentUser", null);
            model.addAttribute("isLoggedIn", false);
            model.addAttribute("isAdmin", false);
            model.addAttribute("canManageUsers", false);
        }
    }
}
