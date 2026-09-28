package com.example.certmgr.controller;

import com.example.certmgr.entity.UserEntity;
import com.example.certmgr.security.Permissions;
import com.example.certmgr.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Set;

/**
 * 用户管理控制器：用户列表、新增/编辑、删除、启用禁用、重置密码。
 *
 * <p>类级别要求 {@code PERM_USER_VIEW}，写操作（新增/编辑/删除/禁用/重置密码）
 * 进一步要求 {@code PERM_USER_EDIT} / {@code PERM_USER_DELETE}，由方法级注解约束。
 * 管理员(ADMIN)在登录时自动拥有全部权限，因此可正常进入本控制器。</p>
 */
@Controller
@RequiredArgsConstructor
@RequestMapping("/users")
@PreAuthorize("hasAuthority('PERM_USER_VIEW')")
public class UserController {

    /** 用户业务服务 */
    private final UserService userService;

    /**
     * 向所有本控制器视图注入权限元数据，供表单渲染复选框。
     *
     * @return 权限元数据列表
     */
    @ModelAttribute("permissionMeta")
    public List<Permissions.PermissionMeta> permissionMeta() {
        return Permissions.META;
    }

    /**
     * 用户列表页。
     */
    @GetMapping
    public String list(Model model) {
        model.addAttribute("pageTitle", "用户管理");
        model.addAttribute("users", userService.list());
        return "users/list";
    }

    /**
     * 新增用户表单页。
     */
    @GetMapping("/new")
    public String newForm(Model model) {
        model.addAttribute("pageTitle", "新增用户");
        model.addAttribute("user", new UserEntity());
        model.addAttribute("isNew", true);
        // 默认勾选一组合理的普通用户权限（不含用户管理与删除类高危项）
        model.addAttribute("checkedPerms", Permissions.DEFAULT_USER_PERMS);
        return "users/form";
    }

    /**
     * 创建用户。
     */
    @PostMapping
    @PreAuthorize("hasAuthority('PERM_USER_EDIT')")
    public String create(@RequestParam String username,
                         @RequestParam String displayName,
                         @RequestParam String password,
                         @RequestParam String role,
                         @RequestParam(required = false) String permissions,
                         @RequestParam(defaultValue = "true") boolean enabled,
                         RedirectAttributes ra) {
        try {
            userService.create(username, displayName, password, role, permissions, enabled);
            ra.addFlashAttribute("success", "用户已创建");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/users";
    }

    /**
     * 编辑用户表单页。
     */
    @GetMapping("/{id}/edit")
    public String editForm(@PathVariable Long id, Model model) {
        UserEntity user = userService.get(id);
        model.addAttribute("pageTitle", "编辑用户 - " + user.getUsername());
        model.addAttribute("user", user);
        model.addAttribute("isNew", false);
        model.addAttribute("checkedPerms", user.getPermissionSet());
        return "users/form";
    }

    /**
     * 更新用户。
     */
    @PostMapping("/{id}")
    @PreAuthorize("hasAuthority('PERM_USER_EDIT')")
    public String update(@PathVariable Long id,
                         @RequestParam String displayName,
                         @RequestParam(required = false) String password,
                         @RequestParam String role,
                         @RequestParam(required = false) String permissions,
                         @RequestParam(defaultValue = "true") boolean enabled,
                         RedirectAttributes ra,
                         Authentication auth) {
        try {
            userService.update(id, displayName, password, role, permissions, enabled, auth.getName());
            ra.addFlashAttribute("success", "用户已更新");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/users";
    }

    /**
     * 删除用户。
     */
    @PostMapping("/{id}/delete")
    @PreAuthorize("hasAuthority('PERM_USER_DELETE')")
    public String delete(@PathVariable Long id, RedirectAttributes ra, Authentication auth) {
        try {
            userService.delete(id, auth.getName());
            ra.addFlashAttribute("success", "用户已删除");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/users";
    }

    /**
     * 启用/禁用切换。
     */
    @PostMapping("/{id}/toggle")
    @PreAuthorize("hasAuthority('PERM_USER_EDIT')")
    public String toggle(@PathVariable Long id, RedirectAttributes ra, Authentication auth) {
        try {
            userService.toggleEnabled(id, auth.getName());
            ra.addFlashAttribute("success", "用户状态已更新");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/users";
    }

    /**
     * 重置密码。
     */
    @PostMapping("/{id}/reset-password")
    @PreAuthorize("hasAuthority('PERM_USER_EDIT')")
    public String resetPassword(@PathVariable Long id,
                                @RequestParam String newPassword,
                                RedirectAttributes ra) {
        try {
            userService.resetPassword(id, newPassword);
            ra.addFlashAttribute("success", "密码已重置");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/users";
    }
}
