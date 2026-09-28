package com.example.certmgr.service;

import com.example.certmgr.entity.UserEntity;
import com.example.certmgr.repository.UserRepository;
import com.example.certmgr.security.Permissions;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 用户业务服务：负责用户的增删改查、启用/禁用、密码重置等业务规则。
 *
 * <p>关键安全约束在此集中实现：
 * ① 不能删除/禁用当前登录账号（避免把自己锁死）；
 * ② 至少保留一个启用的管理员（避免系统无人可管）；
 * ③ 不能把当前登录账号的角色降级为非管理员。</p>
 */
@Service
@RequiredArgsConstructor
public class UserService {

    /** 用户数据访问接口 */
    private final UserRepository userRepository;

    /** 密码编码器（BCrypt） */
    private final PasswordEncoder passwordEncoder;

    /**
     * 查询全部用户（按 ID 升序，保证列表稳定）。
     *
     * @return 用户列表
     */
    public List<UserEntity> list() {
        return userRepository.findAllByOrderByIdAsc();
    }

    /**
     * 按 ID 查询用户（不存在抛异常）。
     *
     * @param id 主键
     * @return 用户实体
     */
    public UserEntity get(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("用户不存在: " + id));
    }

    /**
     * 新增用户（密码必填）。
     *
     * @param username    登录用户名（唯一）
     * @param displayName 展示名称
     * @param rawPassword 明文密码（入库前 BCrypt 加密）
     * @param role        角色 ADMIN / USER
     * @param permissions 逗号分隔的权限编码（ADMIN 可留空）
     * @param enabled     是否启用
     * @return 持久化后的用户
     */
    public UserEntity create(String username, String displayName, String rawPassword,
                             String role, String permissions, boolean enabled) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("用户名不能为空");
        }
        if (rawPassword == null || rawPassword.length() < 6) {
            throw new IllegalArgumentException("密码长度至少 6 位");
        }
        if (userRepository.existsByUsername(username.trim())) {
            throw new IllegalArgumentException("用户名已存在: " + username);
        }
        UserEntity u = new UserEntity();
        u.setUsername(username.trim());
        u.setDisplayName(displayName);
        u.setPassword(passwordEncoder.encode(rawPassword));
        boolean isAdmin = "ADMIN".equals(role);
        u.setRole(isAdmin ? "ADMIN" : "USER");
        // 普通用户未显式勾选权限时，赋予一组合理的默认操作权限
        // （含仪表盘/域名/证书的基础操作，不含用户管理与删除类高危项）
        if (!isAdmin && (permissions == null || permissions.isBlank())) {
            permissions = String.join(",", Permissions.DEFAULT_USER_PERMS);
        }
        u.setPermissions(normalize(permissions));
        u.setEnabled(enabled);
        return userRepository.save(u);
    }

    /**
     * 更新用户（密码为空则保留原密码）。
     *
     * @param id           主键
     * @param displayName  展示名称
     * @param rawPassword  明文密码（可空）
     * @param role         角色
     * @param permissions  权限编码串
     * @param enabled      是否启用
     * @param currentUser  当前操作者用户名（用于自保护校验）
     * @return 更新后的用户
     */
    public UserEntity update(Long id, String displayName, String rawPassword,
                             String role, String permissions, boolean enabled, String currentUser) {
        UserEntity u = get(id);
        // 不能把当前登录账号降级为非管理员，避免锁死
        if (u.getUsername().equals(currentUser) && !"ADMIN".equals(role)) {
            throw new IllegalArgumentException("不能将自己的角色改为非管理员");
        }
        // 不能禁用当前登录账号
        if (u.getUsername().equals(currentUser) && !enabled) {
            throw new IllegalArgumentException("不能禁用当前登录账号");
        }
        u.setDisplayName(displayName);
        if (rawPassword != null && !rawPassword.isBlank()) {
            if (rawPassword.length() < 6) {
                throw new IllegalArgumentException("密码长度至少 6 位");
            }
            u.setPassword(passwordEncoder.encode(rawPassword));
        }
        u.setRole("ADMIN".equals(role) ? "ADMIN" : "USER");
        u.setPermissions(normalize(permissions));
        u.setEnabled(enabled);
        return userRepository.save(u);
    }

    /**
     * 删除用户（防自删、防删最后一个管理员）。
     *
     * @param id          主键
     * @param currentUser 当前操作者用户名
     */
    public void delete(Long id, String currentUser) {
        UserEntity u = get(id);
        if (u.getUsername().equals(currentUser)) {
            throw new IllegalArgumentException("不能删除当前登录账号");
        }
        if ("ADMIN".equals(u.getRole()) && countEnabledAdmins() <= 1) {
            throw new IllegalArgumentException("至少保留一个启用的管理员");
        }
        userRepository.delete(u);
    }

    /**
     * 启用/禁用切换（防自禁、防禁最后一个管理员）。
     *
     * @param id          主键
     * @param currentUser 当前操作者用户名
     */
    public void toggleEnabled(Long id, String currentUser) {
        UserEntity u = get(id);
        if (u.getUsername().equals(currentUser)) {
            throw new IllegalArgumentException("不能禁用当前登录账号");
        }
        boolean next = !u.isEnabled();
        if (!next && "ADMIN".equals(u.getRole()) && countEnabledAdmins() <= 1) {
            throw new IllegalArgumentException("至少保留一个启用的管理员");
        }
        u.setEnabled(next);
        userRepository.save(u);
    }

    /**
     * 重置密码（长度 >= 6）。
     *
     * @param id          主键
     * @param newPassword 新明文密码
     */
    public void resetPassword(Long id, String newPassword) {
        UserEntity u = get(id);
        if (newPassword == null || newPassword.length() < 6) {
            throw new IllegalArgumentException("密码长度至少 6 位");
        }
        u.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(u);
    }

    /**
     * 统计当前启用的管理员数量。
     *
     * @return 启用管理员数
     */
    private long countEnabledAdmins() {
        return userRepository.findAll().stream()
                .filter(u -> "ADMIN".equals(u.getRole()) && u.isEnabled())
                .count();
    }

    /**
     * 规范化权限字符串：去空、去重、逗号分隔；ADMIN 角色忽略具体权限。
     *
     * @param permissions 原始权限串
     * @return 规范化后的权限串（可空）
     */
    private String normalize(String permissions) {
        if (permissions == null || permissions.isBlank()) {
            return null;
        }
        Set<String> set = Arrays.stream(permissions.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty() && Permissions.ALL.contains(s))
                .collect(Collectors.toCollection(java.util.LinkedHashSet::new));
        return set.isEmpty() ? null : String.join(",", set);
    }
}
