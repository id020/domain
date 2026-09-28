package com.example.certmgr.entity;

import com.example.certmgr.security.Permissions;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 系统用户实体：用于登录鉴权。
 *
 * <p>对应数据库 {@code users} 表，存储登录用户名、BCrypt 加密后的密码、
 * 角色与启用状态。Spring Security 通过该实体完成身份认证。</p>
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "users", uniqueConstraints = @UniqueConstraint(columnNames = "username"))
public class UserEntity {

    /** 主键 ID，自增 */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 登录用户名，全局唯一 */
    @Column(nullable = false, unique = true, length = 64)
    private String username;

    /** BCrypt 加密后的密码（明文绝不入库） */
    @Column(nullable = false, length = 100)
    private String password;

    /** 展示名称（可选） */
    @Column(length = 100)
    private String displayName;

    /** 角色：ADMIN / USER（对应 Spring Security 的 ROLE_ADMIN / ROLE_USER） */
    @Column(nullable = false, length = 20)
    private String role = "USER";

    /** 是否启用：禁用后无法登录 */
    @Column(nullable = false)
    private boolean enabled = true;

    /** 细粒度权限编码（逗号分隔，如 DOMAIN_VIEW,CERT_VIEW）；ADMIN 留空表示拥有全部 */
    @Column(length = 500)
    private String permissions;

    /** 创建时间（插入时自动写入） */
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    /** 更新时间（每次更新自动刷新） */
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    /**
     * 解析当前用户拥有的权限编码集合。
     * 管理员(ADMIN)始终视为拥有 {@link Permissions#ALL} 全部权限。
     *
     * @return 权限编码集合（去重、保序）
     */
    public Set<String> getPermissionSet() {
        if ("ADMIN".equals(role)) {
            return new LinkedHashSet<>(Permissions.ALL);
        }
        if (permissions == null || permissions.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(permissions.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * 供页面展示的权限中文标签列表。
     * 管理员显示“全部权限”，普通用户按其权限集合映射为标签。
     *
     * @return 权限中文标签列表
     */
    public List<String> getPermissionLabels() {
        if ("ADMIN".equals(role)) {
            return List.of("全部权限");
        }
        Set<String> set = getPermissionSet();
        if (set.isEmpty()) {
            return List.of();
        }
        return Permissions.META.stream()
                .filter(m -> set.contains(m.code))
                .map(m -> m.label)
                .collect(Collectors.toList());
    }
}
