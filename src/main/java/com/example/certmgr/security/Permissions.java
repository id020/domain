package com.example.certmgr.security;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 系统权限定义。
 *
 * <p>每个权限用固定字符串编码（如 {@code DOMAIN_VIEW}），在 Spring Security 中
 * 以 {@code PERM_} 前缀的 authority 形式参与鉴权（如 {@code PERM_DOMAIN_VIEW}）。
 * 管理员(ADMIN)在登录时自动拥有全部权限，无需逐个勾选。</p>
 */
public final class Permissions {

    // ===================== 域名管理 =====================
    /** 域名查看：列表与详情 */
    public static final String DOMAIN_VIEW = "DOMAIN_VIEW";
    /** 域名编辑：新增/修改、触发检测、刷新 Whois */
    public static final String DOMAIN_EDIT = "DOMAIN_EDIT";
    /** 域名删除 */
    public static final String DOMAIN_DELETE = "DOMAIN_DELETE";

    // ===================== 证书管理 =====================
    /** 证书查看：列表与详情 */
    public static final String CERT_VIEW = "CERT_VIEW";
    /** 证书编辑：上传证书 */
    public static final String CERT_EDIT = "CERT_EDIT";
    /** 证书删除 */
    public static final String CERT_DELETE = "CERT_DELETE";
    /** 证书签发：ACME 自动签发 */
    public static final String CERT_ISSUE = "CERT_ISSUE";

    // ===================== 用户管理 =====================
    /** 用户查看：用户列表 */
    public static final String USER_VIEW = "USER_VIEW";
    /** 用户编辑：新增/修改/启用禁用/重置密码 */
    public static final String USER_EDIT = "USER_EDIT";
    /** 用户删除 */
    public static final String USER_DELETE = "USER_DELETE";

    // ===================== 仪表盘 =====================
    /** 仪表盘查看：首页统计与预警 */
    public static final String DASHBOARD_VIEW = "DASHBOARD_VIEW";

    /** Spring Security 中权限 authority 的前缀 */
    public static final String PREFIX = "PERM_";

    /** 全部权限编码（管理员自动拥有） */
    public static final List<String> ALL = List.of(
            DASHBOARD_VIEW,
            DOMAIN_VIEW, DOMAIN_EDIT, DOMAIN_DELETE,
            CERT_VIEW, CERT_EDIT, CERT_DELETE, CERT_ISSUE,
            USER_VIEW, USER_EDIT, USER_DELETE
    );

    /** 权限元数据：编码 + 中文名称 + 说明（用于用户管理界面展示） */
    public static final List<PermissionMeta> META = List.of(
            new PermissionMeta(DASHBOARD_VIEW, "仪表盘查看", "查看首页仪表盘与统计"),
            new PermissionMeta(DOMAIN_VIEW, "域名查看", "查看域名列表与详情"),
            new PermissionMeta(DOMAIN_EDIT, "域名编辑", "新增/修改域名、触发检测、刷新 Whois"),
            new PermissionMeta(DOMAIN_DELETE, "域名删除", "删除域名"),
            new PermissionMeta(CERT_VIEW, "证书查看", "查看证书列表与详情"),
            new PermissionMeta(CERT_EDIT, "证书编辑", "上传证书"),
            new PermissionMeta(CERT_ISSUE, "证书签发", "ACME 自动签发证书"),
            new PermissionMeta(CERT_DELETE, "证书删除", "删除证书"),
            new PermissionMeta(USER_VIEW, "用户查看", "查看用户列表"),
            new PermissionMeta(USER_EDIT, "用户编辑", "新增/修改/启用禁用用户、重置密码"),
            new PermissionMeta(USER_DELETE, "用户删除", "删除用户")
    );

    /** 普通用户默认勾选的一组合理操作权限（不含用户管理与删除类高危项） */
    public static final Set<String> DEFAULT_USER_PERMS = new LinkedHashSet<>(Set.of(
            DASHBOARD_VIEW, DOMAIN_VIEW, DOMAIN_EDIT, CERT_VIEW, CERT_EDIT, CERT_ISSUE
    ));

    private Permissions() {
    }

    /**
     * 将逗号分隔的权限编码字符串解析为去重后的权限集合。
     *
     * @param raw 原始字符串（可为 null 或空）
     * @return 权限编码集合
     */
    public static Set<String> parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * 权限元数据：编码 + 名称 + 说明。供页面迭代展示。
     */
    public static class PermissionMeta {
        /** 权限编码，如 DOMAIN_VIEW */
        public final String code;
        /** 中文名称 */
        public final String label;
        /** 简要说明 */
        public final String desc;

        public PermissionMeta(String code, String label, String desc) {
            this.code = code;
            this.label = label;
            this.desc = desc;
        }
    }
}
