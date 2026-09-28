-- ============================================================
-- 证书管理系统 - 用户表（鉴权功能）DDL
-- 适用：MySQL 8.x
-- 说明：
--   1) 结构与 com.example.certmgr.entity.UserEntity 完全一致；
--   2) 应用启动时若 users 表为空，会自动创建默认管理员
--      （用户名 admin / 密码 admin123，BCrypt 加密），见 DataInitializer；
--   3) 本文件用于手动建表 / DBA 评审；CREATE TABLE IF NOT EXISTS 保证重复执行不会报错；
--   4) 末尾的 INSERT 为可选种子数据（密码为 admin123 的 BCrypt 哈希），
--      若应用已自动初始化过管理员，UNIQUE 约束会避免重复插入。
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id           BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    username     VARCHAR(64)  NOT NULL                COMMENT '登录用户名（唯一）',
    password     VARCHAR(100) NOT NULL                COMMENT 'BCrypt 加密后的密码',
    display_name VARCHAR(100) DEFAULT NULL            COMMENT '展示名称',
    role         VARCHAR(20)  NOT NULL DEFAULT 'USER' COMMENT '角色：ADMIN / USER',
    enabled      TINYINT(1)   NOT NULL DEFAULT 1      COMMENT '是否启用（1=启用,0=禁用）',
    created_at   DATETIME     DEFAULT CURRENT_TIMESTAMP
                              COMMENT '创建时间',
    updated_at   DATETIME     DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (id),
    UNIQUE KEY uk_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='系统用户表';

-- 可选：手动插入默认管理员
-- 密码明文为 admin123，下方为对应的 BCrypt 哈希值（与 DataInitializer 无关，仅用于手动初始化）
INSERT IGNORE INTO users (username, password, display_name, role, enabled)
VALUES ('admin', '$2a$10$.bbDXULS16BpfAgYKFuI/.LOZOelhRxIBepA0BK1iiixljEcyGfKy', '系统管理员', 'ADMIN', 1);
