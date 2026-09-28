/*
 Navicat Premium Dump SQL

 Source Server         : localhost
 Source Server Type    : MySQL
 Source Server Version : 80046 (8.0.46)
 Source Host           : localhost:3306
 Source Schema         : task

 Target Server Type    : MySQL
 Target Server Version : 80046 (8.0.46)
 File Encoding         : 65001

 Date: 28/09/2026 15:50:41
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for certificate
-- ----------------------------
DROP TABLE IF EXISTS `certificate`;
CREATE TABLE `certificate` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `auto_renew` bit(1) DEFAULT NULL,
  `cert_pem` text COLLATE utf8mb4_general_ci,
  `common_name` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `created_at` datetime(6) DEFAULT NULL,
  `domain_name` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `issuer` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `name` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `not_after` datetime(6) DEFAULT NULL,
  `not_before` datetime(6) DEFAULT NULL,
  `private_key_pem` text COLLATE utf8mb4_general_ci,
  `public_key_algorithm` varchar(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `san_domains` varchar(2000) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `serial_number` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `signature_algorithm` varchar(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `status` enum('EXPIRED','REVOKED','VALID') COLLATE utf8mb4_general_ci NOT NULL,
  `type` enum('ACME_ISSUED','UPLOADED') COLLATE utf8mb4_general_ci NOT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of certificate
-- ----------------------------
BEGIN;
INSERT INTO `certificate` (`id`, `auto_renew`, `cert_pem`, `common_name`, `created_at`, `domain_name`, `issuer`, `name`, `not_after`, `not_before`, `private_key_pem`, `public_key_algorithm`, `san_domains`, `serial_number`, `signature_algorithm`, `status`, `type`, `updated_at`) VALUES (1, b'0', '-----BEGIN CERTIFICATE-----\r\nMIID3jCCAsagAwIBAgIUItw9f0UcdN0SzV5Y6/a0XSdHgzIwDQYJKoZIhvcNAQEL\r\nBQAwajELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0Jl\r\naWppbmcxFDASBgNVBAoMC0V4YW1wbGUgSW5jMQswCQYDVQQLDAJJVDEUMBIGA1UE\r\nAwwLZXhhbXBsZS5jb20wHhcNMjYwOTIzMTM0ODA2WhcNMjcwOTIzMTM0ODA2WjBq\r\nMQswCQYDVQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamlu\r\nZzEUMBIGA1UECgwLRXhhbXBsZSBJbmMxCzAJBgNVBAsMAklUMRQwEgYDVQQDDAtl\r\neGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBftv6G\r\n6WwLm+h2Kzs8/iRxAGBeIZqWHs9qWipzI+25cEV92nYGWlKRGhYa7lhDv1kmLpcj\r\nlKPswPdG2jZoyq01R9cPWpSEDAXHNfhI5svuJRSNkFuWIu+w3gTuXKktw7GPNX3U\r\nJel+C9fak9Vn2jva4tvvBw784S7Z5jVbbYt12glcN+Lraa4SB8X8YbXt3Z66mlqu\r\nFJ1+kfke+o1WV97mhfKqh4Tzq1Px4/nzPwssMHEAO0Mhc/NZ1KpLuyvFjE0E1yfh\r\nwrL3VI2sOnUkwaTas7LqmPdEYVErmFWMge3jforwtjaBqEY8/CUgegT/AwM52aIH\r\n+fWKjuuwIzpP7rkCAwEAAaN8MHowHQYDVR0OBBYEFMw97uiJKdnXECidJmYrt+cx\r\nC+xlMB8GA1UdIwQYMBaAFMw97uiJKdnXECidJmYrt+cxC+xlMA8GA1UdEwEB/wQF\r\nMAMBAf8wJwYDVR0RBCAwHoILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLmNvbTAN\r\nBgkqhkiG9w0BAQsFAAOCAQEABevk5eq3Xm2RquhA3lMgSijPaElqU+a4RJHBZia1\r\n7kjC6sruwOOD3yMev8IJzDCiVXLimZ1Wpb4HZWDIdf9p7qNgLm7C96RramJN/2G9\r\nxmU3b8N3Pvirs1qYg6iTCeWNB04ID9XoTUN+MjE+n6J7+cWRCJuTGVkVKFFnLRSn\r\nALQ6znbXcjB5pFUZtxFquTKTpzC8WC/pzPWJw+dAYoSIh2uStgFNT8LdUiSz0/me\r\n4YoTK/i2h+Mv3HHAZJK6n4sJb1DaWdptzEVG3LDWMkfuE7N8RpAa+5MDc98xm0wg\r\nbpDbYzGlfBorFTvETve/3Ga2i5QXg9drdrfvNQp4DnVcGA==\r\n-----END CERTIFICATE-----', 'example.com', '2026-09-25 10:21:07.867022', '', 'example.com', 'aaa', '2027-09-23 21:48:06.000000', '2026-09-23 21:48:06.000000', '-----BEGIN PRIVATE KEY-----\r\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAX7b+hulsC5vo\r\ndis7PP4kcQBgXiGalh7PaloqcyPtuXBFfdp2BlpSkRoWGu5YQ79ZJi6XI5Sj7MD3\r\nRto2aMqtNUfXD1qUhAwFxzX4SObL7iUUjZBbliLvsN4E7lypLcOxjzV91CXpfgvX\r\n2pPVZ9o72uLb7wcO/OEu2eY1W22LddoJXDfi62muEgfF/GG17d2eupparhSdfpH5\r\nHvqNVlfe5oXyqoeE86tT8eP58z8LLDBxADtDIXPzWdSqS7srxYxNBNcn4cKy91SN\r\nrDp1JMGk2rOy6pj3RGFRK5hVjIHt436K8LY2gahGPPwlIHoE/wMDOdmiB/n1io7r\r\nsCM6T+65AgMBAAECggEATivWyZD680u4W/sA0D6Vqys8EuzNTOrptDEsWImXNPeg\r\ntqxQhJtKQrjx17+z0Kwe6lQIpKPxt7byJslkzK1ChqXa/nofva/2zrZHqQ++sWmh\r\nKbvoyD63DZ1aariNcLXHCrT98JavnTT6DQml/xcHaEEm5GY6AQ4jVw12bYIsfnl9\r\n9BO5cByhEPsuLWg03/9T+s7Rvih6nynX4scGzSzCsH04eknHDaPC2b1jfXoHR3i1\r\nWCYwPt+227w3t+R8imPS+pnu/I5+2tVXu4QVSo4SBSh0yv9IvU+KBX2mw2Xexh+e\r\nLot5NzzIysPA/0aMv6qjy2bsNTnEIoDhdysFkHCgLQKBgQDg4ZK9Zz1sGH5XwXk6\r\npmQuegp9Hdwx06TERySd8jttGo5XZPCii7kl/xXpFvQmPnI3n+czJEDT/ZzDeVLU\r\nOaT05VSOWIaRlqCPCKYZ+0rEuHq4KPi8QRvkpTO/mlQPhru9UWeHAoS5qM51Sn38\r\nRTAUOLjra+twFwaEDHuYLr37BwKBgQDa/pH4B1MyBrLZ1mfFv26TfF5mThx72QtU\r\nFixy4vSymL3Mt/tYV9ImOgcLHVAMkT4BnSn8KWAEWi68Hc/XaaF/DTQg80tHUqZS\r\ndvZL3L6/zXcLVojTMt9oKFogQpefRCavUH6kMb+LSiZ7Dwxi3p+YOhK7gwFF5OOT\r\nSZh9l6WYPwKBgQCayQjMj2QKpC1KT+QWh3LLPrs7dTMbpLZzVxiQEqvuo+m3o8Wx\r\nzARrb9Fv95mjPTY2rTxgyiJJB/Y/4aEubGLrIXJ669nsGcZ3zRcvKPVExEnLun/C\r\na/o7/a3Jwvr7GNzeKUrd9dDPTa6VsulWm3TFZml5uXV7WI3mlAT6MaoYPwKBgDR1\r\ndNv4TTqXljJOhO8+yyszSJ2zKmmUdX1ADoe6zCkYI6ctj1z7NJEJp3RHIkzQYg0a\r\n69rGwoRoYfeYIJiWaiQ4MnuOLEM6jjME4j0L9PmXK2Qg54fIEPIvcF939EAnoCiw\r\n3JVSgXLJYWxrD2mDsLFTf/dBC4YFrWoz3/593CIbAoGAVXMVhLpNJCo8Qq3Tcjlx\r\nIqSdRi6fYDBhEd1sPQvYijhReFBCBtuJgG1j5cp/jS5CwKwZbjAVdmwh7a7t186Q\r\naKnmeaA1Scvq+ZEWir8x4RtBBjdJ9BTqNmCdP1RTu5T6OckWMUTR7C7HS/vqcYxG\r\nEzRJnm7WWLnAE/Tk7OAlyNI=\r\n-----END PRIVATE KEY-----\r\n', 'RSA 2048', 'example.com,www.example.com', '22DC3D7F451C74DD12CD5E58EBF6B45D27478332', 'SHA256withRSA', 'VALID', 'UPLOADED', '2026-09-25 10:21:07.867076');
COMMIT;

-- ----------------------------
-- Table structure for domain
-- ----------------------------
DROP TABLE IF EXISTS `domain`;
CREATE TABLE `domain` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `cert_common_name` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `cert_days_left` int DEFAULT NULL,
  `cert_expiry_at` datetime(6) DEFAULT NULL,
  `cert_issuer` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `cert_status` enum('ERROR','EXPIRED','EXPIRING','NONE','OK') COLLATE utf8mb4_general_ci DEFAULT NULL,
  `created_at` datetime(6) DEFAULT NULL,
  `description` varchar(500) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `last_check_at` datetime(6) DEFAULT NULL,
  `last_error` varchar(1000) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `name` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `port` int NOT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `whois_creation_date` varchar(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `whois_expiry_date` varchar(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `whois_registrar` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UKga2sqp4lboblqv6oks9oryd9q` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of domain
-- ----------------------------
BEGIN;
INSERT INTO `domain` (`id`, `cert_common_name`, `cert_days_left`, `cert_expiry_at`, `cert_issuer`, `cert_status`, `created_at`, `description`, `last_check_at`, `last_error`, `name`, `port`, `updated_at`, `whois_creation_date`, `whois_expiry_date`, `whois_registrar`) VALUES (8, 'baidu.com', 120, '2027-01-24 10:32:55.000000', 'GlobalSign RSA OV SSL CA 2018', 'OK', '2026-09-25 11:08:53.251329', '', '2026-09-25 16:02:27.023443', NULL, 'baidu.com', 443, '2026-09-25 16:02:27.688068', '1999-10-11', '2028-10-11', 'MarkMonitor Information Technology (Shanghai) Co., Ltd.');
COMMIT;

-- ----------------------------
-- Table structure for users
-- ----------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '主键',
  `username` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '登录用户名（唯一）',
  `password` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'BCrypt 加密后的密码',
  `display_name` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '展示名称',
  `role` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'USER' COMMENT '角色：ADMIN / USER',
  `enabled` tinyint(1) NOT NULL DEFAULT '1' COMMENT '是否启用（1=启用,0=禁用）',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  `permissions` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_users_username` (`username`),
  UNIQUE KEY `UKr43af9ap4edm43mmtq01oddj6` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='系统用户表';

-- ----------------------------
-- Records of users
-- ----------------------------
BEGIN;
INSERT INTO `users` (`id`, `username`, `password`, `display_name`, `role`, `enabled`, `created_at`, `updated_at`, `permissions`) VALUES (1, 'admin', '$2a$10$.bbDXULS16BpfAgYKFuI/.LOZOelhRxIBepA0BK1iiixljEcyGfKy', '系统管理员', 'ADMIN', 1, '2026-09-25 02:13:36', '2026-09-25 02:13:36', NULL);
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
