package com.example.certmgr.dto;

import lombok.Data;

import java.util.List;

/**
 * Whois 查询结果对象。
 * 包含从原始 Whois 文本中解析出的常用字段，
 * 解析失败时仅保留 raw 与 error 字段。
 */
@Data
public class WhoisResult {

    /** 查询来源：RDAP 或 WHOIS */
    private String source;

    /** 域名 */
    private String domainName;

    /** WHOIS/RDAP 实际查询的注册域名，子域名的注册信息继承自此域名 */
    private String registrableDomain;

    /** 注册商 */
    private String registrar;

    /** 注册（创建）时间 */
    private String creationDate;

    /** 到期时间 */
    private String expiryDate;

    /** 域名状态列表 */
    private List<String> statuses;

    /** 名称服务器列表 */
    private List<String> nameServers;

    /** 原始 Whois 文本（用于详情页完整展示） */
    private String raw;

    /** 错误信息（无错误则为 null） */
    private String error;
}
