package com.example.certmgr.dto;

import lombok.Data;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DNS 解析结果对象。
 * 以记录类型为键、记录值为列表，便于详情页逐类型展示。
 */
@Data
public class DnsResult {

    /** 各类型记录：A / AAAA / CNAME / MX / NS / TXT / SOA */
    private Map<String, List<String>> records = new LinkedHashMap<>();

    /** 探测错误信息（无错误则为 null） */
    private String error;
}
