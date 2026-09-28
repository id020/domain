package com.example.certmgr.util;

import com.example.certmgr.dto.CertInfo;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 证书解析工具类。
 * 提供从 X509Certificate 对象或 PEM 文本中提取结构化元信息的能力，
 * 被远程探测与证书上传解析共用。
 */
public final class CertParser {

    /** 私有构造，避免实例化工具类 */
    private CertParser() {
    }

    /**
     * 将 X509Certificate 解析为 {@link CertInfo}。
     *
     * @param cert X509 证书对象
     * @return 结构化证书元信息
     */
    public static CertInfo parse(X509Certificate cert) {
        CertInfo info = new CertInfo();
        // 主域名 CN：从主体名称中提取 "CN=xxx" 部分
        info.setCommonName(extractCn(cert.getSubjectX500Principal().getName()));
        // 签发者
        info.setIssuer(extractCn(cert.getIssuerX500Principal().getName()));
        // 生效/到期时间：Date -> LocalDateTime（系统默认时区）
        info.setNotBefore(toLocal(cert.getNotBefore().toInstant()));
        info.setNotAfter(toLocal(cert.getNotAfter().toInstant()));
        // 序列号（十六进制大写）
        info.setSerialNumber(cert.getSerialNumber().toString(16).toUpperCase());
        // 签名算法
        info.setSignatureAlgorithm(cert.getSigAlgName());
        // 公钥算法与长度
        info.setPublicKeyAlgorithm(extractPublicKeyInfo(cert));
        // SAN 列表
        info.setSanDomains(extractSan(cert));
        return info;
    }

    /**
     * 从 PEM 文本（可含多个证书）中解析出第一张（叶子）证书。
     *
     * @param pemText 证书 PEM 文本
     * @return 叶子 X509 证书
     * @throws CertificateException PEM 解析失败
     */
    public static X509Certificate parsePem(String pemText) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream in = new ByteArrayInputStream(pemText.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        // generateCertificates 支持 PEM 批量解析，取第一张作为叶子证书
        Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(in);
        if (certs.isEmpty()) {
            throw new CertificateException("PEM 中未找到有效证书");
        }
        return (X509Certificate) certs.iterator().next();
    }

    /** 将 Instant 转为本地时区 LocalDateTime */
    private static LocalDateTime toLocal(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
    }

    /** 从 X500 名称字符串中提取 CN 字段 */
    private static String extractCn(String name) {
        // 形如 "CN=www.example.com, O=Let's Encrypt, C=US"
        for (String part : name.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=") || trimmed.startsWith("cn=")) {
                return trimmed.substring(3).trim();
            }
        }
        return name;
    }

    /** 提取公钥算法及长度，如 "RSA 2048" / "EC 256" */
    private static String extractPublicKeyInfo(X509Certificate cert) {
        String alg = cert.getPublicKey().getAlgorithm();
        int length = -1;
        if (cert.getPublicKey() instanceof RSAKey rsaKey) {
            length = rsaKey.getModulus().bitLength();
        }
        return length > 0 ? alg + " " + length : alg;
    }

    /** 提取 SAN 域名列表（仅 DNS 类型，忽略 IP 等） */
    private static List<String> extractSan(X509Certificate cert) {
        List<String> sans = new ArrayList<>();
        try {
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            if (altNames != null) {
                for (List<?> entry : altNames) {
                    // entry[0] = 类型(2=DNS,7=IP...)，entry[1] = 值
                    if (entry.size() >= 2 && entry.get(0) instanceof Integer type && type == 2) {
                        sans.add(String.valueOf(entry.get(1)));
                    }
                }
            }
        } catch (Exception e) {
            // SAN 解析失败不影响主流程，返回空列表
        }
        return sans;
    }
}
