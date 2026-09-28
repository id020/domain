package com.example.certmgr.service;

import com.example.certmgr.dto.CertInfo;
import com.example.certmgr.entity.CertificateEntity;
import com.example.certmgr.entity.CertificateStatus;
import com.example.certmgr.entity.CertificateType;
import com.example.certmgr.repository.CertificateRepository;
import com.example.certmgr.util.CertParser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * 证书业务服务。
 *
 * <p>负责证书库的增删改查、手动上传解析（PEM + 私钥）以及委托 ACME 自动签发。
 * 上传时自动解析证书元信息（CN/SAN/签发者/有效期等）并落库。</p>
 */
@Service
@RequiredArgsConstructor
public class CertificateService {

    /** 证书数据访问 */
    private final CertificateRepository certRepo;

    /** ACME 自动签发服务 */
    private final AcmeService acmeService;

    /**
     * 查询全部证书。
     *
     * @return 证书列表
     */
    public List<CertificateEntity> list() {
        return certRepo.findAll();
    }

    /**
     * 按 ID 查询证书（不存在抛异常）。
     *
     * @param id 主键
     * @return 证书实体
     */
    public CertificateEntity get(Long id) {
        return certRepo.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("证书不存在: " + id));
    }

    /**
     * 保存或更新证书实体。
     *
     * @param entity 证书实体
     * @return 持久化后的实体
     */
    public CertificateEntity save(CertificateEntity entity) {
        return certRepo.save(entity);
    }

    /**
     * 删除证书。
     *
     * @param id 主键
     */
    public void delete(Long id) {
        certRepo.deleteById(id);
    }

    /**
     * 手动上传证书：解析 PEM 元信息后入库（来源标记为 UPLOADED）。
     *
     * @param name 证书别名
     * @param domainName 关联域名
     * @param certPem 证书 PEM 文本（可含链）
     * @param privateKeyPem 私钥 PEM 文本（可为空）
     * @return 保存后的证书实体
     */
    public CertificateEntity upload(String name, String domainName, String certPem, String privateKeyPem) {
        if (certPem == null || certPem.isBlank()) {
            throw new IllegalArgumentException("证书内容不能为空");
        }
        try {
            // 解析 PEM 得到叶子证书并提取元信息
            X509Certificate cert = CertParser.parsePem(certPem);
            CertInfo info = CertParser.parse(cert);

            CertificateEntity entity = new CertificateEntity();
            entity.setName(name);
            entity.setDomainName(domainName);
            entity.setCommonName(info.getCommonName());
            entity.setSanDomains(String.join(",", info.getSanDomains()));
            entity.setIssuer(info.getIssuer());
            entity.setNotBefore(info.getNotBefore());
            entity.setNotAfter(info.getNotAfter());
            entity.setSerialNumber(info.getSerialNumber());
            entity.setSignatureAlgorithm(info.getSignatureAlgorithm());
            entity.setPublicKeyAlgorithm(info.getPublicKeyAlgorithm());
            entity.setCertPem(certPem);
            entity.setPrivateKeyPem(privateKeyPem);
            entity.setType(CertificateType.UPLOADED);
            // 依据到期时间判定初始状态
            boolean expired = cert.getNotAfter().toInstant().isBefore(Instant.now());
            entity.setStatus(expired ? CertificateStatus.EXPIRED : CertificateStatus.VALID);
            entity.setAutoRenew(false);
            return certRepo.save(entity);
        } catch (Exception e) {
            throw new IllegalArgumentException("证书解析失败: " + e.getMessage(), e);
        }
    }

    /**
     * 委托 ACME 服务签发证书并入库。
     *
     * @param domainName 主域名
     * @param sans 附加 SAN 域名
     * @param autoRenew 是否自动续期
     * @return 保存后的证书实体
     */
    public CertificateEntity issue(String domainName, List<String> sans, boolean autoRenew) {
        return acmeService.issue(domainName, sans, autoRenew);
    }
}
