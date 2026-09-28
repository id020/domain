package com.example.certmgr.repository;

import com.example.certmgr.entity.CertificateEntity;
import com.example.certmgr.entity.CertificateType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 证书数据访问层。
 * 提供按域名、按来源类型查询的能力。
 */
@Repository
public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> {

    /**
     * 根据关联域名查询其下所有证书。
     *
     * @param domainName 域名
     * @return 证书列表（可能为空）
     */
    List<CertificateEntity> findByDomainName(String domainName);

    /**
     * 根据证书来源类型查询。
     *
     * @param type 来源类型
     * @return 证书列表
     */
    List<CertificateEntity> findByType(CertificateType type);
}
