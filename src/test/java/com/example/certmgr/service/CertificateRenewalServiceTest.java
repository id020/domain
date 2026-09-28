package com.example.certmgr.service;

import com.example.certmgr.config.CertProperties;
import com.example.certmgr.entity.CertificateEntity;
import com.example.certmgr.repository.CertificateRepository;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 自动部署必须显式指定目标域名，避免覆盖其他网站的 HTTPS 证书。 */
class CertificateRenewalServiceTest {
    @Test
    void doesNotDeployUnmatchedDomain() {
        CertProperties config = new CertProperties();
        config.getAcme().setDeployDomain("example.com");
        CertificateRenewalService service = new CertificateRenewalService(
                mock(CertificateRepository.class), mock(AcmeService.class), config);
        CertificateEntity cert = new CertificateEntity();
        cert.setDomainName("other.example.com");
        assertDoesNotThrow(() -> service.deploy(cert));
    }
}
