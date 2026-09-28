package com.example.certmgr.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** RDAP 服务发现与 URL 拼接回归测试；不依赖外部网络。 */
class WhoisServiceTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void shouldSelectLongestSuffixAndAllHttpsEndpoints() throws Exception {
        JsonNode bootstrap = mapper.readTree("""
                {"services":[
                  [["cn"],["https://rdap.example/cn/"]],
                  [["com.cn"],["http://insecure.example/", "https://rdap.example/com-cn/", "https://backup.example/rdap/"]],
                  [["com"],["https://rdap.verisign.com/com/v1/"]],
                  [["net"],["https://rdap.verisign.com/net/v1/"]],
                  [["org"],["https://rdap.example/org/"]],
                  [["io"],["https://rdap.example/io/"]],
                  [["ai"],["https://rdap.example/ai/"]] ]}
                """);
        assertEquals(List.of("https://rdap.example/com-cn/", "https://backup.example/rdap/"),
                WhoisService.findBootstrapUrls(bootstrap, "www.example.com.cn"));
        for (String tld : List.of("com", "net", "org", "cn", "io", "ai")) {
            assertFalse(WhoisService.findBootstrapUrls(bootstrap, "example." + tld).isEmpty(), tld);
        }
    }

    @Test
    void shouldJoinRdapUrlWithoutDuplicateDomainPath() {
        assertEquals("https://rdap.verisign.com/com/v1/domain/baidu.com",
                WhoisService.rdapDomainUrl("https://rdap.verisign.com/com/v1/", "baidu.com"));
        assertEquals("https://rdap.example/rdap/domain/example.org",
                WhoisService.rdapDomainUrl("https://rdap.example/rdap/domain/", "example.org"));
        assertThrows(IllegalArgumentException.class,
                () -> WhoisService.rdapDomainUrl("http://untrusted.example/", "example.org"));
    }
    @Test
    void shouldExtractMissingDatesFromWhoisRawAndNormalizeFormat() {
        com.example.certmgr.dto.WhoisResult result = new com.example.certmgr.dto.WhoisResult();
        result.setRaw("Domain Name: BAIDU.COM\nCreation Date: 1999-10-11T11:05:17Z\n"
                + "Registry Expiry Date: 2028-10-11T11:05:17Z\nUpdated Date: 2026-08-17T07:44:00Z\n");
        WhoisService.completeDatesFromRaw(result);
        assertEquals("1999-10-11", result.getCreationDate());
        assertEquals("2028-10-11", result.getExpiryDate());
    }

    @Test
    void shouldPreserveValidDateAndFillOnlyMissingDate() {
        com.example.certmgr.dto.WhoisResult result = new com.example.certmgr.dto.WhoisResult();
        result.setCreationDate("2001/02/03");
        result.setRaw("Creation Date: 1999-10-11\nExpires On: 11-Oct-2028\n");
        WhoisService.completeDatesFromRaw(result);
        assertEquals("2001-02-03", result.getCreationDate());
        assertEquals("2028-10-11", result.getExpiryDate());
    }

    @Test
    void shouldExtractDatesFromRdapJsonWhenStructuredFieldsMissing() {
        com.example.certmgr.dto.WhoisResult result = new com.example.certmgr.dto.WhoisResult();
        result.setRaw("{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"1999-10-11T11:05:17Z\"},"
                + "{\"eventAction\":\"expiration\",\"eventDate\":\"2028-10-11T11:05:17Z\"}]}");
        WhoisService.completeDatesFromRaw(result);
        assertEquals("1999-10-11", result.getCreationDate());
        assertEquals("2028-10-11", result.getExpiryDate());
    }

    @Test
    void shouldIgnoreInvalidDateRatherThanPersistIt() {
        com.example.certmgr.dto.WhoisResult result = new com.example.certmgr.dto.WhoisResult();
        result.setRaw("Creation Date: 2026-02-30\nExpiry Date: unknown\n");
        WhoisService.completeDatesFromRaw(result);
        assertNull(result.getCreationDate());
        assertNull(result.getExpiryDate());
    }
    /** CNNIC 的 Registration Time 必须作为注册日期识别，而不能只识别 Creation Date。 */
    @Test
    void shouldParseCnnicRegistrationTimeAndExpirationTime() {
        com.example.certmgr.dto.WhoisResult result = new com.example.certmgr.dto.WhoisResult();
        result.setRaw("Domain Name: example.cn\nRegistration Time: 2003-03-17 12:20:05\n"
                + "Expiration Time: 2028-03-17 12:20:05\nDNSSEC: unsigned\n");
        WhoisService.completeDatesFromRaw(result);
        assertEquals("2003-03-17", result.getCreationDate());
        assertEquals("2028-03-17", result.getExpiryDate());
    }

    /** 已有 RDAP 注册日期优先；缺失的到期日期才从 CNNIC WHOIS 补充。 */
    @Test
    void shouldPreserveExistingRdapDateAndFillMissingCnnicDate() {
        com.example.certmgr.dto.WhoisResult result = new com.example.certmgr.dto.WhoisResult();
        result.setCreationDate("2005-01-02T12:00:00Z");
        result.setRaw("Registration Time: 2003-03-17 12:20:05\n"
                + "Expiration Time: 2028-03-17 12:20:05\n");
        WhoisService.completeDatesFromRaw(result);
        assertEquals("2005-01-02", result.getCreationDate());
        assertEquals("2028-03-17", result.getExpiryDate());
    }

    @Test
    void shouldResolveRegistrableDomainsForSubdomainsAndMultiLevelSuffixes() {
        assertEquals("baidu.com", WhoisService.registrableDomain("www.baidu.com"));
        assertEquals("baidu.com", WhoisService.registrableDomain("api.test.baidu.com"));
        assertEquals("example.com.cn", WhoisService.registrableDomain("www.example.com.cn"));
        assertEquals("example.net", WhoisService.registrableDomain("mail.example.net"));
        assertEquals("example.org", WhoisService.registrableDomain("example.org"));
        assertEquals("example.io", WhoisService.registrableDomain("www.example.io"));
        assertEquals("example.ai", WhoisService.registrableDomain("www.example.ai"));
        assertThrows(IllegalArgumentException.class,
                () -> WhoisService.registrableDomain("com.cn"));
    }

}
