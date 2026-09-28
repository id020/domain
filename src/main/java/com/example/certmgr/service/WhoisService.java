package com.example.certmgr.service;

import com.example.certmgr.dto.WhoisResult;
import com.google.common.net.InternetDomainName;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.InetSocketAddress;
import java.net.IDN;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.time.temporal.TemporalAccessor;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Locale;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashSet;
import java.util.Collections;
import java.util.function.Consumer;

/**
 * Whois 查询服务。
 *
 * <p>通过 43 端口向对应后缀的 Whois 服务器发起查询并读取原始文本，
 * 再解析出注册商、创建/到期时间、状态、名称服务器等常用字段。
 * 解析为尽力而为，覆盖主流注册局常见字段，失败不影响其他信息展示。</p>
 */
@Service
public class WhoisService {

    private static final Logger log = LoggerFactory.getLogger(WhoisService.class);
    private static final String BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
    private static final long BOOTSTRAP_TTL_MS = 24L * 60 * 60 * 1000;
    /** IANA 列表缓存：即使下一次更新失败，仍可使用上次成功的版本。 */
    private volatile JsonNode cachedBootstrap;
    private volatile long bootstrapFetchedAt;
    /** 只允许从可信的 IANA 列表或明确配置的注册局地址发起 HTTPS 查询。 */
    private static final Map<String, List<String>> RDAP_FALLBACK = Map.of(
            "com", List.of("https://rdap.verisign.com/com/v1/"),
            "net", List.of("https://rdap.verisign.com/net/v1/"),
            "org", List.of("https://rdap.publicinterestregistry.org/rdap/"),
            "cn", List.of("https://rdap.cnnic.cn/rdap/"));
    private final ObjectMapper mapper;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NORMAL).build();

    public WhoisService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** 常见后缀 -> Whois 服务器映射；未命中则回退到 IANA 根 */
    private static final Map<String, String> WHOIS_SERVERS = new LinkedHashMap<>();

    /** 连接超时（毫秒）：目标 Whois 服务器不可达时快速失败，避免请求长时间阻塞 */
    private static final int CONNECT_TIMEOUT_MS = 5000;

    /** 读取超时（毫秒）：连接成功但响应缓慢时快速失败 */
    private static final int READ_TIMEOUT_MS = 8000;

    static {
        WHOIS_SERVERS.put("com", "whois.verisign-grs.com");
        WHOIS_SERVERS.put("net", "whois.verisign-grs.com");
        WHOIS_SERVERS.put("org", "whois.pir.org");
        WHOIS_SERVERS.put("cn", "whois.cnnic.cn");
        WHOIS_SERVERS.put("io", "whois.nic.io");
        WHOIS_SERVERS.put("ai", "whois.nic.ai");
        WHOIS_SERVERS.put("info", "whois.afilias.net");
        WHOIS_SERVERS.put("biz", "whois.nic.biz");
        WHOIS_SERVERS.put("xyz", "whois.nic.xyz");
        WHOIS_SERVERS.put("top", "whois.nic.top");
        WHOIS_SERVERS.put("club", "whois.nic.club");
    }

    /**
     * 查询域名 Whois 信息。
     *
     * @param domain 域名
     * @return Whois 结果对象
     */
    public WhoisResult query(String domain) {
        WhoisResult result = new WhoisResult();
        String rdapError;
        try {
            String normalized = IDN.toASCII(domain.trim().toLowerCase(Locale.ROOT));
            if (!normalized.matches("(?=.{1,253}$)[a-z0-9-]+(\\.[a-z0-9-]+)+")) {
                throw new IllegalArgumentException("域名格式不正确");
            }
            result.setDomainName(normalized);
            // 注册信息属于可注册域名；SSL/DNS 仍使用数据库保存的完整主机名。
            String registrable = registrableDomain(normalized);
            result.setRegistrableDomain(registrable);
            String server = null;
            try {
                WhoisResult rdap = queryRdap(registrable, result);
                completeDatesFromRaw(rdap);
                // 某些注册局的 RDAP 响应不公开注册时间，但其传统 WHOIS 仍提供
                // Registration Time。只补充缺失字段，不覆盖 RDAP 已确认的数据。
                if (!hasText(rdap.getCreationDate()) || !hasText(rdap.getExpiryDate())) {
                    supplementMissingDatesFromWhois(registrable, rdap);
                }
                rdap.setDomainName(normalized);
                return rdap;
            } catch (Exception e) {
                rdapError = e.getMessage();
                log.warn("RDAP 查询失败，域名={}，原因={}", normalized, rdapError, e);
            }
            try {
                String tld = registrable.substring(registrable.lastIndexOf('.') + 1);
                server = WHOIS_SERVERS.get(tld);
                if (server == null) {
                    // IANA WHOIS 返回 refer 字段，必须继续查询注册局而非解析 IANA 文本。
                    String iana = queryRaw("whois.iana.org", tld);
                    for (String line : iana.split("\\n")) {
                        if (line.toLowerCase(Locale.ROOT).startsWith("refer:")) {
                            server = line.substring(line.indexOf(':') + 1).trim();
                            break;
                        }
                    }
                }
                if (server == null || !server.matches("[a-zA-Z0-9.-]+")) {
                    throw new IllegalStateException("未发现注册局 WHOIS 服务器");
                }
                String raw = queryRaw(server, registrable);
                result.setRaw(raw);
                parse(raw, result);
                // WHOIS 原始响应可能包含大写注册域名，页面仍展示用户输入的完整主机名。
                result.setDomainName(normalized);
                completeDatesFromRaw(result);
                if (result.getRegistrar() == null && result.getExpiryDate() == null
                        && result.getCreationDate() == null) {
                    throw new IllegalStateException("注册局未返回可识别的注册信息；响应长度=" + raw.length()
                            + "，响应前200字=" + raw.substring(0, Math.min(200, raw.length())).replaceAll("[\\r\\n]", " "));
                }
                result.setSource("WHOIS");
            } catch (Exception e) {
                log.warn("WHOIS 查询失败，域名={}，服务器={}，原因={}", normalized, server, e.toString(), e);
                result.setError("RDAP: " + rdapError + "; WHOIS: " + e.getMessage());
            }
        } catch (Exception e) {
            result.setError(e.getMessage());
        }
        return result;
    }

    /**
     * 使用 Public Suffix List 提取注册域名（eTLD+1）。
     * www.baidu.com -> baidu.com，api.www.example.com.cn -> example.com.cn。
     * 对于无法识别公共后缀的域名，明确报错，避免错误地查询 com.cn 等公共后缀。
     */
    static String registrableDomain(String hostname) {
        if (hostname == null || hostname.isBlank()) {
            throw new IllegalArgumentException("域名不能为空");
        }
        String ascii;
        try {
            ascii = IDN.toASCII(hostname.strip().replaceFirst("\\.$", ""), IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
            InternetDomainName parsed = InternetDomainName.from(ascii);
            if (!parsed.isUnderPublicSuffix()) {
                throw new IllegalArgumentException("无法识别可注册域名：" + hostname);
            }
            return parsed.topPrivateDomain().toString();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("域名格式或公共后缀无效：" + hostname, e);
        }
    }

    /**
     * 从 IANA Bootstrap 选择所有匹配的 HTTPS 注册局端点，按最长后缀匹配。
     * 某个端点返回 404 时尝试同一后缀的其他端点；绝不将所有域名硬编码到 .com。
     */
    private WhoisResult queryRdap(String domain, WhoisResult result) throws Exception {
        List<String> candidates = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        try {
            candidates.addAll(findBootstrapUrls(loadBootstrap(), domain));
        } catch (Exception e) {
            failures.add("IANA: " + e.getMessage());
            log.warn("读取 IANA RDAP 列表失败：{}", e.toString());
        }
        String tld = domain.substring(domain.lastIndexOf('.') + 1);
        candidates.addAll(RDAP_FALLBACK.getOrDefault(tld, List.of()));
        if (candidates.isEmpty()) {
            throw new IllegalStateException("未找到可用 RDAP 服务；" + String.join("；", failures));
        }
        for (String base : new LinkedHashSet<>(candidates)) {
            String url;
            try {
                url = rdapDomainUrl(base, domain);
                JsonNode data = getJson(url);
                if (data.has("errorCode")) {
                    throw new IllegalStateException("RDAP errorCode=" + data.path("errorCode").asText());
                }
                if (!"domain".equalsIgnoreCase(data.path("objectClassName").asText())) {
                    throw new IllegalStateException("RDAP 返回的不是域名对象");
                }
                fillRdapResult(data, domain, result);
                log.info("RDAP 查询成功：{}，地址={}", domain, url);
                return result;
            } catch (Exception e) {
                failures.add(base + " -> " + e.getMessage());
                log.warn("RDAP 端点失败：域名={}，端点={}，原因={}", domain, base, e.toString());
            }
        }
        throw new IllegalStateException(String.join("；", failures));
    }

    /** 缓存 IANA 官方数据，减少对外部服务的依赖。 */
    private synchronized JsonNode loadBootstrap() throws Exception {
        long now = System.currentTimeMillis();
        if (cachedBootstrap != null && now - bootstrapFetchedAt < BOOTSTRAP_TTL_MS) {
            return cachedBootstrap;
        }
        try {
            JsonNode fresh = getJson(BOOTSTRAP_URL);
            if (!fresh.path("services").isArray()) {
                throw new IllegalStateException("IANA 响应缺少 services 数组");
            }
            cachedBootstrap = fresh;
            bootstrapFetchedAt = now;
            return fresh;
        } catch (Exception e) {
            if (cachedBootstrap != null) {
                log.warn("IANA 刷新失败，继续使用上次成功缓存：{}", e.toString());
                return cachedBootstrap;
            }
            throw e;
        }
    }

    /** 解析 IANA services: [[后缀列表], [URL 列表]]，选择最长后缀。 */
    static List<String> findBootstrapUrls(JsonNode bootstrap, String domain) {
        int longest = -1;
        List<String> urls = new ArrayList<>();
        for (JsonNode service : bootstrap.path("services")) {
            if (!service.isArray() || service.size() < 2) continue;
            for (JsonNode suffix : service.path(0)) {
                String zone = suffix.asText().toLowerCase(Locale.ROOT).replaceFirst("^\\.", "");
                if (!domain.equals(zone) && !domain.endsWith("." + zone)) continue;
                if (zone.length() < longest) continue;
                if (zone.length() > longest) {
                    urls.clear();
                    longest = zone.length();
                }
                for (JsonNode candidate : service.path(1)) {
                    String base = candidate.asText();
                    if (base.startsWith("https://")) urls.add(base);
                }
            }
        }
        return new ArrayList<>(new LinkedHashSet<>(urls));
    }

    /** 兼容注册局返回带尾部斜杠的基础 URL，避免出现 domain/domain/。 */
    static String rdapDomainUrl(String base, String domain) {
        URI uri = URI.create(base);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("无效的 RDAP HTTPS 基础地址");
        }
        String normalized = base.endsWith("/") ? base : base + "/";
        if (normalized.endsWith("/domain/")) return normalized + domain;
        return normalized + "domain/" + domain;
    }

    /** 将不同注册局的 RDAP JSON 统一为现有页面使用的 WhoisResult。 */
    private void fillRdapResult(JsonNode data, String domain, WhoisResult result) throws Exception {
        result.setRaw(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(data));
        result.setSource("RDAP");
        result.setDomainName(data.path("ldhName").asText(domain));
        List<String> statuses = new ArrayList<>();
        data.path("status").forEach(n -> statuses.add(n.asText()));
        result.setStatuses(statuses);
        List<String> ns = new ArrayList<>();
        data.path("nameservers").forEach(n -> {
            String name = n.path("ldhName").asText("");
            if (!name.isBlank()) ns.add(name);
        });
        result.setNameServers(ns);
        for (JsonNode event : data.path("events")) {
            String action = event.path("eventAction").asText("");
            String date = event.path("eventDate").asText("");
            if (action.equalsIgnoreCase("registration")) result.setCreationDate(date);
            if (action.equalsIgnoreCase("expiration")) result.setExpiryDate(date);
        }
        completeDatesFromRaw(result);
        for (JsonNode entity : data.path("entities")) {
            for (JsonNode role : entity.path("roles")) {
                if ("registrar".equalsIgnoreCase(role.asText())) {
                    String name = vcardName(entity.path("vcardArray").path(1));
                    if (name.isBlank()) name = entity.path("handle").asText("");
                    if (!name.isBlank()) result.setRegistrar(name);
                }
            }
        }
    }

    private String vcardName(JsonNode properties) {
        for (JsonNode prop : properties) {
            if ("fn".equals(prop.path(0).asText())) return prop.path(3).asText("");
        }
        return "";
    }

    private JsonNode getJson(String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .header("Accept", "application/rdap+json, application/json")
                .header("User-Agent", "cert-manager/1.0")
                .GET().build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("URL=" + url + " HTTP=" + response.statusCode());
        }
        if (response.body().length() > 2_000_000) throw new IllegalStateException("RDAP 响应过大");
        return mapper.readTree(response.body());
    }

    /**
     * 向 Whois 服务器发送查询并读取响应文本。
     *
     * @param server Whois 服务器地址
     * @param domain 域名
     * @return 原始文本
     * @throws Exception 网络异常
     */
    private String queryRaw(String server, String domain) throws Exception {
        // 先建立连接（带连接超时），再设置读取超时，避免环境不通时长时间阻塞
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(server, 43), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);
            OutputStream os = socket.getOutputStream();
            os.write((domain + "\r\n").getBytes(StandardCharsets.UTF_8));
            os.flush();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        }
    }

    /**
     * 在 RDAP 查询成功但日期不完整时，使用传统 WHOIS 补全缺失字段。
     *
     * <p>特别是 CNNIC 的 .cn 域名，原始 WHOIS 常使用 Registration Time
     * 和 Expiration Time；不同 RDAP 注册局也可能因数据策略而省略某个事件。
     * 补充查询失败不应将已经成功的 RDAP 查询判定为失败，更不能清空已有日期。</p>
     */
    private void supplementMissingDatesFromWhois(String registrable, WhoisResult result) {
        String tld = registrable.substring(registrable.lastIndexOf('.') + 1);
        String server = WHOIS_SERVERS.get(tld);
        if (server == null) {
            return;
        }
        try {
            String whoisRaw = queryRaw(server, registrable);
            WhoisResult supplement = new WhoisResult();
            supplement.setRaw(whoisRaw);
            completeDatesFromRaw(supplement);
            if (!hasText(result.getCreationDate()) && hasText(supplement.getCreationDate())) {
                result.setCreationDate(supplement.getCreationDate());
            }
            if (!hasText(result.getExpiryDate()) && hasText(supplement.getExpiryDate())) {
                result.setExpiryDate(supplement.getExpiryDate());
            }
            // RDAP JSON 仍作为原始记录；不把 WHOIS 文本混入 JSON，避免破坏详情页展示。
            log.info("WHOIS 日期补全：域名={}，注册日期={}，到期日期={}",
                    registrable, result.getCreationDate(), result.getExpiryDate());
        } catch (Exception e) {
            log.warn("RDAP 已成功，但 WHOIS 日期补全失败：域名={}，服务器={}", registrable, server, e);
        }
    }

    /** 常见 WHOIS 日期字段；仅识别完整的键名，避免误读更新日期。 */
    private static final Pattern CREATION_FIELD = Pattern.compile(
            "(?i)^(?:Creation Date|Created(?: On| Date)?|Registered On|Registration Date|Registration Time|Domain Create Date|created-date)\\s*:\\s*(.+)$");
    private static final Pattern EXPIRY_FIELD = Pattern.compile(
            "(?i)^(?:Registry Expiry Date|Expiry Date|Expiration Date|Expires(?: On| Date)?|Registrar Registration Expiration Date|Registry Expiration Date|paid-till|expire-date|Expiration Time)\\s*:\\s*(.+)$");
    private static final List<DateTimeFormatter> LOCAL_DATE_FORMATS = List.of(
            DateTimeFormatter.ISO_LOCAL_DATE,
            DateTimeFormatter.ofPattern("uuuu/MM/dd"),
            DateTimeFormatter.ofPattern("uuuu.MM.dd"),
            new DateTimeFormatterBuilder().parseCaseInsensitive()
                    .appendPattern("dd-MMM-uuuu").toFormatter(Locale.ENGLISH)
                    .withResolverStyle(ResolverStyle.STRICT),
            new DateTimeFormatterBuilder().parseCaseInsensitive()
                    .appendPattern("MMM dd uuuu").toFormatter(Locale.ENGLISH)
                    .withResolverStyle(ResolverStyle.STRICT));

    /**
     * 统一补全日期：先规范已有字段，缺失时再从原始 WHOIS 文本或 RDAP JSON 解析。
     * CNNIC 的 Registration Time、Expiration Time 格式为 yyyy-MM-dd HH:mm:ss；
     * 只保留日期部分，统一返回 yyyy-MM-dd，不把注册局本地时间错误转换为系统时区。
     * 对于 RDAP 的 UTC 时间戳保留其原始日期部分，避免时区换算造成日期偏移。
     */
    static void completeDatesFromRaw(WhoisResult result) {
        String creation = normalizeDate(result.getCreationDate());
        String expiry = normalizeDate(result.getExpiryDate());
        String raw = result.getRaw();
        if (raw != null && (!hasText(creation) || !hasText(expiry))) {
            String trimmed = raw.stripLeading();
            if (trimmed.startsWith("{")) {
                // RDAP 的 raw 是 JSON；不应使用文本正则扫描 JSON 中的任意日期。
                try {
                    JsonNode root = new ObjectMapper().readTree(trimmed);
                    for (JsonNode event : root.path("events")) {
                        String action = event.path("eventAction").asText("");
                        String date = normalizeDate(event.path("eventDate").asText(""));
                        if (!hasText(creation) && "registration".equalsIgnoreCase(action)) creation = date;
                        if (!hasText(expiry) && "expiration".equalsIgnoreCase(action)) expiry = date;
                    }
                } catch (Exception ignored) {
                    // 原始数据可能不完整；保留已经成功解析的字段。
                }
            } else {
                for (String line : raw.split("\\R")) {
                    String value = line.trim();
                    if (!hasText(creation)) {
                        Matcher match = CREATION_FIELD.matcher(value);
                        if (match.matches()) creation = normalizeDate(match.group(1));
                    }
                    if (!hasText(expiry)) {
                        Matcher match = EXPIRY_FIELD.matcher(value);
                        if (match.matches()) expiry = normalizeDate(match.group(1));
                    }
                    if (hasText(creation) && hasText(expiry)) break;
                }
            }
        }
        result.setCreationDate(creation);
        result.setExpiryDate(expiry);
    }

    private static boolean hasText(String text) {
        return text != null && !text.isBlank();
    }

    /** 将常见注册局日期统一为 yyyy-MM-dd；无法识别时返回 null，不写入错误日期。 */
    static String normalizeDate(String value) {
        if (!hasText(value)) return null;
        String text = value.trim();
        // RFC3339、ISO8601 和带毫秒的时间：直接读取日期部分，不受本地时区影响。
        if (text.matches("^\\d{4}-\\d{2}-\\d{2}[Tt ].*")) {
            String day = text.substring(0, 10);
            try { return LocalDate.parse(day).toString(); }
            catch (DateTimeParseException ignored) { return null; }
        }
        for (DateTimeFormatter formatter : LOCAL_DATE_FORMATS) {
            try { return LocalDate.parse(text, formatter).toString(); }
            catch (DateTimeParseException ignored) { /* 尝试下一种格式 */ }
        }
        return null;
    }

    /**
     * 解析 WHOIS 文本的其他字段；日期统一交给 completeDatesFromRaw，避免被无效值覆盖。
     */
    private void parse(String raw, WhoisResult result) {
        String[] lines = raw.split("\\R");
        List<String> statuses = new ArrayList<>();
        List<String> nameServers = new ArrayList<>();
        for (String rawLine : lines) {
            String line = rawLine.trim();
            match(line, "Domain Name:", result::setDomainName);
            match(line, "Registrar:", result::setRegistrar);
            match(line, "Registrar Name:", result::setRegistrar);
            match(line, "Sponsoring Registrar:", result::setRegistrar);
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.startsWith("domain status:") || lower.startsWith("status:")) {
                statuses.add(line.substring(line.indexOf(':') + 1).trim());
            }
            if (lower.startsWith("name server:") || lower.startsWith("nserver:")) {
                nameServers.add(line.substring(line.indexOf(':') + 1).trim());
            }
        }
        result.setStatuses(statuses);
        result.setNameServers(nameServers);
    }

    /** 从单行键值字段提取非空值。 */
    private void match(String line, String prefix, Consumer<String> setter) {
        if (line.regionMatches(true, 0, prefix, 0, prefix.length())) {
            String value = line.substring(prefix.length()).trim();
            if (!value.isEmpty()) setter.accept(value);
        }
    }
}
