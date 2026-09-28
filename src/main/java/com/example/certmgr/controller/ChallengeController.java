package com.example.certmgr.controller;

import com.example.certmgr.config.CertProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * ACME HTTP-01 验证文件服务控制器。
 *
 * <p>ACME 签发时，CA 会访问 {@code http://域名/.well-known/acme-challenge/<token>}
 * 以获取验证文件。本控制器将其从配置的 webroot 目录对外提供，
 * 使本系统自身即可完成 HTTP-01 校验（前提是 80 端口请求到达本应用）。</p>
 */
@Controller
@RequiredArgsConstructor
public class ChallengeController {

    /** 自定义配置（webroot 路径） */
    private final CertProperties certProperties;

    /**
     * 提供指定 token 的验证文件内容。
     *
     * @param token 验证 token
     * @return 文件内容（纯文本）或 404
     * @throws IOException 读取异常
     */
    @GetMapping(value = "/.well-known/acme-challenge/{token}", produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public ResponseEntity<String> serve(@PathVariable String token) throws IOException {
        // 防止路径遍历：token 仅允许字母数字与连字符/下划线
        if (token == null || !token.matches("[A-Za-z0-9_-]{1,256}")) {
            return ResponseEntity.notFound().build();
        }
        Path file = Paths.get(certProperties.getAcme().getWebroot(),
                ".well-known", "acme-challenge", token);
        if (!Files.exists(file)) {
            return ResponseEntity.notFound().build();
        }
        String content = Files.readString(file);
        return ResponseEntity.ok(content);
    }
}
