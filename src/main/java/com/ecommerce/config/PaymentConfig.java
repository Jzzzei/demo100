package com.ecommerce.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import lombok.Data;
import java.math.BigDecimal;

@Data
@Configuration
@ConfigurationProperties(prefix = "payment")
public class PaymentConfig {
    private int timeoutSeconds = 300; // 默认5分钟超时
    private BigDecimal maxAmount = new BigDecimal("50000"); // 默认最大支付金额
    private int maxRetries = 3; // 最大重试次数
} 