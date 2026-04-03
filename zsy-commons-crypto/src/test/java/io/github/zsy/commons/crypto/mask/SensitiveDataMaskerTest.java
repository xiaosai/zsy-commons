package io.github.zsy.commons.crypto.mask;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SensitiveDataMasker 测试
 */
class SensitiveDataMaskerTest {

    @Test
    void testMaskPhone() {
        Map<String, Object> params = Map.of(
                "phone", "13812345678",
                "orderId", "123456"
        );

        String result = SensitiveDataMasker.mask(params);

        System.out.println("手机号脱敏结果: " + result);
        assertTrue(result.contains("138****5678"));
        assertTrue(result.contains("123456"));
    }

    @Test
    void testMaskIdCard() {
        Map<String, Object> params = Map.of(
                "idCard", "110101199001011234",
                "name", "张三"
        );

        String result = SensitiveDataMasker.mask(params);

        System.out.println("身份证脱敏结果: " + result);
        assertTrue(result.contains("1101********1234"));
        assertTrue(result.contains("张***"));
    }

    @Test
    void testMaskNestedMap() {
        Map<String, Object> user = Map.of(
                "name", "张三",
                "phone", "13812345678",
                "idCard", "110101199001011234"
        );
        Map<String, Object> params = Map.of(
                "orderId", "123",
                "user", user
        );

        String result = SensitiveDataMasker.mask(params);

        System.out.println("嵌套Map脱敏结果: " + result);
        assertTrue(result.contains("\"orderId\":\"123\""));
        assertTrue(result.contains("138****5678"));
        assertTrue(result.contains("张***"));
    }

    @Test
    void testMaskList() {
        Map<String, Object> passenger1 = Map.of("name", "李四", "phone", "13912345678");
        Map<String, Object> passenger2 = Map.of("name", "王五", "phone", "13712345678");
        Map<String, Object> params = Map.of(
                "orderId", "123",
                "passengers", List.of(passenger1, passenger2)
        );

        String result = SensitiveDataMasker.mask(params);

        System.out.println("List脱敏结果: " + result);
        assertTrue(result.contains("139****5678"));
        assertTrue(result.contains("137****5678"));
        assertTrue(result.contains("李***"));
        assertTrue(result.contains("王***"));
    }

    @Test
    void testMaskComplexNested() {
        // 构建复杂嵌套结构
        Map<String, Object> user = new java.util.LinkedHashMap<>();
        user.put("name", "张三");
        user.put("phone", "13812345678");
        user.put("idCard", "110101199001011234");

        Map<String, Object> passenger1 = new java.util.LinkedHashMap<>();
        passenger1.put("name", "李四");
        passenger1.put("phone", "13912345678");

        Map<String, Object> passenger2 = new java.util.LinkedHashMap<>();
        passenger2.put("name", "王五");
        passenger2.put("phone", "13712345678");
        passenger2.put("idNo", "320102199205152345");

        Map<String, Object> params = new java.util.LinkedHashMap<>();
        params.put("orderId", "123");
        params.put("user", user);
        params.put("passengers", List.of(passenger1, passenger2));
        params.put("bankCard", "6222021234567890123");
        params.put("email", "zhangsan@example.com");

        String result = SensitiveDataMasker.mask(params);

        System.out.println("复杂嵌套脱敏结果:");
        System.out.println(result);

        // 验证各字段脱敏正确
        assertTrue(result.contains("138****5678"));      // 手机
        assertTrue(result.contains("1101********1234")); // 身份证
        assertTrue(result.contains("张***"));            // 姓名
        assertTrue(result.contains("139****5678"));      // 乘客手机
        assertTrue(result.contains("6222****0123"));     // 银行卡
        assertTrue(result.contains("z***@example.com")); // 邮箱
    }

    @Test
    void testMaskNull() {
        assertEquals("{}", SensitiveDataMasker.mask((Map<String, Object>) null));
        assertEquals("[]", SensitiveDataMasker.mask((List<Object>) null));
        assertEquals("null", SensitiveDataMasker.mask((Object) null));
    }

    @Test
    void testMaskValue() {
        // 手机号
        assertEquals("138****5678", SensitiveDataMasker.maskValue("13812345678"));

        // 身份证
        assertEquals("1101********1234", SensitiveDataMasker.maskValue("110101199001011234"));

        // 银行卡
        assertEquals("6222****0123", SensitiveDataMasker.maskValue("6222021234567890123"));

        // 邮箱
        assertEquals("z***@example.com", SensitiveDataMasker.maskValue("zhangsan@example.com"));

        // 普通字符串（不符合任何模式，原样返回）
        assertEquals("hello", SensitiveDataMasker.maskValue("hello"));
    }

    @Test
    void testAddCustomFields() {
        SensitiveDataMasker.addSensitiveFields("mySecret", "customField");

        Map<String, Object> params = Map.of(
                "mySecret", "secretValue123",
                "customField", "customValue456",
                "normalField", "normalValue"
        );

        String result = SensitiveDataMasker.mask(params);

        System.out.println("自定义字段脱敏结果: " + result);

        // 清理自定义字段
        SensitiveDataMasker.clearCustomFields();
    }

    @Test
    void testPassword() {
        Map<String, Object> params = Map.of(
                "username", "admin",
                "password", "MyP@ssw0rd123"
        );

        String result = SensitiveDataMasker.mask(params);

        System.out.println("密码脱敏结果: " + result);
        assertTrue(result.contains("******"));
        assertFalse(result.contains("MyP@ssw0rd123"));
    }

    @Test
    void testOriginalDataUnchanged() {
        // 验证原始数据不被修改
        Map<String, Object> user = new java.util.LinkedHashMap<>();
        user.put("phone", "13812345678");

        Map<String, Object> params = new java.util.LinkedHashMap<>();
        params.put("user", user);

        SensitiveDataMasker.mask(params);

        // 原始数据应该保持不变
        assertEquals("13812345678", user.get("phone"));
    }
}
