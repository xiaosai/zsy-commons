package io.github.zsy.commons.crypto.mask;

import java.util.*;
import java.util.regex.Pattern;

/**
 * 敏感数据脱敏工具
 * <p>
 * 支持递归脱敏嵌套的 Map、List 结构，常用于日志打印前对参数进行脱敏处理。
 *
 * <pre>{@code
 * // 使用示例
 * Map<String, Object> params = new HashMap<>();
 * params.put("phone", "13812345678");
 * params.put("user", Map.of("name", "张三", "idCard", "110101199001011234"));
 *
 * String masked = SensitiveDataMasker.mask(params);
 * // {"phone":"138****5678","user":{"name":"张***","idCard":"1101********1234"}}
 * }</pre>
 *
 * @author zsy
 */
public final class SensitiveDataMasker {

    private SensitiveDataMasker() {
    }

    /**
     * 默认敏感字段名（小写）
     */
    private static final Set<String> DEFAULT_SENSITIVE_FIELDS = Set.of(
            // 身份证
            "idcard", "id_card", "idcardno", "idcardnumber", "idno", "id_no", "idnumber",
            // 手机号
            "phone", "mobile", "phonenumber", "phone_number", "mobilephone", "tel",
            // 姓名
            "name", "username", "user_name", "realname", "real_name", "truename", "true_name",
            "passengername", "passenger_name", "contactname", "contact_name",
            // 银行卡
            "bankcard", "bank_card", "bankcardno", "bankcardnumber", "bankaccount",
            // 邮箱
            "email", "emailaddress",
            // 密码
            "password", "pwd", "passwd",
            // 地址
            "address", "addr"
    );

    /**
     * 自定义敏感字段（可通过 {@link #addSensitiveFields(String...)} 添加）
     */
    private static final Set<String> CUSTOM_SENSITIVE_FIELDS = new HashSet<>();

    /**
     * 手机号正则：1开头11位数字
     */
    private static final Pattern PHONE_PATTERN = Pattern.compile("^1[3-9]\\d{9}$");

    /**
     * 身份证正则：15位或18位
     */
    private static final Pattern ID_CARD_PATTERN = Pattern.compile("^\\d{15}(\\d{2}[0-9Xx])?$");

    /**
     * 银行卡正则：16-19位数字
     */
    private static final Pattern BANK_CARD_PATTERN = Pattern.compile("^\\d{16,19}$");

    /**
     * 邮箱正则
     */
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[\\w.-]+@[\\w.-]+\\.\\w+$");

    /**
     * 添加自定义敏感字段名
     *
     * @param fields 字段名（不区分大小写）
     */
    public static void addSensitiveFields(String... fields) {
        for (String field : fields) {
            CUSTOM_SENSITIVE_FIELDS.add(field.toLowerCase());
        }
    }

    /**
     * 清空自定义敏感字段
     */
    public static void clearCustomFields() {
        CUSTOM_SENSITIVE_FIELDS.clear();
    }

    /**
     * 脱敏 Map 参数（返回 JSON 字符串）
     *
     * @param params 原始参数
     * @return 脱敏后的 JSON 字符串
     */
    public static String mask(Map<String, Object> params) {
        if (params == null) {
            return "{}";
        }
        Map<String, Object> copy = deepCopy(params);
        sanitizeMap(copy);
        return toJson(copy);
    }

    /**
     * 脱敏 List 参数（返回 JSON 字符串）
     *
     * @param list 原始列表
     * @return 脱敏后的 JSON 字符串
     */
    public static String mask(List<Object> list) {
        if (list == null) {
            return "[]";
        }
        List<Object> copy = deepCopyList(list);
        sanitizeList(copy);
        return toJson(copy);
    }

    /**
     * 脱敏任意对象（返回 JSON 字符串）
     *
     * @param obj 原始对象
     * @return 脱敏后的 JSON 字符串
     */
    public static String mask(Object obj) {
        if (obj == null) {
            return "null";
        }
        if (obj instanceof Map) {
            return mask((Map<String, Object>) obj);
        }
        if (obj instanceof List) {
            return mask((List<Object>) obj);
        }
        return toJson(obj);
    }

    /**
     * 直接脱敏字符串值（根据内容自动识别类型）
     *
     * @param value 原始值
     * @return 脱敏后的值
     */
    public static String maskValue(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        return autoMask(value);
    }

    // ==================== 内部方法 ====================

    /**
     * 递归脱敏 Map
     */
    @SuppressWarnings("unchecked")
    private static void sanitizeMap(Map<String, Object> map) {
        if (map == null) {
            return;
        }

        map.forEach((key, value) -> {
            if (value == null) {
                return;
            }
            String lowerKey = key.toLowerCase();
            if (isSensitiveField(lowerKey)) {
                // 敏感字段脱敏
                map.put(key, maskByType(value.toString(), lowerKey));
            } else if (value instanceof Map) {
                sanitizeMap((Map<String, Object>) value);
            } else if (value instanceof List) {
                sanitizeList((List<Object>) value);
            }
        });
    }

    /**
     * 递归脱敏 List
     */
    @SuppressWarnings("unchecked")
    private static void sanitizeList(List<Object> list) {
        if (list == null) {
            return;
        }

        for (int i = 0; i < list.size(); i++) {
            Object item = list.get(i);
            if (item instanceof Map) {
                sanitizeMap((Map<String, Object>) item);
            } else if (item instanceof List) {
                sanitizeList((List<Object>) item);
            }
        }
    }

    /**
     * 判断是否为敏感字段
     */
    private static boolean isSensitiveField(String lowerKey) {
        return DEFAULT_SENSITIVE_FIELDS.contains(lowerKey) || CUSTOM_SENSITIVE_FIELDS.contains(lowerKey);
    }

    /**
     * 根据字段类型选择脱敏策略
     */
    private static String maskByType(String value, String lowerKey) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        // 根据字段名推断类型
        if (isPhoneField(lowerKey) || PHONE_PATTERN.matcher(value).matches()) {
            return maskPhone(value);
        }
        if (isIdCardField(lowerKey) || ID_CARD_PATTERN.matcher(value).matches()) {
            return maskIdCard(value);
        }
        if (isBankCardField(lowerKey) || BANK_CARD_PATTERN.matcher(value).matches()) {
            return maskBankCard(value);
        }
        if (isEmailField(lowerKey) || EMAIL_PATTERN.matcher(value).matches()) {
            return maskEmail(value);
        }
        if (isNameField(lowerKey)) {
            return maskName(value);
        }
        if (isPasswordField(lowerKey)) {
            return "******";
        }

        // 默认：保留首尾各2位
        return maskDefault(value);
    }

    /**
     * 自动识别并脱敏（用于无字段名场景）
     */
    private static String autoMask(String value) {
        if (PHONE_PATTERN.matcher(value).matches()) {
            return maskPhone(value);
        }
        if (ID_CARD_PATTERN.matcher(value).matches()) {
            return maskIdCard(value);
        }
        if (BANK_CARD_PATTERN.matcher(value).matches()) {
            return maskBankCard(value);
        }
        if (EMAIL_PATTERN.matcher(value).matches()) {
            return maskEmail(value);
        }
        return value;
    }

    // ==================== 具体脱敏策略 ====================

    /**
     * 手机号脱敏：138****5678
     */
    private static String maskPhone(String phone) {
        if (phone == null || phone.length() < 7) {
            return phone;
        }
        return phone.substring(0, 3) + "****" + phone.substring(phone.length() - 4);
    }

    /**
     * 身份证脱敏：1101********1234
     */
    private static String maskIdCard(String idCard) {
        if (idCard == null || idCard.length() < 8) {
            return idCard;
        }
        int len = idCard.length();
        return idCard.substring(0, 4) + "********" + idCard.substring(len - 4);
    }

    /**
     * 银行卡脱敏：6222****1234
     */
    private static String maskBankCard(String bankCard) {
        if (bankCard == null || bankCard.length() < 8) {
            return bankCard;
        }
        return bankCard.substring(0, 4) + "****" + bankCard.substring(bankCard.length() - 4);
    }

    /**
     * 姓名脱敏：张*** （统一保留首字符，后面用 *** 替代）
     */
    private static String maskName(String name) {
        if (name == null || name.isEmpty()) {
            return name;
        }
        if (name.length() == 1) {
            return name + "***";
        }
        return name.charAt(0) + "***";
    }

    /**
     * 邮箱脱敏：a***@example.com
     */
    private static String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return email;
        }
        int atIndex = email.indexOf("@");
        if (atIndex <= 1) {
            return email;
        }
        return email.charAt(0) + "***" + email.substring(atIndex);
    }

    /**
     * 默认脱敏：保留首尾各2位
     */
    private static String maskDefault(String value) {
        if (value == null || value.length() <= 4) {
            return "****";
        }
        return value.substring(0, 2) + "****" + value.substring(value.length() - 2);
    }

    // ==================== 字段类型判断 ====================

    private static boolean isPhoneField(String lowerKey) {
        return lowerKey.contains("phone") || lowerKey.contains("mobile") || lowerKey.equals("tel");
    }

    private static boolean isIdCardField(String lowerKey) {
        return lowerKey.contains("idcard") || lowerKey.contains("id_no") || lowerKey.contains("idno");
    }

    private static boolean isBankCardField(String lowerKey) {
        return lowerKey.contains("bankcard") || lowerKey.contains("bank_account");
    }

    private static boolean isEmailField(String lowerKey) {
        return lowerKey.contains("email");
    }

    private static boolean isNameField(String lowerKey) {
        return lowerKey.equals("name") || lowerKey.contains("name") && !lowerKey.contains("user");
    }

    private static boolean isPasswordField(String lowerKey) {
        return lowerKey.contains("password") || lowerKey.equals("pwd") || lowerKey.equals("passwd");
    }

    // ==================== 深拷贝 & JSON ====================

    /**
     * 深拷贝 Map（使用 JSON 序列化/反序列化）
     * 注意：这里使用简单的 JSON 实现，实际项目中建议使用 Jackson/Gson
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> deepCopy(Map<String, Object> original) {
        if (original == null) {
            return null;
        }
        // 简单实现：构造新的 LinkedHashMap
        Map<String, Object> copy = new LinkedHashMap<>(original.size());
        original.forEach((k, v) -> {
            if (v instanceof Map) {
                copy.put(k, deepCopy((Map<String, Object>) v));
            } else if (v instanceof List) {
                copy.put(k, deepCopyList((List<Object>) v));
            } else {
                copy.put(k, v);
            }
        });
        return copy;
    }

    /**
     * 深拷贝 List
     */
    @SuppressWarnings("unchecked")
    private static List<Object> deepCopyList(List<Object> original) {
        if (original == null) {
            return null;
        }
        List<Object> copy = new ArrayList<>(original.size());
        for (Object item : original) {
            if (item instanceof Map) {
                copy.add(deepCopy((Map<String, Object>) item));
            } else if (item instanceof List) {
                copy.add(deepCopyList((List<Object>) item));
            } else {
                copy.add(item);
            }
        }
        return copy;
    }

    /**
     * 转换为 JSON 字符串（简单实现）
     * 注意：建议在 zsy-commons-json 模块中提供 Jackson 实现
     */
    private static String toJson(Object obj) {
        if (obj == null) {
            return "null";
        }
        if (obj instanceof Map) {
            return mapToJson((Map<String, Object>) obj);
        }
        if (obj instanceof List) {
            return listToJson((List<Object>) obj);
        }
        if (obj instanceof String) {
            return "\"" + escapeJson((String) obj) + "\"";
        }
        if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        }
        return "\"" + escapeJson(obj.toString()) + "\"";
    }

    private static String mapToJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            sb.append("\"").append(escapeJson(entry.getKey())).append("\":");
            sb.append(toJson(entry.getValue()));
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    private static String listToJson(List<Object> list) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                sb.append(",");
            }
            sb.append(toJson(item));
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
