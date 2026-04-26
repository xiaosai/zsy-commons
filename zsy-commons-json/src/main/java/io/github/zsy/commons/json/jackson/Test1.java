package io.github.zsy.commons.json.jackson;

import java.util.HashMap;

/**
 * @author zhangsaiyong
 * Created on 2026-04-24
 */
public class Test1 {
    public static void main(String[] args) {
        HashMap<String, Integer> h = new HashMap<>();
        h.put("zhangsan", 18);
        h.put("lisi", 80);

        System.out.println("test : h:" + h);
        System.out.println("test : h:" + h);
    }
}
