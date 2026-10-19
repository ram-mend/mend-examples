package com.example;

import com.example.lib.JsonUtil;
import com.thoughtworks.xstream.XStream;

/**
 * Calls two vulnerable libraries, for Mend's reachability analysis: xstream
 * directly, and the Jackson that parquet-jackson bundles, only through lib's
 * JsonUtil. It never imports Jackson itself.
 */
public class App {
    public static void main(String[] args) throws Exception {
        Object xml = new XStream().fromXML("<string>hello</string>");
        System.out.println(xml + " " + JsonUtil.value("{\"value\": 1.5}"));
    }
}
