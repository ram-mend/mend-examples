package com.example;

import com.thoughtworks.xstream.XStream;
import shaded.parquet.com.fasterxml.jackson.databind.JsonNode;
import shaded.parquet.com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Calls two vulnerable libraries, for Mend's reachability analysis: xstream
 * directly, and the Jackson that parquet-jackson bundles, through its
 * relocated packages. It never imports com.fasterxml, so only the bundled
 * copies are reached.
 */
public class App {
    public static void main(String[] args) throws Exception {
        Object xml = new XStream().fromXML("<string>hello</string>");
        JsonNode json = new ObjectMapper().readTree("{\"value\": 1.5}");
        System.out.println(xml + " " + json.get("value").asDouble());
    }
}
