package com.example.lib;

import shaded.parquet.com.fasterxml.jackson.databind.JsonNode;
import shaded.parquet.com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Reads JSON with the Jackson that parquet-jackson bundles, for Mend's
 * reachability analysis. It calls Jackson through the relocated packages only
 * and never imports com.fasterxml, so only the bundled copies are reached.
 */
public class JsonUtil {
    public static double value(String json) throws Exception {
        JsonNode node = new ObjectMapper().readTree(json);
        return node.get("value").asDouble();
    }
}
