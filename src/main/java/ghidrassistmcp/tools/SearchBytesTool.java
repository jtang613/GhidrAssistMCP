/*
 * MCP tool for searching byte patterns in memory.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that searches for byte patterns in program memory.
 */
public class SearchBytesTool implements McpTool {

    @Override
    public String getName() {
        return "search_bytes";
    }

    @Override
    public String getDescription() {
        return "Search for byte patterns in program memory (hex string with optional wildcards '??')";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "pattern", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of("pattern"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String pattern = (String) arguments.get("pattern");
        int limit = 100;

        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        if (pattern == null || pattern.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Pattern is required")
                .build();
        }

        // Parse the pattern (hex string with optional wildcards)
        byte[] searchBytes;
        byte[] searchMask;
        try {
            ParsedPattern parsed = parsePattern(pattern);
            searchBytes = parsed.bytes;
            searchMask = parsed.mask;
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid pattern format: " + e.getMessage() +
                    "\nExpected hex bytes like '48 8b c1' or '48 ?? c1' for wildcards")
                .build();
        }

        Memory memory = currentProgram.getMemory();
        List<Address> matches = new ArrayList<>();

        StringBuilder result = new StringBuilder();
        result.append("Searching for pattern: ").append(pattern).append("\n");
        result.append("Pattern length: ").append(searchBytes.length).append(" bytes\n\n");

        // Search through all memory blocks
        try {
            Address startAddr = memory.getMinAddress();
            Address endAddr = memory.getMaxAddress();

            if (startAddr == null || endAddr == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No memory to search")
                    .build();
            }

            Address addr = startAddr;
            while (addr != null && matches.size() < limit) {
                addr = memory.findBytes(addr, endAddr, searchBytes, searchMask, true, null);
                if (addr != null) {
                    matches.add(addr);
                    addr = addr.add(1); // Move past this match
                }
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error during search: " + e.getMessage())
                .build();
        }

        result.append("Found ").append(matches.size()).append(" matches");
        if (matches.size() >= limit) {
            result.append(" (limited to ").append(limit).append(")");
        }
        result.append(":\n\n");

        for (Address match : matches) {
            result.append("  ").append(match);

            // Try to get function context
            var func = currentProgram.getFunctionManager().getFunctionContaining(match);
            if (func != null) {
                result.append(" in ").append(func.getName());
            }
            result.append("\n");
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private static class ParsedPattern {
        byte[] bytes;
        byte[] mask;
    }

    private ParsedPattern parsePattern(String pattern) throws Exception {
        // Remove common separators and normalize
        pattern = pattern.replaceAll("[\\s,]", "");

        if (pattern.length() % 2 != 0) {
            throw new Exception("Pattern must have even number of hex characters");
        }

        int length = pattern.length() / 2;
        byte[] bytes = new byte[length];
        byte[] mask = new byte[length];

        for (int i = 0; i < length; i++) {
            String byteStr = pattern.substring(i * 2, i * 2 + 2);

            if (byteStr.equals("??") || byteStr.equals("**")) {
                // Wildcard
                bytes[i] = 0;
                mask[i] = 0;
            } else {
                try {
                    bytes[i] = (byte) Integer.parseInt(byteStr, 16);
                    mask[i] = (byte) 0xFF;
                } catch (NumberFormatException e) {
                    throw new Exception("Invalid hex byte: " + byteStr);
                }
            }
        }

        ParsedPattern result = new ParsedPattern();
        result.bytes = bytes;
        result.mask = mask;
        return result;
    }
}
