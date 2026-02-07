/*
 * MCP tool for getting cross-references to/from an address or function.
 * Consolidates xrefs_to, xrefs_from, and function_xrefs into a single tool.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets cross-references to and/or from an address or function.
 * Replaces separate xrefs_to, xrefs_from, and function_xrefs tools.
 */
public class XrefsTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "xrefs";
    }

    @Override
    public String getDescription() {
        return "Get cross-references to/from an address or function (direction: to, from, or both)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", Map.of(
                    "type", "string",
                    "description", "Optional: address to find xrefs for (either address or function must be provided)"
                ),
                "function", Map.of(
                    "type", "string",
                    "description", "Optional: function name to find callers/callees xrefs for (either address or function must be provided)"
                ),
                "direction", Map.of(
                    "type", "string",
                    "description", "Direction of cross-references to return",
                    "enum", List.of("to", "from", "both"),
                    "default", "both"
                ),
                "limit", Map.of(
                    "type", "integer",
                    "description", "Maximum number of references to return (default 100)"
                )
            ),
            List.of(), null, null, null);  // Neither address nor function is strictly required, but one must be provided
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String addressStr = (String) arguments.get("address");
        String functionName = (String) arguments.get("function");
        String direction = (String) arguments.get("direction");
        int limit = 100;

        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        if (direction == null || direction.isEmpty()) {
            direction = "both";
        }
        direction = direction.toLowerCase();

        if (!direction.equals("to") && !direction.equals("from") && !direction.equals("both")) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid direction. Use 'to', 'from', or 'both'")
                .build();
        }

        // Check that at least one of address or function is provided
        if ((addressStr == null || addressStr.isEmpty()) && (functionName == null || functionName.isEmpty())) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either 'address' or 'function' parameter is required")
                .build();
        }

        // If function is provided, use function-based xrefs
        if (functionName != null && !functionName.isEmpty()) {
            return getFunctionXrefs(currentProgram, functionName, direction, limit);
        }

        // Otherwise, use address-based xrefs
        return getAddressXrefs(currentProgram, addressStr, direction, limit);
    }

    /**
     * Get cross-references for an address.
     */
    private McpSchema.CallToolResult getAddressXrefs(Program program, String addressStr, String direction, int limit) {
        // Parse the address
        Address address;
        try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address: " + addressStr)
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error parsing address: " + e.getMessage())
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Cross-references for ").append(addressStr).append(":\n\n");

        // Get references TO this address
        if (direction.equals("to") || direction.equals("both")) {
            result.append("## References TO this address:\n");
            ReferenceIterator refsTo = program.getReferenceManager().getReferencesTo(address);
            int count = 0;

            while (refsTo.hasNext() && count < limit) {
                Reference ref = refsTo.next();
                result.append("  - From: ").append(ref.getFromAddress())
                      .append(" (").append(ref.getReferenceType()).append(")\n");
                count++;
            }

            if (count == 0) {
                result.append("  No references found.\n");
            } else if (count >= limit) {
                result.append("  ... (limited to ").append(limit).append(" results)\n");
            }
            result.append("\n");
        }

        // Get references FROM this address
        if (direction.equals("from") || direction.equals("both")) {
            result.append("## References FROM this address:\n");
            Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(address);
            int count = 0;

            for (Reference ref : refsFrom) {
                if (count >= limit) break;
                result.append("  - To: ").append(ref.getToAddress())
                      .append(" (").append(ref.getReferenceType()).append(")\n");
                count++;
            }

            if (count == 0) {
                result.append("  No references found.\n");
            } else if (count >= limit) {
                result.append("  ... (limited to ").append(limit).append(" results)\n");
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Get cross-references for a function (callers and callees).
     */
    private McpSchema.CallToolResult getFunctionXrefs(Program program, String functionName, String direction, int limit) {
        // Find the function
        Function function = findFunctionByName(program, functionName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionName)
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Cross-references for function: ").append(functionName).append("\n");
        result.append("Entry Point: ").append(function.getEntryPoint()).append("\n\n");

        int totalCount = 0;
        int count = 0;

        // Get XREFs TO the function (callers)
        if (direction.equals("to") || direction.equals("both")) {
            result.append("## References TO function (callers):\n");
            Set<Function> callingFunctions = function.getCallingFunctions(null);

            for (Function callerFunc : callingFunctions) {
                if (count >= limit) {
                    break;
                }

                result.append("  - ").append(callerFunc.getEntryPoint())
                      .append(" (").append(callerFunc.getName()).append(")\n");
                count++;
                totalCount++;
            }

            if (callingFunctions.isEmpty()) {
                result.append("  No callers found.\n");
            } else if (count >= limit) {
                result.append("  ... (limited to ").append(limit).append(" results)\n");
            }
            result.append("\n");
        }

        // Get XREFs FROM the function (callees)
        if (direction.equals("from") || direction.equals("both")) {
            result.append("## References FROM function (callees):\n");
            Set<Function> calledFunctions = function.getCalledFunctions(null);

            int calleeCount = 0;
            for (Function calledFunc : calledFunctions) {
                if (calleeCount >= limit) {
                    break;
                }

                result.append("  - ").append(calledFunc.getEntryPoint())
                      .append(" (").append(calledFunc.getName()).append(")\n");
                calleeCount++;
                totalCount++;
            }

            if (calledFunctions.isEmpty()) {
                result.append("  No called functions found.\n");
            } else if (calleeCount >= limit) {
                result.append("  ... (limited to ").append(limit).append(" results)\n");
            }
        }

        if (totalCount == 0) {
            result.append("No cross-references found for function: ").append(functionName);
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Find a function by name.
     */
    private Function findFunctionByName(Program program, String functionName) {
        var functionManager = program.getFunctionManager();
        var functions = functionManager.getFunctions(true);

        for (Function function : functions) {
            if (function.getName().equals(functionName)) {
                return function;
            }
        }
        return null;
    }
}
