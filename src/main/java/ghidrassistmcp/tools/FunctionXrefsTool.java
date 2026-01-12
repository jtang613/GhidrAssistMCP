/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets cross-references for a specific function.
 */
public class FunctionXrefsTool implements McpTool {
    
    @Override
    public String getName() {
        return "function_xrefs";
    }
    
    @Override
    public String getDescription() {
        return "Get cross-references to and from a specific function";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "function_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "direction", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of("function_name"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String functionName = (String) arguments.get("function_name");
        String direction = (String) arguments.get("direction"); // "to", "from", or "both"
        
        if (functionName == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function_name parameter is required")
                .build();
        }
        
        // Parse optional parameters
        int offset = 0;
        int limit = 100; // Default limit
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        
        if (direction == null) {
            direction = "both"; // Default to both directions
        }
        
        // Find the function
        Function function = findFunctionByName(currentProgram, functionName);
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
        if ("to".equals(direction) || "both".equals(direction)) {
            result.append("=== References TO function (callers) ===\n");
            Set<Function> callingFunctions = function.getCallingFunctions(null);
            
            for (Function callerFunc : callingFunctions) {
                totalCount++;
                
                // Apply offset
                if (totalCount <= offset) {
                    continue;
                }
                
                // Apply limit
                if (count >= limit) {
                    break;
                }
                
                result.append("- ").append(callerFunc.getEntryPoint())
                      .append(" (").append(callerFunc.getName()).append(")\n");
                count++;
            }
            
            if (callingFunctions.isEmpty()) {
                result.append("No callers found.\n");
            }
            result.append("\n");
        }
        
        // Get XREFs FROM the function (callees)
        if ("from".equals(direction) || "both".equals(direction)) {
            result.append("=== References FROM function (callees) ===\n");
            Set<Function> calledFunctions = function.getCalledFunctions(null);
            
            for (Function calledFunc : calledFunctions) {
                if (count >= limit) {
                    break;
                }
                
                totalCount++;
                
                // Apply offset (continue from previous count)
                if (totalCount <= offset) {
                    continue;
                }
                
                result.append("- ").append(calledFunc.getEntryPoint())
                      .append(" (").append(calledFunc.getName()).append(")\n");
                count++;
            }
            
            if (calledFunctions.isEmpty()) {
                result.append("No called functions found.\n");
            }
        }
        
        if (totalCount == 0) {
            result.append("No cross-references found for function: ").append(functionName);
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" references");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }
    
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

    @Override
    public boolean isReadOnly() {
        return true;
    }
}