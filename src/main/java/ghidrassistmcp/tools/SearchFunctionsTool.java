/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that searches for functions by name pattern.
 */
public class SearchFunctionsTool implements McpTool {
    
    @Override
    public String getName() {
        return "search_functions";
    }
    
    @Override
    public String getDescription() {
        return "Search for functions by name pattern (supports partial matching)";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "pattern", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "case_sensitive", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
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
        if (pattern == null || pattern.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("pattern parameter is required")
                .build();
        }
        
        // Parse optional parameters
        boolean caseSensitive = true;
        if (arguments.get("case_sensitive") instanceof Boolean) {
            caseSensitive = (Boolean) arguments.get("case_sensitive");
        }
        
        int offset = 0;
        int limit = 100; // Default limit
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Functions matching pattern: \"").append(pattern).append("\"");
        result.append(" (case ").append(caseSensitive ? "sensitive" : "insensitive").append(")\n\n");
        
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        
        int count = 0;
        int totalCount = 0;
        String searchPattern = caseSensitive ? pattern : pattern.toLowerCase();
        
        while (functions.hasNext()) {
            Function function = functions.next();
            String functionName = caseSensitive ? function.getName() : function.getName().toLowerCase();
            
            // Check if the function name contains the pattern
            if (functionName.contains(searchPattern)) {
                totalCount++;
                
                // Apply offset
                if (totalCount <= offset) {
                    continue;
                }
                
                // Apply limit
                if (count >= limit) {
                    break;
                }
                
                result.append("- ").append(function.getName())
                      .append(" @ ").append(function.getEntryPoint())
                      .append(" (").append(function.getParameterCount()).append(" params)")
                      .append("\n");
                
                count++;
            }
        }
        
        if (totalCount == 0) {
            result.append("No functions found matching pattern: \"").append(pattern).append("\"");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" matching functions");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }
}