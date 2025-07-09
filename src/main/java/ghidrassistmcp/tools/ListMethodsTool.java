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
 * MCP tool that lists all methods/functions in the program.
 */
public class ListMethodsTool implements McpTool {
    
    @Override
    public String getName() {
        return "list_methods";
    }
    
    @Override
    public String getDescription() {
        return "List all methods/functions in the program";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of(), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        // Parse optional offset and limit
        int offset = 0;
        int limit = 100; // Default limit
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Methods/Functions in program:\n\n");
        
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        
        int count = 0;
        int totalCount = 0;
        
        while (functions.hasNext()) {
            Function function = functions.next();
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
        
        if (totalCount == 0) {
            result.append("No functions found in the program.");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" functions");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }
}