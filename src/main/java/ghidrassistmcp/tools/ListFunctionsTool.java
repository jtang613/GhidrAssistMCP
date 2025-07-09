/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists all functions in the currently loaded program.
 */
public class ListFunctionsTool implements McpTool {
    
    @Override
    public String getName() {
        return "list_functions";
    }
    
    @Override
    public String getDescription() {
        return "List all functions in the current program";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(), List.of(), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String functions = listFunctions(currentProgram);
        return McpSchema.CallToolResult.builder()
            .addTextContent(functions)
            .build();
    }
    
    private String listFunctions(Program program) {
        StringBuilder functions = new StringBuilder();
        functions.append("Functions in program:\n");
        
        program.getFunctionManager().getFunctions(true).forEach(function -> {
            functions.append("- ").append(function.getName())
                    .append(" @ ").append(function.getEntryPoint())
                    .append("\n");
        });
        
        return functions.toString();
    }
}