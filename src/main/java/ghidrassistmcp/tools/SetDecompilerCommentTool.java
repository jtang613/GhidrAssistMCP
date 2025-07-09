/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that sets a comment on a function (appears in decompiler).
 */
public class SetDecompilerCommentTool implements McpTool {
    
    @Override
    public String getName() {
        return "set_decompiler_comment";
    }
    
    @Override
    public String getDescription() {
        return "Set a comment on a function (appears in decompiler view)";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "function_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "comment", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("function_name", "comment"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String functionName = (String) arguments.get("function_name");
        String comment = (String) arguments.get("comment");
        
        if (functionName == null || comment == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function_name and comment parameters are required")
                .build();
        }
        
        // Find the function
        Function function = findFunctionByName(currentProgram, functionName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionName)
                .build();
        }
        
        try {
            // Set the function comment (appears in decompiler)
            function.setComment(comment);
            
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully set decompiler comment on function '" + functionName + 
                              "': \"" + comment + "\"")
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error setting function comment: " + e.getMessage())
                .build();
        }
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
}