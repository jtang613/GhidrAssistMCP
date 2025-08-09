/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that renames a function.
 */
public class RenameFunctionTool implements McpTool {
    
    @Override
    public String getName() {
        return "rename_function";
    }
    
    @Override
    public String getDescription() {
        return "Rename an existing function";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "old_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "new_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("old_name", "new_name"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String oldName = (String) arguments.get("old_name");
        String newName = (String) arguments.get("new_name");
        
        if (oldName == null || newName == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Both old_name and new_name are required")
                .build();
        }
        
        // Find the function by old name
        Function function = findFunctionByName(currentProgram, oldName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + oldName)
                .build();
        }
        
        // Check if new name already exists
        Function existingFunction = findFunctionByName(currentProgram, newName);
        if (existingFunction != null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function with name '" + newName + "' already exists")
                .build();
        }
        
        // Perform the rename within a transaction
        int transactionID = currentProgram.startTransaction("Rename Function");
        try {
            function.setName(newName, SourceType.USER_DEFINED);
            currentProgram.endTransaction(transactionID, true);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully renamed function '" + oldName + "' to '" + newName + "'")
                .build();
        } catch (Exception e) {
            currentProgram.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error renaming function: " + e.getMessage())
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