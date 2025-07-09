/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that renames a local variable within a function.
 */
public class RenameVariableTool implements McpTool {
    
    @Override
    public String getName() {
        return "rename_variable";
    }
    
    @Override
    public String getDescription() {
        return "Rename a local variable within a specific function";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "function_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "old_variable_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "new_variable_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("function_name", "old_variable_name", "new_variable_name"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String functionName = (String) arguments.get("function_name");
        String oldVariableName = (String) arguments.get("old_variable_name");
        String newVariableName = (String) arguments.get("new_variable_name");
        
        if (functionName == null || oldVariableName == null || newVariableName == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function_name, old_variable_name, and new_variable_name are all required")
                .build();
        }
        
        // Find the function
        Function function = findFunctionByName(currentProgram, functionName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionName)
                .build();
        }
        
        // Get the high function and rename the variable
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            
            if (results.isTimedOut()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation timed out for function: " + functionName)
                    .build();
            }
            
            if (results.getErrorMessage() != null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation error: " + results.getErrorMessage())
                    .build();
            }
            
            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Could not get high function for: " + functionName)
                    .build();
            }
            
            // Find and rename the variable
            HighSymbol targetSymbol = null;
            Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
            
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                if (symbol.getName().equals(oldVariableName)) {
                    targetSymbol = symbol;
                    break;
                }
            }
            
            if (targetSymbol == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Variable '" + oldVariableName + "' not found in function '" + functionName + "'")
                    .build();
            }
            
            // Rename the variable using the underlying symbol
            try {
                if (targetSymbol.getSymbol() != null) {
                    targetSymbol.getSymbol().setName(newVariableName, SourceType.USER_DEFINED);
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Successfully renamed variable '" + oldVariableName + "' to '" + newVariableName + "' in function '" + functionName + "'")
                        .build();
                }
				return McpSchema.CallToolResult.builder()
				    .addTextContent("Cannot rename variable '" + oldVariableName + "' - no underlying symbol available")
				    .build();
            } catch (DuplicateNameException e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Variable with name '" + newVariableName + "' already exists in function '" + functionName + "'")
                    .build();
            } catch (InvalidInputException e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid variable name: " + newVariableName)
                    .build();
            }
            
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error renaming variable: " + e.getMessage())
                .build();
        } finally {
            decompiler.dispose();
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