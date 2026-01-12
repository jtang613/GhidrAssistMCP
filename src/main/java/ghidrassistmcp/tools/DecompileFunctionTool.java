/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that decompiles a function to readable C-like code.
 */
public class DecompileFunctionTool implements McpTool {
    
    @Override
    public String getName() {
        return "decompile_function";
    }
    
    @Override
    public String getDescription() {
        return "Decompile a function to readable C-like code using function name or address";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "function_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null)
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
        
        String functionName = (String) arguments.get("function_name");
        String addressStr = (String) arguments.get("address");
        
        if (functionName == null && addressStr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either function_name or address must be provided")
                .build();
        }
        
        Function function = null;
        
        // Find function by name or address
        if (functionName != null) {
            function = findFunctionByName(currentProgram, functionName);
        } else if (addressStr != null) {
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                function = currentProgram.getFunctionManager().getFunctionAt(addr);
            } catch (Exception e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address format: " + addressStr)
                    .build();
            }
        }
        
        if (function == null) {
            String target = functionName != null ? functionName : addressStr;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + target)
                .build();
        }
        
        // Decompile the function
        String decompiledCode = decompileFunction(currentProgram, function);
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(decompiledCode)
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
    
    private String decompileFunction(Program program, Function function) {
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(function.getProgram());

            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);

            if (results.isTimedOut()) {
                return "Decompilation timed out for function: " + function.getName();
            }

            if (results.isValid() == false) {
                return "Decompilation error for function " + function.getName() + ": " + results.getErrorMessage();
            }

            String decompiledCode = results.getDecompiledFunction().getC();

            if (decompiledCode == null || decompiledCode.trim().isEmpty()) {
                return "No decompiled code available for function: " + function.getName();
            }

            return "Decompiled function " + function.getName() + ":\n\n" + decompiledCode;

        } catch (Exception e) {
            return "Error decompiling function " + function.getName() + ": " + e.getMessage();
        } finally {
            decompiler.dispose();
        }
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }
}