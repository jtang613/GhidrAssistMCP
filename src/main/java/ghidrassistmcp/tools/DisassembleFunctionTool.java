/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that disassembles a function to assembly instructions.
 */
public class DisassembleFunctionTool implements McpTool {
    
    @Override
    public String getName() {
        return "disassemble_function";
    }
    
    @Override
    public String getDescription() {
        return "Disassemble a function to assembly instructions";
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
                .addTextContent("Either function_name or address parameter is required")
                .build();
        }
        
        Function function = null;
        
        if (functionName != null) {
            function = findFunctionByName(currentProgram, functionName);
            if (function == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Function not found: " + functionName)
                    .build();
            }
        } else {
            // Find function by address
            try {
                Address address = currentProgram.getAddressFactory().getAddress(addressStr);
                function = currentProgram.getFunctionManager().getFunctionContaining(address);
                if (function == null) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("No function found at address: " + addressStr)
                        .build();
                }
            } catch (Exception e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address format: " + addressStr)
                    .build();
            }
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Disassembly of function: ").append(function.getName()).append("\n");
        result.append("Entry Point: ").append(function.getEntryPoint()).append("\n\n");
        
        // Iterate through instructions in the function
        InstructionIterator instrIter = currentProgram.getListing().getInstructions(function.getBody(), true);
        
        int instructionCount = 0;
        while (instrIter.hasNext()) {
            Instruction instruction = instrIter.next();
            
            result.append(instruction.getAddress()).append(": ");
            result.append(instruction.getMnemonicString());
            
            // Add operands
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                if (i == 0) {
                    result.append(" ");
                } else {
                    result.append(", ");
                }
                result.append(instruction.getDefaultOperandRepresentation(i));
            }
            
            // Add any comments
            String comment = instruction.getComment(CommentType.EOL);
            if (comment != null && !comment.trim().isEmpty()) {
                result.append(" ; ").append(comment.trim());
            }
            
            result.append("\n");
            instructionCount++;
        }
        
        result.append("\nTotal instructions: ").append(instructionCount);
        
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
}