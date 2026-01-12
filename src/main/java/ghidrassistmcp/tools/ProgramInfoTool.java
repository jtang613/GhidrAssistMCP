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
 * MCP tool that provides basic information about the currently loaded program.
 */
public class ProgramInfoTool implements McpTool {
    
    @Override
    public String getName() {
        return "get_program_info";
    }
    
    @Override
    public String getDescription() {
        return "Get information about the currently loaded program";
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
        
        String info = buildProgramInfo(currentProgram);
        return McpSchema.CallToolResult.builder()
            .addTextContent(info)
            .build();
    }
    
    private String buildProgramInfo(Program program) {
        StringBuilder info = new StringBuilder();
        info.append("Program Information:\n");
        info.append("Name: ").append(program.getName()).append("\n");
        info.append("Language: ").append(program.getLanguage().getLanguageDescription()).append("\n");
        info.append("Address Space: ").append(program.getAddressFactory().getDefaultAddressSpace().getName()).append("\n");
        info.append("Image Base: ").append(program.getImageBase()).append("\n");
        info.append("Min Address: ").append(program.getMinAddress()).append("\n");
        info.append("Max Address: ").append(program.getMaxAddress()).append("\n");
        info.append("Function Count: ").append(program.getFunctionManager().getFunctionCount()).append("\n");
        
        return info.toString();
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }
}