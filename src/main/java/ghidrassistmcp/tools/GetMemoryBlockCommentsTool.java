/*
 * MCP tool for retrieving memory block comments.
 * Companion to SetMemoryBlockCommentTool.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.utils.McpUtils;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that returns all memory blocks that have comments set.
 *
 * <p>Used to retrieve semantic annotations previously set via
 * {@link SetMemoryBlockCommentTool}. Returns a JSON array of objects
 * with block name, address range, and comment.</p>
 */
public class GetMemoryBlockCommentsTool implements McpTool {

    @Override
    public String getName() {
        return "get_memory_block_comments";
    }

    @Override
    public String getDescription() {
        return "Get all memory blocks that have comments/labels set";
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public boolean includeContext() {
        // Structured JSON response should not be prepended with a prose context header
        return false;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(), List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();

        StringBuilder json = new StringBuilder();
        json.append("[");

        int emitted = 0;
        for (MemoryBlock block : blocks) {
            String comment = block.getComment();
            if (comment == null || comment.isEmpty()) {
                continue;
            }

            if (emitted > 0) {
                json.append(",");
            }
            json.append("{\"name\":\"").append(McpUtils.escapeJson(block.getName()))
                .append("\",\"start\":\"0x").append(block.getStart().toString())
                .append("\",\"end\":\"0x").append(block.getEnd().toString())
                .append("\",\"comment\":\"").append(McpUtils.escapeJson(comment))
                .append("\"}");
            emitted++;
        }

        json.append("]");

        return McpSchema.CallToolResult.builder()
            .addTextContent(json.toString())
            .build();
    }
}
