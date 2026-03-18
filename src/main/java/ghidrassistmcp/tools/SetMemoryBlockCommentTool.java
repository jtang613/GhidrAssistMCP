/*
 * MCP tool for setting comments on memory blocks.
 * Used by PreScanNode to annotate detected peripheral regions.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that sets a comment on a memory block containing the given address.
 *
 * <p>Memory block comments provide semantic labels for memory regions,
 * e.g., "STM32: GPIO Port A" for an MMIO peripheral region.</p>
 *
 * <p>The tool resolves the address to its containing memory block and sets
 * the comment via {@code MemoryBlock.setComment()}. Idempotent — calling
 * with the same address and comment produces the same result.</p>
 */
public class SetMemoryBlockCommentTool implements McpTool {

    @Override
    public String getName() {
        return "set_memory_block_comment";
    }

    @Override
    public String getDescription() {
        return "Set a semantic comment/label on the memory block containing the given address";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", Map.of(
                    "type", "string",
                    "description", "Any address within the target memory block"
                ),
                "comment", Map.of(
                    "type", "string",
                    "description", "Semantic label for the memory region (max 1000 chars)"
                )
            ),
            List.of("address", "comment"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String addressStr = (String) arguments.get("address");
        String comment = (String) arguments.get("comment");

        if (addressStr == null || addressStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }

        if (comment == null || comment.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("comment parameter is required")
                .build();
        }

        // Truncate comment to 1000 chars
        if (comment.length() > 1000) {
            comment = comment.substring(0, 1000);
        }

        // Parse address
        Address address;
        try {
            address = currentProgram.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address: " + addressStr)
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error parsing address: " + e.getMessage())
                .build();
        }

        // Find the memory block containing this address
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        if (block == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No memory block at address: " + addressStr)
                .build();
        }

        // Set comment in a transaction using the standard Ghidra try-finally pattern
        int transactionID = currentProgram.startTransaction("Set Memory Block Comment");
        boolean success = false;
        try {
            block.setComment(comment);

            // Flush events to ensure internal state is updated and visible to other tools
            currentProgram.flushEvents();

            success = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully set comment on memory block '" + block.getName() +
                    "' (" + block.getStart() + "-" + block.getEnd() + "): \"" + comment + "\"")
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error setting memory block comment: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
