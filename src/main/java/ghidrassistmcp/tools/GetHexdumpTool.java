/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that retrieves a hexdump of memory at a specific address.
 * Displays data in standard hex+ASCII format.
 */
public class GetHexdumpTool implements McpTool {

    private static final int BYTES_PER_LINE = 16;

    @Override
    public String getName() {
        return "get_hexdump";
    }

    @Override
    public String getDescription() {
        return "Get a hexdump of memory at a specific address in standard hex+ASCII format. " +
               "Useful for examining data structures, .rodata, .data, .bss, and other non-code regions.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "len", new McpSchema.JsonSchema("number", null, null, null, null, null)
            ),
            List.of("address", "len"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        // Get and validate address parameter
        String addressStr = (String) arguments.get("address");
        if (addressStr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }

        // Get and validate length parameter
        Object lenObj = arguments.get("len");
        if (lenObj == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("len parameter is required")
                .build();
        }

        int length;
        try {
            // Handle both Integer and Double (JSON numbers can be either)
            if (lenObj instanceof Integer) {
                length = (Integer) lenObj;
            } else if (lenObj instanceof Double) {
                length = ((Double) lenObj).intValue();
            } else if (lenObj instanceof Long) {
                length = ((Long) lenObj).intValue();
            } else {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("len parameter must be a number")
                    .build();
            }

            if (length <= 0) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("len must be greater than 0")
                    .build();
            }

            // Limit maximum length to prevent excessive output
            if (length > 65536) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("len exceeds maximum allowed value of 65536 bytes")
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid len parameter: " + e.getMessage())
                .build();
        }

        // Parse the address
        Address address;
        try {
            address = currentProgram.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address format: " + addressStr)
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addressStr + " - " + e.getMessage())
                .build();
        }

        // Generate the hexdump
        try {
            String hexdump = generateHexdump(currentProgram, address, length);
            return McpSchema.CallToolResult.builder()
                .addTextContent(hexdump)
                .build();
        } catch (MemoryAccessException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Memory access error at address " + addressStr + ": " + e.getMessage())
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error generating hexdump: " + e.getMessage())
                .build();
        }
    }

    /**
     * Generate a hexdump in standard format with hex and ASCII representation.
     * Format: ADDRESS  HEX_BYTES (16 per line, grouped by 8)  |ASCII|
     */
    private String generateHexdump(Program program, Address startAddr, int length)
            throws MemoryAccessException {
        StringBuilder result = new StringBuilder();
        Memory memory = program.getMemory();

        result.append("Hexdump at ").append(startAddr).append(" (").append(length).append(" bytes):\n\n");

        int bytesRead = 0;
        Address currentAddr = startAddr;

        while (bytesRead < length) {
            // Calculate how many bytes to read on this line
            int bytesToRead = Math.min(BYTES_PER_LINE, length - bytesRead);
            byte[] lineBytes = new byte[bytesToRead];

            // Read the bytes for this line
            int actualBytesRead = 0;
            for (int i = 0; i < bytesToRead; i++) {
                try {
                    lineBytes[i] = memory.getByte(currentAddr);
                    currentAddr = currentAddr.add(1);
                    actualBytesRead++;
                } catch (MemoryAccessException e) {
                    // If we can't read a byte, mark it as unreadable
                    lineBytes[i] = 0;
                    currentAddr = currentAddr.add(1);
                    actualBytesRead++;
                }
            }

            // Format the line
            result.append(formatHexdumpLine(startAddr.add(bytesRead), lineBytes, actualBytesRead));
            result.append("\n");

            bytesRead += actualBytesRead;
        }

        return result.toString();
    }

    /**
     * Format a single line of the hexdump.
     */
    private String formatHexdumpLine(Address lineAddr, byte[] bytes, int validBytes) {
        StringBuilder line = new StringBuilder();

        if ( lineAddr.getOffset() > (1L << 32)) {
	        // Address (8 hex digits)
	        line.append(String.format("%08x  ", lineAddr.getOffset()));
        } else {
            // Address (4 hex digits)
            line.append(String.format("%04x  ", lineAddr.getOffset()));
        }

        // Hex bytes (16 per line, with space after 8th byte)
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            if (i < validBytes) {
                line.append(String.format("%02x ", bytes[i] & 0xFF));
            } else {
                line.append("   "); // 3 spaces for missing bytes
            }

            // Extra space after 8th byte
            if (i == 7) {
                line.append(" ");
            }
        }

        // ASCII representation
        line.append(" |");
        for (int i = 0; i < validBytes; i++) {
            char c = (char) (bytes[i] & 0xFF);
            // Print printable ASCII characters, otherwise use '.'
            if (c >= 32 && c <= 126) {
                line.append(c);
            } else {
                line.append('.');
            }
        }
        line.append("|");

        return line.toString();
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }
}
