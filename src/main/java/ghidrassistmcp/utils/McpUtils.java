package ghidrassistmcp.utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

/**
 * Common utilities for MCP tools, including JSON escaping and optimized Ghidra lookups.
 */
public class McpUtils {

    /**
     * Escape a string for JSON output.
     */
    public static String escapeJson(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }

    /**
     * Optimized function lookup by name or address.
     * Uses Ghidra's indexed symbols instead of a linear scan.
     */
    public static Function findFunction(Program program, String identifier) {
        if (program == null || identifier == null || identifier.isEmpty()) {
            return null;
        }

        // 1. Try as address first
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) return func;

                // If no function at address, try containing function
                func = program.getFunctionManager().getFunctionContaining(addr);
                if (func != null) return func;
            }
        } catch (Exception e) {
            // Not a valid address string, proceed to name lookup
        }

        // 2. Optimized name lookup using Ghidra's symbol index (O(1) or O(log N))
        // Look up by name
        for (Symbol symbol : program.getSymbolTable().getSymbols(identifier)) {
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                return (Function) symbol.getObject();
            }
        }

        return null;
    }
}
