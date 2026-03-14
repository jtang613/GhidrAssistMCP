/*
 * Consolidated MCP tool for variable operations.
 * Replaces SetLocalVariableTypeTool and absorbs SetFunctionPrototypeTool.
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class VariablesTool implements McpTool {

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isIdempotent() { return true; }

    @Override
    public boolean isLongRunning() { return true; }

    @Override
    public String getName() { return "variables"; }

    @Override
    public String getDescription() {
        return "Variable operations: list, rename, retype local variables, or set_prototype for function signatures";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("list", "rename", "retype", "set_prototype")
                )),
                Map.entry("function_name", Map.of(
                    "type", "string",
                    "description", "Function name (required for list/rename/retype)"
                )),
                Map.entry("variable_name", Map.of(
                    "type", "string",
                    "description", "Variable name (required for rename/retype)"
                )),
                Map.entry("new_name", Map.of(
                    "type", "string",
                    "description", "New name (required for rename)"
                )),
                Map.entry("data_type", Map.of(
                    "type", "string",
                    "description", "Data type string (required for retype)"
                )),
                Map.entry("function_address", Map.of(
                    "type", "string",
                    "description", "Function address (required for set_prototype)"
                )),
                Map.entry("prototype", Map.of(
                    "type", "string",
                    "description", "Function prototype/signature string (required for set_prototype)"
                ))
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return result("No program currently loaded");
        }
        String action = (String) arguments.get("action");
        if (action == null) return result("action is required");

        switch (action.toLowerCase()) {
            case "list": return executeList(arguments, currentProgram);
            case "rename": return executeRename(arguments, currentProgram);
            case "retype": return executeRetype(arguments, currentProgram);
            case "set_prototype": return executeSetPrototype(arguments, currentProgram);
            default: return result("Invalid action. Use 'list', 'rename', 'retype', or 'set_prototype'");
        }
    }

    private McpSchema.CallToolResult executeList(Map<String, Object> arguments, Program program) {
        String functionName = (String) arguments.get("function_name");
        if (functionName == null) return result("function_name is required for list");

        Function function = findFunction(program, functionName);
        if (function == null) return result("Function not found: " + functionName);

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (!results.isValid()) return result("Decompilation failed: " + results.getErrorMessage());

            HighFunction hf = results.getHighFunction();
            if (hf == null) return result("Could not get high function");

            StringBuilder sb = new StringBuilder();
            sb.append("Variables in function: ").append(functionName).append("\n\n");

            // Parameters
            sb.append("## Parameters\n");
            int paramCount = 0;
            Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol sym = symbols.next();
                if (sym.isParameter()) {
                    HighVariable hv = sym.getHighVariable();
                    String typeName = hv != null && hv.getDataType() != null ? hv.getDataType().getName() : "unknown";
                    sb.append("  - ").append(typeName).append(" ").append(sym.getName())
                      .append(" (param ").append(sym.getCategoryIndex()).append(")\n");
                    paramCount++;
                }
            }
            if (paramCount == 0) sb.append("  (none)\n");

            // Locals
            sb.append("\n## Local Variables\n");
            int localCount = 0;
            symbols = hf.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol sym = symbols.next();
                if (!sym.isParameter()) {
                    HighVariable hv = sym.getHighVariable();
                    String typeName = hv != null && hv.getDataType() != null ? hv.getDataType().getName() : "unknown";
                    sb.append("  - ").append(typeName).append(" ").append(sym.getName());
                    if (sym.getStorage() != null) {
                        sb.append(" (").append(sym.getStorage()).append(")");
                    }
                    sb.append("\n");
                    localCount++;
                }
            }
            if (localCount == 0) sb.append("  (none)\n");

            return result(sb.toString());
        } finally {
            decompiler.dispose();
        }
    }

    private McpSchema.CallToolResult executeRename(Map<String, Object> arguments, Program program) {
        String functionName = (String) arguments.get("function_name");
        String variableName = (String) arguments.get("variable_name");
        String newName = (String) arguments.get("new_name");
        if (functionName == null || variableName == null || newName == null) {
            return result("function_name, variable_name, and new_name are required for rename");
        }

        Function function = findFunction(program, functionName);
        if (function == null) return result("Function not found: " + functionName);

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (!results.isValid()) return result("Decompilation failed");

            HighFunction hf = results.getHighFunction();
            if (hf == null) return result("Could not get high function");

            Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol sym = symbols.next();
                if (sym.getName().equals(variableName)) {
                    int txId = program.startTransaction("Rename Variable");
                    try {
                        ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
                            sym, newName, null, SourceType.USER_DEFINED);
                        program.endTransaction(txId, true);
                        return result("Renamed '" + variableName + "' to '" + newName + "' in " + functionName);
                    } catch (Exception e) {
                        program.endTransaction(txId, false);
                        return result("Error renaming: " + e.getMessage());
                    }
                }
            }
            return result("Variable '" + variableName + "' not found in " + functionName);
        } finally {
            decompiler.dispose();
        }
    }

    private McpSchema.CallToolResult executeRetype(Map<String, Object> arguments, Program program) {
        String functionName = (String) arguments.get("function_name");
        String variableName = (String) arguments.get("variable_name");
        String dataTypeName = (String) arguments.get("data_type");
        if (functionName == null || variableName == null || dataTypeName == null) {
            return result("function_name, variable_name, and data_type are required for retype");
        }

        Function function = findFunction(program, functionName);
        if (function == null) return result("Function not found: " + functionName);

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = dtm.getDataType("/" + dataTypeName);
        if (dataType == null) dataType = dtm.getDataType(dataTypeName);
        if (dataType == null) return result("Data type not found: " + dataTypeName);

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (!results.isValid()) return result("Decompilation failed");

            HighFunction hf = results.getHighFunction();
            if (hf == null) return result("Could not get high function");

            Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol sym = symbols.next();
                if (sym.getName().equals(variableName)) {
                    int txId = program.startTransaction("Retype Variable");
                    try {
                        ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
                            sym, null, dataType, SourceType.USER_DEFINED);
                        program.endTransaction(txId, true);
                        return result("Retyped '" + variableName + "' to " + dataType.getName() + " in " + functionName);
                    } catch (Exception e) {
                        program.endTransaction(txId, false);
                        return result("Error retyping: " + e.getMessage());
                    }
                }
            }
            return result("Variable '" + variableName + "' not found in " + functionName);
        } finally {
            decompiler.dispose();
        }
    }

    private McpSchema.CallToolResult executeSetPrototype(Map<String, Object> arguments, Program program) {
        String functionAddrStr = (String) arguments.get("function_address");
        String prototype = (String) arguments.get("prototype");
        if (functionAddrStr == null || prototype == null) {
            return result("function_address and prototype are required for set_prototype");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                if (addr == null) { errorMessage.append("Invalid address: " + functionAddrStr); return; }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) { errorMessage.append("No function at: " + functionAddrStr); return; }

                int txId = program.startTransaction("Set function prototype");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    FunctionSignatureParser parser = new FunctionSignatureParser(dtm, null);
                    FunctionDefinitionDataType sig = parser.parse(null, prototype);
                    if (sig == null) { errorMessage.append("Failed to parse prototype"); return; }

                    ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                        addr, sig, SourceType.USER_DEFINED);
                    if (cmd.applyTo(program, new ConsoleTaskMonitor())) {
                        success.set(true);
                    } else {
                        errorMessage.append("Command failed: " + cmd.getStatusMsg());
                    }
                } catch (Exception e) {
                    errorMessage.append("Error: " + e.getMessage());
                } finally {
                    program.endTransaction(txId, success.get());
                }
            });
        } catch (Exception e) {
            return result("Failed on Swing thread: " + e.getMessage());
        }

        return result(success.get() ?
            "Successfully set function prototype: " + prototype :
            "Failed: " + errorMessage.toString());
    }

    private Function findFunction(Program program, String name) {
        // Try as address first
        try {
            Address addr = program.getAddressFactory().getAddress(name);
            if (addr != null) {
                Function f = program.getFunctionManager().getFunctionAt(addr);
                if (f != null) return f;
            }
        } catch (Exception e) { /* not an address */ }

        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) return f;
        }
        return null;
    }

    private static McpSchema.CallToolResult result(String text) {
        return McpSchema.CallToolResult.builder().addTextContent(text).build();
    }
}
