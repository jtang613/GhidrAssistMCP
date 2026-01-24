/*
 * MCP tool for renaming symbols (functions, data, variables).
 * Consolidates rename_function, rename_data, and rename_variable into a single tool.
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that renames symbols (functions, data, or variables).
 * Replaces separate rename_function, rename_data, and rename_variable tools.
 */
public class RenameSymbolTool implements McpTool {

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public String getName() {
        return "rename_symbol";
    }

    @Override
    public String getDescription() {
        return "Rename a symbol (function, data/label, or local variable)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "target_type", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "identifier", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "new_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "variable_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("target_type", "identifier", "new_name"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String targetType = (String) arguments.get("target_type");
        String identifier = (String) arguments.get("identifier");
        String newName = (String) arguments.get("new_name");

        if (targetType == null || targetType.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("target_type parameter is required ('function', 'data', or 'variable')")
                .build();
        }

        if (identifier == null || identifier.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("identifier parameter is required")
                .build();
        }

        if (newName == null || newName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("new_name parameter is required")
                .build();
        }

        targetType = targetType.toLowerCase();

        // Dispatch to appropriate handler based on target type
        switch (targetType) {
            case "function":
                return renameFunction(currentProgram, identifier, newName);
            case "data":
                return renameData(currentProgram, identifier, newName);
            case "variable":
                String variableName = (String) arguments.get("variable_name");
                if (variableName == null || variableName.isEmpty()) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("variable_name parameter is required when target_type is 'variable'")
                        .build();
                }
                return renameVariable(currentProgram, identifier, variableName, newName);
            default:
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid target_type. Use 'function', 'data', or 'variable'")
                    .build();
        }
    }

    /**
     * Rename a function.
     * Supports C++ qualified names (e.g., "Class::method" or "Outer::Inner::method").
     * When a qualified name is provided, the namespace hierarchy is created if it doesn't exist.
     *
     * Note: Symbol operations must run on the Swing EDT to avoid race conditions with
     * Ghidra's Symbol Tree UI updates.
     */
    private McpSchema.CallToolResult renameFunction(Program program, String oldName, String newName) {
        // Find the function by old name
        Function function = findFunctionByName(program, oldName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + oldName)
                .build();
        }

        // Use AtomicReference to capture result from EDT execution
        AtomicReference<McpSchema.CallToolResult> resultRef = new AtomicReference<>();
        final Function targetFunction = function;

        try {
            // Run symbol modifications on the Swing EDT to avoid race conditions
            // with Ghidra's Symbol Tree UI updates
            SwingUtilities.invokeAndWait(() -> {
                int transactionID = program.startTransaction("Rename Function");
                try {
                    Object[] parsed = parseAndCreateNamespace(program, newName);
                    if (parsed == null) {
                        program.endTransaction(transactionID, false);
                        resultRef.set(McpSchema.CallToolResult.builder()
                            .addTextContent("Invalid qualified name format: " + newName)
                            .build());
                        return;
                    }

                    Namespace targetNamespace = (Namespace) parsed[0];
                    String simpleName = (String) parsed[1];

                    // Check if a function with this name already exists in the target namespace
                    Function existingFunction = findFunctionByName(program, simpleName);
                    if (existingFunction != null && existingFunction != targetFunction &&
                        existingFunction.getParentNamespace().equals(targetNamespace)) {
                        program.endTransaction(transactionID, false);
                        resultRef.set(McpSchema.CallToolResult.builder()
                            .addTextContent("Function with name '" + simpleName + "' already exists in namespace '" +
                                          targetNamespace.getName(true) + "'")
                            .build());
                        return;
                    }

                    // Set the namespace if it's not global (i.e., we have a qualified name)
                    if (!targetNamespace.isGlobal()) {
                        targetFunction.setParentNamespace(targetNamespace);
                    }

                    // Set the function name
                    targetFunction.setName(simpleName, SourceType.USER_DEFINED);

                    program.endTransaction(transactionID, true);

                    // Build success message
                    String resultName = targetNamespace.isGlobal() ? simpleName : targetNamespace.getName(true) + "::" + simpleName;
                    resultRef.set(McpSchema.CallToolResult.builder()
                        .addTextContent("Successfully renamed function '" + oldName + "' to '" + resultName + "'")
                        .build());
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(McpSchema.CallToolResult.builder()
                        .addTextContent("Error renaming function: " + e.getMessage())
                        .build());
                }
            });
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error executing rename on EDT: " + e.getMessage())
                .build();
        }

        return resultRef.get();
    }

    /**
     * Rename data/label at an address.
     *
     * Note: Symbol operations must run on the Swing EDT to avoid race conditions with
     * Ghidra's Symbol Tree UI updates.
     */
    private McpSchema.CallToolResult renameData(Program program, String addressStr, String newName) {
        // Parse the address
        Address address;
        try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address: " + addressStr)
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addressStr)
                .build();
        }

        // Use AtomicReference to capture result from EDT execution
        AtomicReference<McpSchema.CallToolResult> resultRef = new AtomicReference<>();
        final Address targetAddress = address;

        try {
            // Run symbol modifications on the Swing EDT to avoid race conditions
            // with Ghidra's Symbol Tree UI updates
            SwingUtilities.invokeAndWait(() -> {
                int transactionID = program.startTransaction("Rename Data");
                try {
                    Data data = program.getListing().getDataAt(targetAddress);
                    if (data != null) {
                        // Rename the data symbol
                        Symbol primarySymbol = data.getPrimarySymbol();
                        if (primarySymbol != null) {
                            String oldName = primarySymbol.getName();
                            try {
                                primarySymbol.setName(newName, SourceType.USER_DEFINED);
                                program.endTransaction(transactionID, true);
                                resultRef.set(McpSchema.CallToolResult.builder()
                                    .addTextContent("Successfully renamed data at " + addressStr +
                                                  " from '" + oldName + "' to '" + newName + "'")
                                    .build());
                                return;
                            } catch (DuplicateNameException e) {
                                program.endTransaction(transactionID, false);
                                resultRef.set(McpSchema.CallToolResult.builder()
                                    .addTextContent("Symbol with name '" + newName + "' already exists")
                                    .build());
                                return;
                            } catch (InvalidInputException e) {
                                program.endTransaction(transactionID, false);
                                resultRef.set(McpSchema.CallToolResult.builder()
                                    .addTextContent("Invalid symbol name: " + newName)
                                    .build());
                                return;
                            }
                        }
                        // Create a new symbol for the data
                        program.getSymbolTable().createLabel(targetAddress, newName, SourceType.USER_DEFINED);
                        program.endTransaction(transactionID, true);
                        resultRef.set(McpSchema.CallToolResult.builder()
                            .addTextContent("Successfully created label '" + newName + "' at " + addressStr)
                            .build());
                        return;
                    }

                    // No data at address, try to find any symbol and rename it
                    Symbol[] symbols = program.getSymbolTable().getSymbols(targetAddress);
                    if (symbols.length > 0) {
                        Symbol symbol = symbols[0]; // Use first symbol
                        String oldName = symbol.getName();
                        try {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            program.endTransaction(transactionID, true);
                            resultRef.set(McpSchema.CallToolResult.builder()
                                .addTextContent("Successfully renamed symbol at " + addressStr +
                                              " from '" + oldName + "' to '" + newName + "'")
                                .build());
                            return;
                        } catch (DuplicateNameException e) {
                            program.endTransaction(transactionID, false);
                            resultRef.set(McpSchema.CallToolResult.builder()
                                .addTextContent("Symbol with name '" + newName + "' already exists")
                                .build());
                            return;
                        } catch (InvalidInputException e) {
                            program.endTransaction(transactionID, false);
                            resultRef.set(McpSchema.CallToolResult.builder()
                                .addTextContent("Invalid symbol name: " + newName)
                                .build());
                            return;
                        }
                    }

                    // Create a new label at the address
                    program.getSymbolTable().createLabel(targetAddress, newName, SourceType.USER_DEFINED);
                    program.endTransaction(transactionID, true);
                    resultRef.set(McpSchema.CallToolResult.builder()
                        .addTextContent("Successfully created label '" + newName + "' at " + addressStr)
                        .build());
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(McpSchema.CallToolResult.builder()
                        .addTextContent("Error creating label: " + e.getMessage())
                        .build());
                }
            });
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error executing rename on EDT: " + e.getMessage())
                .build();
        }

        return resultRef.get();
    }

    /**
     * Rename a local variable within a function.
     *
     * Note: Symbol operations must run on the Swing EDT to avoid race conditions with
     * Ghidra's Symbol Tree UI updates.
     */
    private McpSchema.CallToolResult renameVariable(Program program, String functionName,
                                                     String oldVariableName, String newVariableName) {
        // Find the function
        Function function = findFunctionByName(program, functionName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionName)
                .build();
        }

        // Get the high function and rename the variable
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);

            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);

            if (results.isTimedOut()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation timed out for function: " + functionName)
                    .build();
            }

            if (results.isValid() == false) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation error for function " + functionName + ": " + results.getErrorMessage())
                    .build();
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Could not get high function for: " + functionName)
                    .build();
            }

            // Find the variable
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

            // Use AtomicReference to capture result from EDT execution
            AtomicReference<McpSchema.CallToolResult> resultRef = new AtomicReference<>();
            final HighSymbol symbolToRename = targetSymbol;

            // Rename the variable on the EDT within a transaction
            SwingUtilities.invokeAndWait(() -> {
                int transactionID = program.startTransaction("Rename Variable");
                try {
                    HighFunctionDBUtil.updateDBVariable(symbolToRename, newVariableName, null, SourceType.USER_DEFINED);

                    program.endTransaction(transactionID, true);
                    resultRef.set(McpSchema.CallToolResult.builder()
                        .addTextContent("Successfully renamed variable '" + oldVariableName + "' to '" + newVariableName + "' in function '" + functionName + "'")
                        .build());
                } catch (DuplicateNameException e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(McpSchema.CallToolResult.builder()
                        .addTextContent("Variable with name '" + newVariableName + "' already exists in function '" + functionName + "'")
                        .build());
                } catch (InvalidInputException e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(McpSchema.CallToolResult.builder()
                        .addTextContent("Invalid variable name: " + newVariableName)
                        .build());
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(McpSchema.CallToolResult.builder()
                        .addTextContent("Error renaming variable: " + e.getMessage())
                        .build());
                }
            });

            return resultRef.get();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error renaming variable: " + e.getMessage())
                .build();
        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Find a function by name.
     */
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

    /**
     * Parse a qualified name (e.g., "Class::method" or "Outer::Inner::method")
     * and return the namespace and simple name.
     * Creates namespace hierarchy if it doesn't exist.
     *
     * @return Object[] with [Namespace, String simpleName], or null on error
     */
    private Object[] parseAndCreateNamespace(Program program, String qualifiedName) {
        if (!qualifiedName.contains("::")) {
            // No namespace, return global namespace and the name as-is
            return new Object[] { program.getGlobalNamespace(), qualifiedName };
        }

        String[] parts = qualifiedName.split("::");
        if (parts.length < 2) {
            return null; // Invalid format
        }

        // The last part is the method/symbol name
        String simpleName = parts[parts.length - 1];

        // Everything before is the namespace hierarchy
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace currentNamespace = program.getGlobalNamespace();

        for (int i = 0; i < parts.length - 1; i++) {
            String nsName = parts[i].trim();
            if (nsName.isEmpty()) {
                continue;
            }

            try {
                // Try to find existing namespace first
                Namespace existingNs = symbolTable.getNamespace(nsName, currentNamespace);
                if (existingNs != null) {
                    currentNamespace = existingNs;
                } else {
                    // Create as a class namespace (appropriate for C++ class::method pattern)
                    currentNamespace = symbolTable.createClass(currentNamespace, nsName, SourceType.USER_DEFINED);
                }
            } catch (Exception e) {
                // If class creation fails, try creating as a regular namespace
                try {
                    currentNamespace = symbolTable.createNameSpace(currentNamespace, nsName, SourceType.USER_DEFINED);
                } catch (Exception e2) {
                    return null; // Failed to create namespace
                }
            }
        }

        return new Object[] { currentNamespace, simpleName };
    }
}
