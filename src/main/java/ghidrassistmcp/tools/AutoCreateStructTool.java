/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that implements Ghidra's 'Auto create structure' and 'Auto fill in structure' functionality.
 * This tool analyzes a variable and creates a structure based on its usage patterns.
 */
public class AutoCreateStructTool implements McpTool {
    
    @Override
    public String getName() {
        return "auto_create_struct";
    }
    
    @Override
    public String getDescription() {
        return "Auto create and apply structure to a variable (equivalent to Ghidra's auto create structure)";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "function_identifier", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "variable_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("function_identifier", "variable_name"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // Fallback for when backend reference is not available
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String functionIdentifier = (String) arguments.get("function_identifier");
        String variableName = (String) arguments.get("variable_name");

        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function_identifier parameter is required (function name or address)")
                .build();
        }

        if (variableName == null || variableName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("variable_name parameter is required")
                .build();
        }

        // Use proper structure creation with transaction handling
        StructureResult result = createAndApplyStructure(currentProgram, functionIdentifier, variableName);

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.success ?
                "Successfully created and applied structure: " + result.message :
                "Failed to create structure: " + result.errorMessage)
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        // This tool doesn't need UI context, so just delegate to the base implementation
        return execute(arguments, currentProgram);
    }
    
    /**
     * Result class for structure operations
     */
    private static class StructureResult {
        final boolean success;
        final String message;
        final String errorMessage;
        
        StructureResult(boolean success, String message, String errorMessage) {
            this.success = success;
            this.message = message;
            this.errorMessage = errorMessage;
        }
    }
    
    /**
     * Create and apply structure with proper error handling
     */
    private StructureResult createAndApplyStructure(Program program, String functionIdentifier, String variableName) {
        final StringBuilder errorMessage = new StringBuilder();
        final StringBuilder successMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                performStructureCreation(program, functionIdentifier, variableName, success, successMessage, errorMessage));
        } catch (Exception e) {
            String msg = "Failed to create structure on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new StructureResult(success.get(), successMessage.toString(), errorMessage.toString());
    }
    
    /**
     * Perform the structure creation within proper threading context
     */
    private void performStructureCreation(Program program, String functionIdentifier, String variableName,
                                        AtomicBoolean success, StringBuilder successMessage, StringBuilder errorMessage) {
        int txId = program.startTransaction("Auto Create Structure");
        boolean committed = false;
        
        try {
            // Find the function
            Function function = findFunction(program, functionIdentifier);
            if (function == null) {
                errorMessage.append("Could not find function: ").append(functionIdentifier);
                return;
            }
            
            Msg.info(this, "Creating structure for variable '" + variableName + "' in function " + function.getName());
            
            // Set up decompiler
            DecompInterface decompiler = new DecompInterface();
            setupDecompiler(decompiler, program);
            
            try {
                // Decompile the function
                DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                
                if (!results.decompileCompleted()) {
                    errorMessage.append("Decompilation failed for function: ").append(function.getName());
                    return;
                }

                HighFunction highFunction = results.getHighFunction();
                
                // Find the variable
                HighVariable highVar = findHighVariable(highFunction, variableName);
                if (highVar == null) {
                    errorMessage.append("Could not find variable '").append(variableName).append("' in function");
                    return;
                }
                
                // Create and apply the structure
                boolean applied = createAndApplyStructureImpl(program, function, highVar, decompiler, highFunction,
                    successMessage, errorMessage);

                if (applied) {
                    success.set(true);
                    committed = true;
                }
                
            } finally {
                decompiler.dispose();
            }
            
        } catch (Exception e) {
            String msg = "Error during structure creation: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txId, committed);
        }
    }
    
    /**
     * Core structure creation logic from reference code
     */
    private boolean createAndApplyStructureImpl(Program program, Function function, HighVariable highVar,
                                             DecompInterface decompiler, HighFunction highFunction, StringBuilder successMessage, StringBuilder errorMessage) throws Exception {
        
        // Try to use FillOutStructureHelper to process the structure
        // Note: This class may not be available in all Ghidra versions
        Structure structDT = null;
        try {
            Class<?> fillHelperClass = Class.forName("ghidra.app.decompiler.util.FillOutStructureHelper");
            Object fillHelper = fillHelperClass.getConstructor(Program.class, TaskMonitor.class)
                .newInstance(program, TaskMonitor.DUMMY);
            
            java.lang.reflect.Method processMethod = fillHelperClass.getMethod("processStructure", 
                HighVariable.class, Function.class, boolean.class, boolean.class, DecompInterface.class);
            
            structDT = (Structure) processMethod.invoke(fillHelper, highVar, function, false, true, decompiler);
        } catch (Exception e) {
            errorMessage.append("FillOutStructureHelper not available or failed: ").append(e.getMessage());
            return false;
        }
        
        if (structDT == null) {
            errorMessage.append("Failed to create structure from variable usage");
            return false;
        }

        // Add structure to data type manager
        DataTypeManager dtm = program.getDataTypeManager();
        structDT = (Structure) dtm.addDataType(structDT, DataTypeConflictHandler.DEFAULT_HANDLER);
        PointerDataType ptrStruct = new PointerDataType(structDT);

        // Get variable from function - try both decompiler and disassembly contexts
        Variable var = findVariableFromDecompiler(function, highFunction, highVar.getSymbol().getName());
        
        if (var != null && var instanceof ghidra.program.model.listing.AutoParameterImpl) {
            // Modify the function signature to change the data type of the auto-parameter
            updateFunctionParameter(function, var.getName(), ptrStruct);
            successMessage.append("Updated function parameter '").append(var.getName())
                         .append("' with structure type: ").append(structDT.getName());
        } else {
            // Update local variable directly through HighFunction
            HighFunctionDBUtil.updateDBVariable(highVar.getSymbol(), null, ptrStruct, SourceType.USER_DEFINED);
            successMessage.append("Updated local variable '").append(highVar.getSymbol().getName())
                         .append("' with structure type: ").append(structDT.getName());
        }
        
        Msg.info(this, "Successfully created and applied structure: " + structDT.getName());
        return true;
    }
    
    /**
     * Find function by name or address
     */
    private Function findFunction(Program program, String identifier) {
        // Try as address first
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                return program.getFunctionManager().getFunctionAt(addr);
            }
        } catch (Exception e) {
            // Not an address, try as name
        }
        
        // Try as function name
        var functionManager = program.getFunctionManager();
        var functions = functionManager.getFunctions(true);
        
        for (Function function : functions) {
            if (function.getName().equals(identifier)) {
                return function;
            }
        }
        
        return null;
    }
    
    
    /**
     * Setup decompiler with program options (from reference implementation)
     */
    private void setupDecompiler(DecompInterface decompiler, Program program) {
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(program);
        decompiler.setOptions(options);
        decompiler.openProgram(program);
    }
    
    /**
     * Find high variable by name in high function (from reference implementation)
     */
    private HighVariable findHighVariable(HighFunction highFunction, String varName) {
        var symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            if (sym.getName().equals(varName)) {
                return sym.getHighVariable();
            }
        }
        return null;
    }
    
    /**
     * Commit local names to ensure all variables are available (from reference implementation)
     */
    private void commitLocalNames(Program program, Function function) {
        try {
            // This ensures all variables are available by flushing events
            program.flushEvents();
            // Force the function to update its variable information
            if (function != null) {
                function.getLocalVariables(); // This forces loading of local variables
                function.getParameters(); // This forces loading of parameters
            }
        } catch (Exception e) {
            // If commit fails, continue anyway
            Msg.warn(this, "Failed to commit local names for function " + function.getName() + ": " + e.getMessage());
        }
    }
    
    /**
     * Find variable from decompiler context - this handles decompiler-only variables
     */
    private Variable findVariableFromDecompiler(Function function, HighFunction highFunction, String varName) {
        // Commit local names to ensure all variables are available
        commitLocalNames(function.getProgram(), function);
        
        // If not found in disassembly, the variable might only exist in decompiler context
        // In this case, we need to work directly with the HighFunction
        // Check if this is a parameter that maps to the decompiler's view
        var symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getName().equals(varName)) {
                HighVariable highVar = symbol.getHighVariable();
                if (highVar != null) {
                    // Try to find a corresponding parameter by storage location
                    try {
                        var representative = highVar.getRepresentative();
                        if (representative != null) {
                            // Check parameters first
                            for (Parameter param : function.getParameters()) {
                                var storage = param.getVariableStorage();
                                if (storage != null && storage.getVarnodes().length > 0) {
                                    var paramVarnode = storage.getVarnodes()[0];
                                    if (paramVarnode.getAddress().equals(representative.getAddress())) {
                                        return param;
                                    }
                                }
                            }
                            
                            // Check local variables by storage
                            for (Variable localVar : function.getLocalVariables()) {
                                var storage = localVar.getVariableStorage();
                                if (storage != null && storage.getVarnodes().length > 0) {
                                    var localVarnode = storage.getVarnodes()[0];
                                    if (localVarnode.getAddress().equals(representative.getAddress())) {
                                        return localVar;
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        // Continue if storage comparison fails
                    }
                }
            }
        }
        
        // If still not found, this is a decompiler-only variable
        // Return null - we'll handle it through HighFunctionDBUtil.updateDBVariable
        return null;
    }
        
    /**
     * Update function parameter with new data type
     */
    private void updateFunctionParameter(Function function, String paramName, 
                                       DataType newType) throws InvalidInputException, DuplicateNameException {
        
        Parameter[] parameters = function.getParameters();
        Parameter[] newParams = new Parameter[parameters.length];

        for (int i = 0; i < parameters.length; i++) {
            if (parameters[i].getName().equals(paramName)) {
                newParams[i] = new ParameterImpl(
                    parameters[i].getName(),
                    newType,
                    parameters[i].getVariableStorage(),
                    function.getProgram(),
                    SourceType.USER_DEFINED
                );
            } else {
                newParams[i] = parameters[i];
            }
        }

        function.updateFunction(
            function.getCallingConventionName(),
            null, // Keep return type
            FunctionUpdateType.CUSTOM_STORAGE,
            true,
            SourceType.USER_DEFINED,
            newParams
        );
    }
}