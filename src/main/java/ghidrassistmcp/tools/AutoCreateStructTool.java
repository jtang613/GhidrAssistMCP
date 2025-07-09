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
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPPlugin;
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
        // Fallback for when plugin reference is not available
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        return McpSchema.CallToolResult.builder()
            .addTextContent("Auto create structure functionality requires plugin context for decompiler access")
            .build();
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPPlugin plugin) {
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
            DecompileOptions options = new DecompileOptions();
            decompiler.setOptions(options);
            
            if (!decompiler.openProgram(program)) {
                errorMessage.append("Failed to initialize decompiler");
                return;
            }
            
            try {
                // Decompile the function
                DecompileResults decompileResults = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                HighFunction highFunction = decompileResults.getHighFunction();
                
                if (highFunction == null) {
                    errorMessage.append("Failed to decompile function");
                    return;
                }
                
                // Find the variable
                HighVariable highVar = findHighVariable(highFunction, variableName);
                if (highVar == null) {
                    errorMessage.append("Could not find variable '").append(variableName).append("' in function");
                    return;
                }
                
                // Create and apply the structure
                createAndApplyStructureImpl(program, function, highVar, decompiler, successMessage, errorMessage);
                
                success.set(true);
                committed = true;
                
            } finally {
                decompiler.closeProgram();
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
     * Core structure creation logic adapted from reference code
     */
    private void createAndApplyStructureImpl(Program program, Function function, HighVariable highVar, 
                                           DecompInterface decompiler, StringBuilder successMessage, StringBuilder errorMessage) throws Exception {
        
        // Try to use FillOutStructureHelper to process the structure
        // Note: This class may not be available in all Ghidra versions
        Structure structDT = null;
        try {
            Class<?> fillHelperClass = Class.forName("ghidra.app.util.datatype.microsoft.FillOutStructureHelper");
            Object fillHelper = fillHelperClass.getConstructor(Program.class, TaskMonitor.class)
                .newInstance(program, TaskMonitor.DUMMY);
            
            java.lang.reflect.Method processMethod = fillHelperClass.getMethod("processStructure", 
                HighVariable.class, Function.class, boolean.class, boolean.class, DecompInterface.class);
            
            structDT = (Structure) processMethod.invoke(fillHelper, highVar, function, false, true, decompiler);
        } catch (Exception e) {
            errorMessage.append("FillOutStructureHelper not available or failed: ").append(e.getMessage());
            return;
        }
        
        if (structDT == null) {
            errorMessage.append("Failed to create structure from variable usage");
            return;
        }

        // Add structure to data type manager
        DataTypeManager dtm = program.getDataTypeManager();
        structDT = (Structure) dtm.addDataType(structDT, DataTypeConflictHandler.DEFAULT_HANDLER);
        PointerDataType ptrStruct = new PointerDataType(structDT);

        // Find the variable in the function
        Variable var = findVariable(function, highVar.getSymbol().getName());
        
        if (var instanceof ghidra.program.model.listing.AutoParameterImpl) {
            // Modify the function signature to change the data type of the auto-parameter
            updateFunctionParameter(function, var.getName(), ptrStruct);
            successMessage.append("Updated function parameter '").append(var.getName())
                         .append("' with structure type: ").append(structDT.getName());
        } else {
            // Update local variable
            HighFunctionDBUtil.updateDBVariable(highVar.getSymbol(), null, ptrStruct, SourceType.USER_DEFINED);
            successMessage.append("Updated local variable '").append(var.getName())
                         .append("' with structure type: ").append(structDT.getName());
        }
        
        Msg.info(this, "Successfully created and applied structure: " + structDT.getName());
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
     * Find high variable by name in high function
     */
    private HighVariable findHighVariable(HighFunction highFunction, String variableName) {
        var localSymbolMap = highFunction.getLocalSymbolMap();
        var symbols = localSymbolMap.getSymbols();
        
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getName().equals(variableName)) {
                return symbol.getHighVariable();
            }
        }
        
        return null;
    }
    
    /**
     * Find variable in function by name
     */
    private Variable findVariable(Function function, String variableName) {
        // Check parameters
        for (Parameter param : function.getParameters()) {
            if (param.getName().equals(variableName)) {
                return param;
            }
        }
        
        // Check local variables
        for (Variable var : function.getLocalVariables()) {
            if (var.getName().equals(variableName)) {
                return var;
            }
        }
        
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