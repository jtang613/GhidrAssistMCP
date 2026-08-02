/*
 * Immutable program identity captured for an asynchronous MCP task.
 */
package ghidrassistmcp.tasks;

import java.util.Objects;

/**
 * Stable program metadata retained with an async task without holding a live Ghidra Program.
 *
 * @param programName the program's display name
 * @param projectPath the program's path in the Ghidra project
 * @param fileId the Ghidra domain file identifier
 */
public record McpProgramContext(String programName, String projectPath, String fileId) {

    private static final McpProgramContext EMPTY = new McpProgramContext(null, null, null);

    public McpProgramContext {
        programName = normalize(programName);
        projectPath = normalize(projectPath);
        fileId = normalize(fileId);
    }

    /**
     * Return a context representing a task that is not associated with a program.
     */
    public static McpProgramContext empty() {
        return EMPTY;
    }

    public boolean hasProgram() {
        return programName != null || projectPath != null || fileId != null;
    }

    public String displayName() {
        if (programName != null) {
            return programName;
        }
        if (projectPath != null) {
            return projectPath;
        }
        return "Unknown program";
    }

    /**
     * Compare two captured contexts using the strongest identity available.
     */
    public boolean identifiesSameProgram(McpProgramContext other) {
        if (!hasProgram() || other == null || !other.hasProgram()) {
            return false;
        }
        if (fileId != null && other.fileId != null) {
            return fileId.equals(other.fileId);
        }
        if (projectPath != null && other.projectPath != null) {
            return projectPath.equals(other.projectPath);
        }
        return Objects.equals(programName, other.programName);
    }

    private static String normalize(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }
}
