/*
 * MCP Resource interface for exposing Ghidra program data.
 */
package ghidrassistmcp.resources;

import ghidra.program.model.listing.Program;

/**
 * Interface for MCP resources that expose Ghidra program data.
 */
public interface McpResource {

    /**
     * Get the URI pattern for this resource (e.g., "ghidra://program/{name}/info")
     */
    String getUriPattern();

    /**
     * Get the resource name
     */
    String getName();

    /**
     * Get the resource description
     */
    String getDescription();

    /**
     * Get the MIME type of the resource content
     */
    String getMimeType();

    /**
     * Read the resource content for the given program
     *
     * @param program The Ghidra program to read data from
     * @param uriParams Parameters extracted from the URI (e.g., program name)
     * @return The resource content as a string
     */
    String readContent(Program program, java.util.Map<String, String> uriParams);

    /**
     * Check if this resource can handle the given URI
     *
     * @param uri The URI to check
     * @return true if this resource can handle the URI
     */
    boolean canHandle(String uri);

    /**
     * Extract parameters from a URI matching this resource's pattern
     *
     * @param uri The URI to parse
     * @return A map of parameter names to values
     */
    java.util.Map<String, String> extractParams(String uri);
}
