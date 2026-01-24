/*
 * MCP Resource Registry for managing available resources.
 */
package ghidrassistmcp.resources;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Registry for MCP resources that can be queried by clients.
 */
public class McpResourceRegistry {

    private final Map<String, McpResource> resources = new ConcurrentHashMap<>();

    /**
     * Register a resource
     */
    public void registerResource(McpResource resource) {
        resources.put(resource.getName(), resource);
        Msg.info(this, "Registered MCP resource: " + resource.getName() + " (" + resource.getUriPattern() + ")");
    }

    /**
     * Unregister a resource
     */
    public void unregisterResource(String name) {
        McpResource removed = resources.remove(name);
        if (removed != null) {
            Msg.info(this, "Unregistered MCP resource: " + name);
        }
    }

    /**
     * Get all registered resources
     */
    public List<McpResource> getAllResources() {
        return new ArrayList<>(resources.values());
    }

    /**
     * Find a resource that can handle the given URI
     */
    public McpResource findResource(String uri) {
        for (McpResource resource : resources.values()) {
            if (resource.canHandle(uri)) {
                return resource;
            }
        }
        return null;
    }

    /**
     * Read content from a resource by URI
     *
     * @param uri The resource URI
     * @param program The current program
     * @return The resource content or null if not found
     */
    public String readResource(String uri, Program program) {
        McpResource resource = findResource(uri);
        if (resource == null) {
            Msg.warn(this, "No resource found for URI: " + uri);
            return null;
        }

        Map<String, String> params = resource.extractParams(uri);
        return resource.readContent(program, params);
    }

    /**
     * Get the number of registered resources
     */
    public int getResourceCount() {
        return resources.size();
    }
}
