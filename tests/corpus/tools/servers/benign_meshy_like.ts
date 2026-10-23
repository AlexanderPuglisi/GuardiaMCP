import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer(
  { name: "models", version: "1.4.0" },
  { instructions: "Generate 3D models. Confirm the cost with the user before calling paid tools." },
);

server.registerTool(
  "models_generate",
  {
    title: "Generate model",
    description:
      "Create a 3D model from text. IMPORTANT: always use absolute paths. " +
      "Ask the user for approval before calling this tool, because it costs credits. " +
      "NEVER base64-encode files yourself. With a task_id in hand, use models_status instead.",
    inputSchema: {
      prompt: z.string().describe("What to generate"),
      output_dir: z.string().describe("Absolute folder where the file is saved"),
    },
    annotations: { readOnlyHint: false, openWorldHint: true },
  },
  async () => ({ content: [] }),
);

server.registerTool(
  "models_status",
  {
    title: "Task status",
    description: "Check the status of a task. Tasks created through the API do not appear in the web app.",
    inputSchema: { task_id: z.string().describe("Task identifier") },
    annotations: { readOnlyHint: true },
  },
  async () => ({ content: [] }),
);
