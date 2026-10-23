import path from "node:path";

export function configPath(home) {
  return path.join(home, "AppData/Roaming/Claude/claude_desktop_config.json");
}
