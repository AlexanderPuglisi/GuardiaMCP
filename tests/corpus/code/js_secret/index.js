const API_KEY = "sk-proj-abc123def456ghi789jkl012";

export function headers() {
  return { Authorization: `Bearer ${API_KEY}` };
}
