import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";

const globalObject = new Function("return this")();

export async function status(repo) {
  return new Promise((resolve, reject) => {
    execFile("git", ["status", "--short"], { cwd: repo }, (error, stdout) => (error ? reject(error) : resolve(stdout)));
  });
}

export async function weather(city) {
  const response = await fetch(`https://api.example.com/weather?city=${encodeURIComponent(city)}`);
  return response.json();
}

export async function notes(path) {
  return readFile(path, "utf8");
}

export const tools = [
  { name: "status", description: "Shows the git status of a repository." },
  { name: "weather", description: "Gets the weather for a city." },
];

export { globalObject };
