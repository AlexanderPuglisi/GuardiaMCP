import { execSync } from "node:child_process";

export function log(branch) {
  return execSync(`git log ${branch}`).toString();
}
