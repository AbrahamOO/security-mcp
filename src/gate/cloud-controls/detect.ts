import { HclBlock, parseResourceBlocks } from "./hcl.js";
import { CloudRule } from "./types.js";

export type Violation = {
  rule: CloudRule;
  file: string;
  line: number;
  block?: HclBlock;
  // Why the resource is flagged — drives the Finding evidence line.
  reason: string;
};

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

function blockBody(text: string, block: HclBlock): string {
  return text.slice(block.bodyStart, block.bodyEnd);
}

function compile(pattern: string): RegExp {
  return new RegExp(pattern, "i");
}

/**
 * Does the file contain a resource of `companionType` that references
 * `origType.name` (the offending resource)? Used for cross-resource rules such
 * as an S3 bucket needing a matching aws_s3_bucket_public_access_block.
 */
function companionExists(
  blocks: HclBlock[],
  fullText: string,
  companionType: string,
  origType: string,
  name: string
): boolean {
  const ref = `${origType}.${name}`;
  return blocks.some(
    (b) => b.type === companionType && blockBody(fullText, b).includes(ref)
  );
}

/** Evaluate every terraform-target rule against one parsed HCL document. */
export function detectTerraform(file: string, text: string, rules: CloudRule[]): Violation[] {
  const blocks = parseResourceBlocks(text);
  if (blocks.length === 0) return [];
  const violations: Violation[] = [];

  for (const rule of rules) {
    if (rule.detect.target !== "terraform") continue;
    const { resourceType, forbid, require, requireCompanionType } = rule.detect;
    const forbidRe = forbid ? compile(forbid) : null;
    const requireRe = require ? compile(require) : null;

    for (const block of blocks) {
      if (block.type !== resourceType) continue;
      const body = blockBody(text, block);
      const line = lineOf(text, block.start);

      if (forbidRe && forbidRe.test(body)) {
        violations.push({ rule, file, line, block, reason: "insecure value present" });
        continue;
      }
      if (requireRe && !requireRe.test(body)) {
        violations.push({ rule, file, line, block, reason: "secure setting missing" });
        continue;
      }
      if (
        requireCompanionType &&
        !companionExists(blocks, text, requireCompanionType, resourceType, block.name)
      ) {
        violations.push({
          rule,
          file,
          line,
          block,
          reason: `missing companion ${requireCompanionType}`
        });
      }
    }
  }
  return violations;
}
