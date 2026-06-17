export function detectSurfaces(changedFiles: string[]) {
  const has = (re: RegExp) => changedFiles.some((f) => re.test(f));

  return {
    web: has(/^(app|pages|components|src)\/.*\.(ts|tsx|js|jsx)$/) || has(/^next\.config\./),
    api: has(/^(app\/api|src\/api|api|server)\//),
    infra:
      has(/^(infra|terraform|iac|k8s|helm|cloudbuild|argo(cd)?|flux|gitops|\.github\/workflows)\//) ||
      has(/\.(tf|tfvars)(\.json)?$/) ||
      has(/\.(bicep)$/i) ||
      has(/(databricks|snowflake|cloudformation|cfn|template\.ya?ml)/i) ||
      has(/(^|\/)docker-compose(\.[\w-]+)?\.ya?ml$/i),
    mobileIos: has(/^(ios|.*\.xcodeproj|.*\.xcworkspace|.*Info\.plist|Podfile)/),
    mobileAndroid: has(/^(android|.*\/AndroidManifest\.xml|.*\/build\.gradle(\.kts)?|gradle\.properties)/),
    ai: has(/^(ai|llm|prompt|rag|agents)\//) || has(/(openai|anthropic|vertexai|langchain|llamaindex)/),
    // Agentic-instruction surface: files an AI coding agent ingests as authority
    // the moment it opens the repo. Path-based and evaluated for ANY repo, since
    // a poisoned instruction file is the attack vector even in non-AI projects.
    agentic:
      has(/(^|\/)(SKILL|AGENTS|CLAUDE)\.md$/i) ||
      has(/(^|\/)\.claude\//) ||
      has(/(^|\/)\.cursor(rules)?(\/|$)/i) ||
      has(/(^|\/)\.windsurfrules$/i) ||
      has(/(^|\/)\.github\/copilot-instructions\.md$/i) ||
      has(/(^|\/)\.mcp\.json$/)
  };
}