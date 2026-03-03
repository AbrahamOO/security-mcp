export function detectSurfaces(changedFiles: string[]) {
  const has = (re: RegExp) => changedFiles.some((f) => re.test(f));

  return {
    web: has(/^(app|pages|components|src)\/.*\.(ts|tsx|js|jsx)$/) || has(/^next\.config\./),
    api: has(/^(app\/api|src\/api|api|server)\//),
    infra: has(/^(infra|terraform|iac|k8s|helm|cloudbuild|\.github\/workflows)\//),
    mobileIos: has(/^(ios|.*\.xcodeproj|.*\.xcworkspace|.*Info\.plist|Podfile)/),
    mobileAndroid: has(/^(android|.*\/AndroidManifest\.xml|.*\/build\.gradle(\.kts)?|gradle\.properties)/),
    ai: has(/^(ai|llm|prompt|rag|agents)\//) || has(/(openai|anthropic|vertexai|langchain|llamaindex)/)
  };
}