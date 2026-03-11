export async function runAgent() {
  const tools = ["delete_user", "list_users"];
  const systemPrompt = "system prompt";
  return {
    tools,
    systemPrompt,
    response: await Promise.resolve("unsafe")
  };
}
