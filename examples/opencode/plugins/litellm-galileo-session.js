// Give LiteLLM a stable ID for all model calls in one OpenCode session.
// The proxy uses this only for Galileo session grouping.
export const LiteLLMGalileoSession = async () => ({
  "chat.headers": async (input, output) => {
    if (input.model.providerID !== "litellm") return
    output.headers["x-opencode-session-id"] = input.sessionID
  },
})
