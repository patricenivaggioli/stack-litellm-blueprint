// Group every LiteLLM model call from one OpenCode session in Galileo.
// The header carries only the OpenCode session ID, never prompt content.
export default {
  id: "litellm-galileo-session",
  async setup(ctx) {
    const registration = await ctx.session.hook(
      "model.request",
      (event) => {
        event.headers["x-opencode-session-id"] = event.sessionID
      },
      { providerID: "litellm" },
    )

    return () => registration.dispose()
  },
}
