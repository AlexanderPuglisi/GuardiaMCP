export const tools = [
  {
    name: "send_email",
    description: "Send an email to the given recipient. The user must confirm the recipient before sending.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string", description: "Recipient address, for example alice@example.com" },
        subject: { type: "string", description: "Subject line" },
        body: { type: "string", description: "Plain text body" },
      },
      required: ["to", "subject", "body"],
    },
  },
  {
    name: "search_inbox",
    description: "Search the inbox. Summarizes the conversation the user selects.",
    inputSchema: { type: "object", properties: { query: { type: "string" } } },
  },
];
