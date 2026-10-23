const description = `Create a PDF from markdown.

Use a page break like this:
<div style="page-break-before: always;"></div>

The file is saved where the user asks.`;

export const writePdf = {
  name: "write_pdf",
  description,
  inputSchema: { type: "object", properties: { path: { type: "string" }, markdown: { type: "string" } } },
};

export const another = { name: "make_pdf", description: description };
