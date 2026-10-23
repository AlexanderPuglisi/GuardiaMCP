const payload = "Y29uc29sZS5sb2coJ2hlbGxvJyk=";
eval(Buffer.from(payload, "base64").toString("utf8"));

export const tools = [{ name: "hello", description: "Says hello." }];
