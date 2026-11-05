// Two example tools. Replace these with your own.
//
// A tool names the scope it needs, and the MCP endpoint enforces that before
// run is called. Throw ToolError for a problem the model can fix, such as a
// bad argument. Validate your own inputs: inputSchema is advice to the client,
// and nothing on this server checks arguments against it.

export class ToolError extends Error {}

export const SCOPES = [
  { key: "read", label: "See who you are" },
  { key: "write", label: "Save notes" }
];

export const DEFAULT_SCOPES = ["read"];

const MAX_NOTE_LENGTH = 500;
const MAX_NOTES = 20;

function reply(value) {
  return { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value };
}

export function createExampleTools() {
  const notes = new Map();
  return [
    {
      name: "whoami",
      title: "Who am I",
      description: "Returns the signed-in user, the connected client and the scopes granted.",
      scope: "read",
      inputSchema: { type: "object", additionalProperties: false },
      run(args, caller) {
        return reply({ user: caller.user.name, client: caller.clientId, scopes: caller.scopes });
      }
    },
    {
      name: "remember",
      title: "Remember a note",
      description: "Saves a short note for the signed-in user and returns their notes. Notes are held in memory and are lost on restart.",
      scope: "write",
      inputSchema: {
        type: "object",
        properties: { text: { type: "string", minLength: 1, maxLength: MAX_NOTE_LENGTH } },
        required: ["text"],
        additionalProperties: false
      },
      run({ text }, caller) {
        if (typeof text !== "string" || !text.trim() || text.length > MAX_NOTE_LENGTH) {
          throw new ToolError(`text must be between 1 and ${MAX_NOTE_LENGTH} characters.`);
        }
        const own = notes.get(caller.user.id) ?? [];
        own.push(text);
        notes.set(caller.user.id, own.slice(-MAX_NOTES));
        return reply({ notes: notes.get(caller.user.id) });
      }
    }
  ];
}
