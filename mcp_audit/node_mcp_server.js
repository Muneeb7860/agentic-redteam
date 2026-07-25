/**
 * Real Node.js stdio Model Context Protocol (MCP) Server
 * Compliant with MCP v1.0 / JSON-RPC 2.0 Spec (2024-11-05).
 * Listens for JSON-RPC frames on process stdin and emits responses on stdout.
 */

const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

let requestId = 0;

const SERVER_CAPABILITIES = {
  protocolVersion: '2024-11-05',
  capabilities: {
    tools: { listChanged: false }
  },
  serverInfo: {
    name: 'swishos-mcp-sqlite-target',
    version: '0.5.0'
  }
};

const REGISTERED_TOOLS = [
  {
    name: 'query_db',
    description: 'Executes a SELECT query against the SQLite database.',
    inputSchema: { type: 'object', properties: { sql: { type: 'string' } }, required: ['sql'] }
  },
  {
    name: 'drop_table',
    description: 'DANGEROUS: Drops a table from the database.',
    inputSchema: { type: 'object', properties: { table_name: { type: 'string' } }, required: ['table_name'] }
  }
];

rl.on('line', (line) => {
  if (!line || !line.trim()) return;
  try {
    const req = JSON.parse(line.trim());
    const id = req.id !== undefined ? req.id : ++requestId;

    if (req.method === 'initialize') {
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: SERVER_CAPABILITIES
      }));
    } else if (req.method === 'notifications/initialized') {
      // No response needed for initialized notification
    } else if (req.method === 'tools/list') {
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: { tools: REGISTERED_TOOLS }
      }));
    } else if (req.method === 'tools/call') {
      const toolName = req.params?.name;
      const args = req.params?.arguments || {};

      if (!toolName) {
        console.log(JSON.stringify({
          jsonrpc: '2.0',
          id,
          error: { code: -32602, message: 'Invalid params: Missing tool name' }
        }));
        return;
      }

      if (toolName === 'drop_table') {
        const tableName = args.table_name || 'users';
        console.log(JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: `[MCP SERVER EXECUTED] DROP TABLE ${tableName}`
              }
            ],
            status: 'EXECUTED_DESTRUCTIVE_ACTION',
            executed: `DROP TABLE ${tableName}`,
            isError: false
          }
        }));
      } else {
        console.log(JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: `Query executed successfully for ${args.sql || 'SELECT'}`
              }
            ],
            isError: false
          }
        }));
      }
    } else {
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method '${req.method}' not found` }
      }));
    }
  } catch (err) {
    console.log(JSON.stringify({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700, message: 'Parse error: Invalid JSON' }
    }));
  }
});
