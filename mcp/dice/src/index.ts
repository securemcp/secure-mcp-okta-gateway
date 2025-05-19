import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import express from "express";

const app = express();
app.use(express.json());

const transport: StreamableHTTPServerTransport =
  new StreamableHTTPServerTransport({
    // ステートレスなサーバーの場合、undefined を指定する
    sessionIdGenerator: undefined,
  });

const mcpServer = new McpServer({ name: "dice-server", version: "0.0.1" });

// シンプルにサイコロを振った結果を返すツール
mcpServer.tool(
  // ツールの名前
  "dice",
  // ツールの説明
  "サイコロを振った結果を返します",
  // ツールの引数のスキーマ
  { sides: z.number().min(1).default(6).describe("サイコロの面の数") },
  // ツールが実行されたときの処理
  async (input) => {
    const sides = input.sides ?? 6;
    const result = Math.floor(Math.random() * sides) + 1;
    return {
      content: [
        {
          type: "text",
          text: result.toString(),
        },
      ],
    };
  },
);

const setupServer = async () => {
  await mcpServer.connect(transport);
};

// POST リクエストで受け付ける
app.post("/mcp", async (req, res) => {
  console.log("Received MCP request:", req.body);
  try {
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("Error handling MCP request:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          // JSON-RPC 2.0のエラーコードを指定
          // http://www.jsonrpc.org/specification#error_object
          code: -32603,
          message: "Internal server error",
        },
        id: null,
      });
    }
  }
});

// GET リクエストは SSE エンドポイントとの互換性のために実装する必要がある
// SSE エンドポイントを実装しない場合は、405 Method Not Allowed を返す
app.get("/mcp", async (req, res) => {
  console.log("Received GET MCP request");
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed.",
      },
      id: null,
    }),
  );
});

// DELETE リクエストはステートフルなサーバーの場合に実装する必要がある
app.delete("/mcp", async (req, res) => {
  console.log("Received DELETE MCP request");
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed.",
      },
      id: null,
    }),
  );
});

setupServer()
  .then(() => {
    app.listen(3000, () => {
      console.log("Server is running on http://localhost:3000/mcp");
    });
  })
  .catch((err) => {
    console.error("Error setting up server:", err);
    process.exit(1);
  });

// graceful shutdown
process.on("SIGINT", async () => {
  console.log("Shutting down server...");
  try {
    console.log(`Closing transport`);
    await transport.close();
  } catch (error) {
    console.error(`Error closing transport:`, error);
  }

  await mcpServer.close();
  console.log("Server shutdown complete");
  process.exit(0);
});
