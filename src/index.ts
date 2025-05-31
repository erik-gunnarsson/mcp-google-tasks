#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { google } from "googleapis";
import dotenv from "dotenv";

dotenv.config();

const { OAuth2 } = google.auth;

// Security: Validate environment variables
if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET || !process.env.REDIRECT_URI) {
  console.error("Missing required environment variables: CLIENT_ID, CLIENT_SECRET, REDIRECT_URI");
  process.exit(1);
}

if (!process.env.ACCESS_TOKEN || !process.env.REFRESH_TOKEN) {
  console.error("Missing required authentication tokens: ACCESS_TOKEN, REFRESH_TOKEN");
  process.exit(1);
}

const GOOGLE_TASKS_API_VERSION = "v1";
const oAuth2Client = new OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);

oAuth2Client.setCredentials({
  access_token: process.env.ACCESS_TOKEN,
  refresh_token: process.env.REFRESH_TOKEN,
});

const tasks = google.tasks({
  version: GOOGLE_TASKS_API_VERSION,
  auth: oAuth2Client,
});

// Security: Add input length limits to prevent DoS attacks
const MAX_TITLE_LENGTH = 256;
const MAX_NOTES_LENGTH = 8192;
const MAX_TASK_ID_LENGTH = 256;

// Security: Validate allowed task status values
const VALID_TASK_STATUSES = ['needsAction', 'completed'] as const;
type TaskStatus = typeof VALID_TASK_STATUSES[number];

interface CreateTaskArgs {
  title: string;
  notes?: string;
  taskId?: string;
  status?: string;
}

interface DeleteTaskArgs {
  taskId: string;
}

interface CompleteTaskArgs {
  taskId: string;
  status?: string;
}

// Security: Add input sanitization function
function sanitizeString(input: string): string {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }
  // Remove potentially dangerous characters and normalize whitespace
  return input.trim().replace(/[\x00-\x1F\x7F]/g, '');
}

// Security: Validate task status
function isValidTaskStatus(status: string): status is TaskStatus {
  return VALID_TASK_STATUSES.includes(status as TaskStatus);
}

// Type guard for CreateTaskArgs with enhanced security validation
export function isValidCreateTaskArgs(args: any): args is CreateTaskArgs {
  if (typeof args !== "object" || args === null) {
    return false;
  }

  // Validate title
  if (args.title !== undefined) {
    if (typeof args.title !== "string" || args.title.length > MAX_TITLE_LENGTH) {
      return false;
    }
  }

  // Validate notes
  if (args.notes !== undefined) {
    if (typeof args.notes !== "string" || args.notes.length > MAX_NOTES_LENGTH) {
      return false;
    }
  }

  // Validate taskId
  if (args.taskId !== undefined) {
    if (typeof args.taskId !== "string" || args.taskId.length > MAX_TASK_ID_LENGTH) {
      return false;
    }
  }

  // Validate status
  if (args.status !== undefined) {
    if (typeof args.status !== "string" || !isValidTaskStatus(args.status)) {
      return false;
    }
  }

  return true;
}

// Security: Add specific validation for delete task args
function isValidDeleteTaskArgs(args: any): args is DeleteTaskArgs {
  return (
    typeof args === "object" &&
    args !== null &&
    typeof args.taskId === "string" &&
    args.taskId.length > 0 &&
    args.taskId.length <= MAX_TASK_ID_LENGTH
  );
}

// Security: Add specific validation for complete task args
function isValidCompleteTaskArgs(args: any): args is CompleteTaskArgs {
  if (typeof args !== "object" || args === null) {
    return false;
  }

  if (typeof args.taskId !== "string" || args.taskId.length === 0 || args.taskId.length > MAX_TASK_ID_LENGTH) {
    return false;
  }

  if (args.status !== undefined && (typeof args.status !== "string" || !isValidTaskStatus(args.status))) {
    return false;
  }

  return true;
}

// Security: Safe error message function to prevent information leakage
function getSafeErrorMessage(error: any): string {
  if (error instanceof Error) {
    // Log full error for debugging but return sanitized message
    console.error('Full error details:', error);
    return 'An error occurred while processing your request';
  }
  return 'Unknown error occurred';
}

class TasksServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: "google-tasks-server",
        version: "1.0.0",
      },
      {
        capabilities: {
          resources: {},
          tools: {},
        },
      }
    );

    this.setupHandlers();
    this.setupErrorHandling();
  }

  private setupErrorHandling(): void {
    this.server.onerror = (error) => {
      console.error("[MCP Error]", error);
    };

    process.on("SIGINT", async () => {
      await this.server.close();
      process.exit(0);
    });

    // Security: Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error('Uncaught exception:', error);
      process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled rejection at:', promise, 'reason:', reason);
      process.exit(1);
    });
  }

  private setupHandlers(): void {
    this.setupResourceHandlers();
    this.setupToolHandlers();
  }

  private setupResourceHandlers(): void {
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: [
        {
          uri: "tasks://default",
          name: "Default Task List",
          mimeType: "application/json",
          description: "Manage your Google Tasks",
        },
      ],
    }));

    this.server.setRequestHandler(
      ReadResourceRequestSchema,
      async (request) => {
        if (request.params.uri !== "tasks://default") {
          throw new McpError(
            ErrorCode.InvalidRequest,
            `Unknown resource: ${request.params.uri}`
          );
        }

        try {
          const response = await tasks.tasks.list({
            tasklist: "@default",
          });

          return {
            contents: [
              {
                uri: request.params.uri,
                mimeType: "application/json",
                text: JSON.stringify(response.data.items, null, 2),
              },
            ],
          };
        } catch (error) {
          throw new McpError(
            ErrorCode.InternalError,
            getSafeErrorMessage(error)
          );
        }
      }
    );
  }

  private setupToolHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: "create_task",
          description: "Create a new task in Google Tasks",
          inputSchema: {
            type: "object",
            properties: {
              title: { 
                type: "string", 
                description: "Title of the task",
                maxLength: MAX_TITLE_LENGTH
              },
              notes: { 
                type: "string", 
                description: "Notes for the task",
                maxLength: MAX_NOTES_LENGTH
              },
            },
            required: ["title"],
          },
        },
        {
          name: "list_tasks",
          description: "List all tasks in the default task list",
          inputSchema: {
            type: "object",
            properties: {},
          },
        },
        {
          name: "delete_task",
          description: "Delete a task from the default task list",
          inputSchema: {
            type: "object",
            properties: {
              taskId: { 
                type: "string", 
                description: "ID of the task to delete",
                maxLength: MAX_TASK_ID_LENGTH
              },
            },
            required: ["taskId"],
          },
        },
        {
          name: "complete_task",
          description: "Toggle the completion status of a task",
          inputSchema: {
            type: "object",
            properties: {
              taskId: { 
                type: "string", 
                description: "ID of the task to toggle completion status",
                maxLength: MAX_TASK_ID_LENGTH
              },
              status: { 
                type: "string", 
                description: "Status of task, needsAction or completed",
                enum: VALID_TASK_STATUSES
              },
            },
            required: ["taskId"],
          },
        },
      ],
    }));
    
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (request.params.name === "list_tasks") {
        try {
          const response = await tasks.tasks.list({
            tasklist: "@default",
          });
    
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(response.data.items, null, 2),
              },
            ],
          };
        } catch (error) {
          throw new McpError(
            ErrorCode.InternalError,
            getSafeErrorMessage(error)
          );
        }
      }
    
      if (request.params.name === "create_task") {
        if (!isValidCreateTaskArgs(request.params.arguments)) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Invalid arguments for creating a task. 'title' must be a string (max 256 chars), 'notes' must be a string (max 8192 chars), and 'status' must be 'needsAction' or 'completed'."
          );
        }
        const args = request.params.arguments;

        // Security: Sanitize inputs
        const sanitizedTitle = sanitizeString(args.title);
        const sanitizedNotes = args.notes ? sanitizeString(args.notes) : undefined;

        if (!sanitizedTitle) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Task title cannot be empty after sanitization."
          );
        }
    
        try {
          const response = await tasks.tasks.insert({
            tasklist: "@default",
            requestBody: {
              title: sanitizedTitle,
              notes: sanitizedNotes,
              status: args.status,
            },
          });
    
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(response.data, null, 2),
              },
            ],
          };
        } catch (error) {
          throw new McpError(
            ErrorCode.InternalError,
            getSafeErrorMessage(error)
          );
        }
      }

      if (request.params.name === "delete_task") {
        if (!isValidDeleteTaskArgs(request.params.arguments)) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Invalid arguments for deleting a task. 'taskId' must be a non-empty string."
          );
        }
        const args = request.params.arguments;
        const taskId = sanitizeString(args.taskId);

        if (!taskId) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Task ID cannot be empty after sanitization."
          );
        }

        try {
          await tasks.tasks.delete({
            tasklist: "@default",
            task: taskId,
          });
    
          return {
            content: [
              {
                type: "text",
                text: "Task deleted successfully.",
              },
            ],
          };
        } catch (error) {
          throw new McpError(
            ErrorCode.InternalError,
            getSafeErrorMessage(error)
          );
        }
      }

      if (request.params.name === "complete_task") {
        if (!isValidCompleteTaskArgs(request.params.arguments)) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Invalid arguments for completing a task. 'taskId' must be a non-empty string and 'status' must be 'needsAction' or 'completed'."
          );
        }
        const args = request.params.arguments;
        const taskId = sanitizeString(args.taskId);
        const newStatus = args.status || 'completed'; // Default to completed if not specified

        if (!taskId) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Task ID cannot be empty after sanitization."
          );
        }

        if (!isValidTaskStatus(newStatus)) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Invalid task status. Must be 'needsAction' or 'completed'."
          );
        }
    
        try {
          const updateResponse = await tasks.tasks.patch({
            tasklist: "@default",
            task: taskId,
            requestBody: { status: newStatus },
          });
    
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(updateResponse.data, null, 2),
              },
            ],
          };
        } catch (error) {
          throw new McpError(
            ErrorCode.InternalError,
            getSafeErrorMessage(error)
          );
        }
      }

      throw new McpError(
        ErrorCode.MethodNotFound,
        `Unknown tool: ${request.params.name}`
      );
    });

  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("Google Tasks MCP server running on stdio");
  }
}

const server = new TasksServer();
server.run().catch(console.error);