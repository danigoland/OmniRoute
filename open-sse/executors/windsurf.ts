/**
 * WindsurfExecutor — routes the retained `windsurf` provider through Devin's
 * direct Connect protocol.
 *
 * Authentication exchanges the imported Windsurf session token for a short-lived
 * JWT through AuthService/GetUserJwt. Chat then streams from
 * ApiServerService/GetChatMessage over gzip-framed Connect protobuf, preserving
 * client tool definitions, tool-call history, and tool results.
 */

import {
  BaseExecutor,
  mergeUpstreamExtraHeaders,
  type ExecuteInput,
  type ExecutorExecuteResult,
} from "./base.ts";
import { PROVIDERS } from "../config/constants.ts";
import { randomUUID } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import { windsurfProvider } from "../config/providers/registry/windsurf/index.ts";

const DEVIN_API_URL = "https://server.codeium.com";
const CHAT_PATH = "/exa.api_server_pb.ApiServerService/GetChatMessage";
const AUTH_PATH = "/exa.auth_pb.AuthService/GetUserJwt";
const DEVIN_IDE_VERSION = "3.2.23";
const DEVIN_EXTENSION_VERSION = "1.48.2";
const DEVIN_SESSION_TOKEN_PREFIX = "devin-session-token$";
const DEVIN_DEFAULT_STOP_PATTERNS = [
  "<|user|>",
  "<|bot|>",
  "<|context_request|>",
  "<|endoftext|>",
  "<|end_of_turn|>",
];
/**
 * Minimal system prompt used only when a client sends `tools` but no
 * system/developer message. Cascade validates that tool requests carry a
 * non-empty `prompt` and answers `invalid_argument` otherwise.
 */
const DEVIN_DEFAULT_TOOL_PROMPT = "You are a helpful coding assistant with access to tools.";
const MAX_CONNECT_FRAME_PAYLOAD = 16 * 1024 * 1024;
const TEXT_ENC = new TextEncoder();
const TEXT_DEC = new TextDecoder();

type ProtoField = { wireType: number; value: number | Uint8Array };
type ImageData = { base64Data: string; mimeType: string };
type OpenAIMessage = {
  role?: string;
  content?: unknown;
  tool_call_id?: string;
  tool_calls?: unknown;
};
type OpenAITool = {
  type?: string;
  function?: { name?: unknown; description?: unknown; parameters?: unknown };
};
type DecodedChatResponse = {
  messageId: string;
  deltaText: string;
  stopReason: number;
  deltaToolCalls: Array<{ id: string; name: string; argumentsJson: string }>;
  usage?: {
    inputTokens: number;
    outputTokens: number;
    cacheReadTokens: number;
    cacheWriteTokens: number;
  };
};

class InvalidRequestError extends Error {}

// ─── Model alias normalizer ──────────────────────────────────────────────────
//
// Model names are passed directly to the Windsurf API as ModelOrAlias strings.
// The API accepts the catalog names as-is (e.g. "claude-4.5-sonnet", "swe-1.6-fast").
//
// This table handles only OmniRoute-style backwards-compat aliases where users
// might type dashes instead of dots (e.g. "swe-1-6-fast" → "swe-1.6-fast").

// Model IDs — source: model_configs_v2.bin extracted from Devin CLI binary.
// OmniRoute uses dot-notation user IDs (e.g. "gpt-5.5-high").
// Windsurf API accepts dash-notation modelUids (e.g. "gpt-5-5-high").
// This map normalises dot→dash for newer models and handles legacy aliases.
const MODEL_ALIAS_MAP: Record<string, string> = {
  // ── Claude ────────────────────────────────────────────────────────────
  "claude-4.5-haiku": "MODEL_PRIVATE_11", // legacy alias (not in live catalog)
  "claude-4.5-opus": "MODEL_CLAUDE_4_5_OPUS", // legacy alias (not in live catalog)
  "claude-4.5-opus-thinking": "MODEL_CLAUDE_4_5_OPUS_THINKING", // legacy alias (not in live catalog)
  "claude-4.5-sonnet": "MODEL_PRIVATE_2", // legacy alias (not in live catalog)
  "claude-4.5-sonnet-thinking": "MODEL_PRIVATE_3", // legacy alias (not in live catalog)
  "claude-haiku-4.5": "MODEL_PRIVATE_11", // legacy alias (not in live catalog)
  "claude-opus-4.5-thinking": "MODEL_CLAUDE_4_5_OPUS_THINKING", // legacy alias (not in live catalog)
  "claude-opus-4.6": "claude-opus-4-6",
  "claude-opus-4.6-1m": "claude-opus-4-6-1m",
  "claude-opus-4.6-thinking": "claude-opus-4-6-thinking",
  "claude-opus-4.6-thinking-1m": "claude-opus-4-6-thinking-1m",
  "claude-opus-4.7-high": "claude-opus-4-7-high",
  "claude-opus-4.7-low": "claude-opus-4-7-low",
  "claude-opus-4.7-max": "claude-opus-4-7-max",
  "claude-opus-4.7-medium": "claude-opus-4-7-medium",
  "claude-opus-4.7-review": "opus-4-7-review", // legacy alias (not in live catalog)
  "claude-opus-4.7-xhigh": "claude-opus-4-7-xhigh",
  "claude-opus-4.8-high": "claude-opus-4-8-high",
  "claude-opus-4.8-high-fast": "claude-opus-4-8-high-fast",
  "claude-opus-4.8-low": "claude-opus-4-8-low",
  "claude-opus-4.8-low-fast": "claude-opus-4-8-low-fast",
  "claude-opus-4.8-max": "claude-opus-4-8-max",
  "claude-opus-4.8-max-fast": "claude-opus-4-8-max-fast",
  "claude-opus-4.8-medium": "claude-opus-4-8-medium",
  "claude-opus-4.8-medium-fast": "claude-opus-4-8-medium-fast",
  "claude-opus-4.8-xhigh": "claude-opus-4-8-xhigh",
  "claude-opus-4.8-xhigh-fast": "claude-opus-4-8-xhigh-fast",
  "claude-sonnet-4.5-thinking": "MODEL_PRIVATE_3", // legacy alias (not in live catalog)
  "claude-sonnet-4.6": "claude-sonnet-4-6",
  "claude-sonnet-4.6-1m": "claude-sonnet-4-6-1m",
  "claude-sonnet-4.6-thinking": "claude-sonnet-4-6-thinking",
  "claude-sonnet-4.6-thinking-1m": "claude-sonnet-4-6-thinking-1m",
  // ── GLM ───────────────────────────────────────────────────────────────
  "glm-5.1": "glm-5-1", // legacy alias (not in live catalog)
  "glm-5.2": "glm-5-2",
  "glm-5.2-1m": "glm-5-2-1m",
  "glm-5.2-max": "glm-5-2-max",
  "glm-5.2-max-1m": "glm-5-2-max-1m",
  "glm-5.2-none": "glm-5-2-none",
  "glm-5.2-none-1m": "glm-5-2-none-1m",
  // ── Gemini ────────────────────────────────────────────────────────────
  "gemini-2.5-pro": "MODEL_GOOGLE_GEMINI_2_5_PRO", // legacy alias (not in live catalog)
  "gemini-3.0-flash-high": "MODEL_GOOGLE_GEMINI_3_0_FLASH_HIGH", // legacy alias (not in live catalog)
  "gemini-3.0-flash-low": "MODEL_GOOGLE_GEMINI_3_0_FLASH_LOW", // legacy alias (not in live catalog)
  "gemini-3.0-flash-medium": "MODEL_GOOGLE_GEMINI_3_0_FLASH_MEDIUM", // legacy alias (not in live catalog)
  "gemini-3.0-flash-minimal": "MODEL_GOOGLE_GEMINI_3_0_FLASH_MINIMAL", // legacy alias (not in live catalog)
  "gemini-3.1-pro": "gemini-3-1-pro-high", // legacy alias (not in live catalog)
  "gemini-3.1-pro-high": "gemini-3-1-pro-high",
  "gemini-3.1-pro-low": "gemini-3-1-pro-low",
  "gemini-3.5-flash-high": "gemini-3-5-flash-high",
  "gemini-3.5-flash-low": "gemini-3-5-flash-low",
  "gemini-3.5-flash-medium": "gemini-3-5-flash-medium",
  "gemini-3.5-flash-minimal": "gemini-3-5-flash-minimal",
  "gemini-3.6-flash-high": "gemini-3-6-flash-high",
  "gemini-3.6-flash-low": "gemini-3-6-flash-low",
  "gemini-3.6-flash-medium": "gemini-3-6-flash-medium",
  "gemini-3.6-flash-minimal": "gemini-3-6-flash-minimal",
  // ── Grok ──────────────────────────────────────────────────────────────
  "grok-4.5-high": "grok-4-5-high",
  "grok-4.5-low": "grok-4-5-low",
  "grok-4.5-medium": "grok-4-5-medium",
  // ── Kimi ──────────────────────────────────────────────────────────────
  "kimi-k2.5": "kimi-k2-5", // legacy alias (not in live catalog)
  "kimi-k2.6": "kimi-k2-6", // legacy alias (not in live catalog)
  // ── OpenAI ────────────────────────────────────────────────────────────
  "gpt-4.1": "MODEL_CHAT_GPT_4_1_2025_04_14", // legacy alias (not in live catalog)
  "gpt-4.1-mini": "gpt-4.1-mini", // legacy alias (not in live catalog)
  "gpt-4o": "MODEL_CHAT_GPT_4O_2024_08_06", // legacy alias (not in live catalog)
  "gpt-5": "gpt-5", // legacy alias (not in live catalog)
  "gpt-5.2-high": "MODEL_GPT_5_2_HIGH", // legacy alias (not in live catalog)
  "gpt-5.2-low": "MODEL_GPT_5_2_LOW", // legacy alias (not in live catalog)
  "gpt-5.2-medium": "MODEL_GPT_5_2_MEDIUM", // legacy alias (not in live catalog)
  "gpt-5.2-none": "MODEL_GPT_5_2_NONE", // legacy alias (not in live catalog)
  "gpt-5.2-xhigh": "MODEL_GPT_5_2_XHIGH", // legacy alias (not in live catalog)
  "gpt-5.3-codex": "gpt-5-3-codex-medium", // legacy alias (not in live catalog)
  "gpt-5.3-codex-high": "gpt-5-3-codex-high",
  "gpt-5.3-codex-high-fast": "gpt-5-3-codex-high-priority", // legacy alias (not in live catalog)
  "gpt-5.3-codex-high-priority": "gpt-5-3-codex-high-priority",
  "gpt-5.3-codex-low": "gpt-5-3-codex-low",
  "gpt-5.3-codex-low-fast": "gpt-5-3-codex-low-priority", // legacy alias (not in live catalog)
  "gpt-5.3-codex-low-priority": "gpt-5-3-codex-low-priority",
  "gpt-5.3-codex-medium": "gpt-5-3-codex-medium",
  "gpt-5.3-codex-medium-fast": "gpt-5-3-codex-medium-priority", // legacy alias (not in live catalog)
  "gpt-5.3-codex-medium-priority": "gpt-5-3-codex-medium-priority",
  "gpt-5.3-codex-xhigh": "gpt-5-3-codex-xhigh",
  "gpt-5.3-codex-xhigh-fast": "gpt-5-3-codex-xhigh-priority", // legacy alias (not in live catalog)
  "gpt-5.3-codex-xhigh-priority": "gpt-5-3-codex-xhigh-priority",
  "gpt-5.4": "gpt-5-4-medium", // legacy alias (not in live catalog)
  "gpt-5.4-high": "gpt-5-4-high",
  "gpt-5.4-high-fast": "gpt-5-4-high-priority", // legacy alias (not in live catalog)
  "gpt-5.4-high-priority": "gpt-5-4-high-priority",
  "gpt-5.4-low": "gpt-5-4-low",
  "gpt-5.4-low-fast": "gpt-5-4-low-priority", // legacy alias (not in live catalog)
  "gpt-5.4-low-priority": "gpt-5-4-low-priority",
  "gpt-5.4-medium": "gpt-5-4-medium",
  "gpt-5.4-medium-fast": "gpt-5-4-medium-priority", // legacy alias (not in live catalog)
  "gpt-5.4-medium-priority": "gpt-5-4-medium-priority",
  "gpt-5.4-mini-high": "gpt-5-4-mini-high",
  "gpt-5.4-mini-low": "gpt-5-4-mini-low",
  "gpt-5.4-mini-medium": "gpt-5-4-mini-medium",
  "gpt-5.4-mini-xhigh": "gpt-5-4-mini-xhigh",
  "gpt-5.4-none": "gpt-5-4-none",
  "gpt-5.4-none-fast": "gpt-5-4-none-priority", // legacy alias (not in live catalog)
  "gpt-5.4-none-priority": "gpt-5-4-none-priority",
  "gpt-5.4-xhigh": "gpt-5-4-xhigh",
  "gpt-5.4-xhigh-fast": "gpt-5-4-xhigh-priority", // legacy alias (not in live catalog)
  "gpt-5.4-xhigh-priority": "gpt-5-4-xhigh-priority",
  "gpt-5.5": "gpt-5-5-medium", // legacy alias (not in live catalog)
  "gpt-5.5-high": "gpt-5-5-high",
  "gpt-5.5-high-fast": "gpt-5-5-high-priority", // legacy alias (not in live catalog)
  "gpt-5.5-high-priority": "gpt-5-5-high-priority",
  "gpt-5.5-low": "gpt-5-5-low",
  "gpt-5.5-low-fast": "gpt-5-5-low-priority", // legacy alias (not in live catalog)
  "gpt-5.5-low-priority": "gpt-5-5-low-priority",
  "gpt-5.5-medium": "gpt-5-5-medium",
  "gpt-5.5-medium-fast": "gpt-5-5-medium-priority", // legacy alias (not in live catalog)
  "gpt-5.5-medium-priority": "gpt-5-5-medium-priority",
  "gpt-5.5-none": "gpt-5-5-none",
  "gpt-5.5-none-fast": "gpt-5-5-none-priority", // legacy alias (not in live catalog)
  "gpt-5.5-none-priority": "gpt-5-5-none-priority",
  "gpt-5.5-review": "gpt-5-5-review", // legacy alias (not in live catalog)
  "gpt-5.5-xhigh": "gpt-5-5-xhigh",
  "gpt-5.5-xhigh-fast": "gpt-5-5-xhigh-priority", // legacy alias (not in live catalog)
  "gpt-5.5-xhigh-priority": "gpt-5-5-xhigh-priority",
  "gpt-5.6-luna-high": "gpt-5-6-luna-high",
  "gpt-5.6-luna-high-priority": "gpt-5-6-luna-high-priority",
  "gpt-5.6-luna-low": "gpt-5-6-luna-low",
  "gpt-5.6-luna-low-priority": "gpt-5-6-luna-low-priority",
  "gpt-5.6-luna-max": "gpt-5-6-luna-max",
  "gpt-5.6-luna-medium": "gpt-5-6-luna-medium",
  "gpt-5.6-luna-medium-priority": "gpt-5-6-luna-medium-priority",
  "gpt-5.6-luna-none": "gpt-5-6-luna-none",
  "gpt-5.6-luna-none-priority": "gpt-5-6-luna-none-priority",
  "gpt-5.6-luna-xhigh": "gpt-5-6-luna-xhigh",
  "gpt-5.6-luna-xhigh-priority": "gpt-5-6-luna-xhigh-priority",
  "gpt-5.6-sol-high": "gpt-5-6-sol-high",
  "gpt-5.6-sol-high-priority": "gpt-5-6-sol-high-priority",
  "gpt-5.6-sol-low": "gpt-5-6-sol-low",
  "gpt-5.6-sol-low-priority": "gpt-5-6-sol-low-priority",
  "gpt-5.6-sol-max": "gpt-5-6-sol-max",
  "gpt-5.6-sol-medium": "gpt-5-6-sol-medium",
  "gpt-5.6-sol-medium-priority": "gpt-5-6-sol-medium-priority",
  "gpt-5.6-sol-none": "gpt-5-6-sol-none",
  "gpt-5.6-sol-none-priority": "gpt-5-6-sol-none-priority",
  "gpt-5.6-sol-xhigh": "gpt-5-6-sol-xhigh",
  "gpt-5.6-sol-xhigh-priority": "gpt-5-6-sol-xhigh-priority",
  "gpt-5.6-terra-high": "gpt-5-6-terra-high",
  "gpt-5.6-terra-high-priority": "gpt-5-6-terra-high-priority",
  "gpt-5.6-terra-low": "gpt-5-6-terra-low",
  "gpt-5.6-terra-low-priority": "gpt-5-6-terra-low-priority",
  "gpt-5.6-terra-max": "gpt-5-6-terra-max",
  "gpt-5.6-terra-medium": "gpt-5-6-terra-medium",
  "gpt-5.6-terra-medium-priority": "gpt-5-6-terra-medium-priority",
  "gpt-5.6-terra-none": "gpt-5-6-terra-none",
  "gpt-5.6-terra-none-priority": "gpt-5-6-terra-none-priority",
  "gpt-5.6-terra-xhigh": "gpt-5-6-terra-xhigh",
  "gpt-5.6-terra-xhigh-priority": "gpt-5-6-terra-xhigh-priority",
  // ── SWE ───────────────────────────────────────────────────────────────
  "swe-1.5": "swe-1p5", // legacy alias (not in live catalog)
  "swe-1.5-fast": "swe-1p5", // legacy alias (not in live catalog)
  "swe-1.6": "swe-1-6",
  "swe-1.6-fast": "swe-1-6-fast",
  "swe-1.7": "swe-1-7",
  "swe-1.7-lightning": "swe-1-7-lightning",
  "swe-1.7-medium": "swe-1-7-medium",
};

function resolveWsModelId(model: string): string {
  return MODEL_ALIAS_MAP[model] ?? model;
}

// ─── Minimal protobuf encoder ────────────────────────────────────────────────

function encodeVarint(value: number): Uint8Array {
  const bytes: number[] = [];
  let remaining = value >>> 0;
  while (remaining > 0x7f) {
    bytes.push((remaining & 0x7f) | 0x80);
    remaining >>>= 7;
  }
  bytes.push(remaining);
  return new Uint8Array(bytes);
}

function concatBytes(arrays: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = arrays.reduce((length, array) => length + array.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const array of arrays) {
    output.set(array, offset);
    offset += array.length;
  }
  return output;
}

function encodeField(fieldNum: number, payload: Uint8Array): Uint8Array<ArrayBuffer> {
  return concatBytes([encodeVarint((fieldNum << 3) | 2), encodeVarint(payload.length), payload]);
}

function encodeString(fieldNum: number, value: string): Uint8Array {
  return encodeField(fieldNum, TEXT_ENC.encode(value));
}

function encodeMessage(fieldNum: number, value: Uint8Array): Uint8Array<ArrayBuffer> {
  return encodeField(fieldNum, value);
}

function encodeVarintField(fieldNum: number, value: number): Uint8Array {
  return concatBytes([encodeVarint(fieldNum << 3), encodeVarint(value)]);
}

function encodeDoubleField(fieldNum: number, value: number): Uint8Array {
  const payload = new Uint8Array(8);
  new DataView(payload.buffer).setFloat64(0, value, true);
  return concatBytes([encodeVarint((fieldNum << 3) | 1), payload]);
}

function encodeConnectFrame(flag: number, payload: Uint8Array): Uint8Array<ArrayBuffer> {
  const frame = new Uint8Array(5 + payload.length);
  frame[0] = flag;
  new DataView(frame.buffer).setUint32(1, payload.length, false);
  frame.set(payload, 5);
  return frame;
}

// ─── Request construction ───────────────────────────────────────────────────

function normalizeDevinSessionToken(token: string | undefined): string {
  if (!token) return "";
  return token.startsWith(DEVIN_SESSION_TOKEN_PREFIX)
    ? token
    : `${DEVIN_SESSION_TOKEN_PREFIX}${token}`;
}

function resolveBaseUrl(credentials: ExecuteInput["credentials"]): string {
  const configuredBaseUrl = credentials.providerSpecificData?.baseUrl;
  return (
    typeof configuredBaseUrl === "string" && configuredBaseUrl.trim()
      ? configuredBaseUrl
      : DEVIN_API_URL
  ).replace(/\/+$/, "");
}

function buildMetadata(apiKey: string, userJwt?: string): Uint8Array {
  const parts = [
    encodeString(1, "windsurf"),
    encodeString(2, DEVIN_EXTENSION_VERSION),
    encodeString(3, apiKey),
    encodeString(4, "en"),
    encodeString(7, DEVIN_IDE_VERSION),
    encodeString(12, "windsurf"),
  ];
  if (userJwt) parts.push(encodeString(21, userJwt));
  return concatBytes(parts);
}

function buildGetUserJwtRequest(apiKey: string): Uint8Array<ArrayBuffer> {
  return encodeMessage(1, buildMetadata(apiKey));
}

/** Auth probe endpoint used by the dashboard connection test (see buildWindsurfProbeBody). */
export const WINDSURF_PROBE_URL = `${DEVIN_API_URL}${AUTH_PATH}`;

/**
 * Connection-test probe body for the dashboard: Devin authenticates inside the request
 * PAYLOAD (the key is a protobuf field, not an Authorization header), so the test
 * harness cannot use a static body. Exposed as a single entry point rather than the
 * individual protobuf helpers to keep the wire encoding owned by this module.
 *
 * A valid key returns 200; a revoked or malformed one returns 401 `invalid api key`
 * — a real auth signal that token-expiry checks alone cannot produce.
 */
export function buildWindsurfProbeBody(apiKey: string): Uint8Array<ArrayBuffer> {
  return buildGetUserJwtRequest(normalizeDevinSessionToken(apiKey));
}

function contentAndImages(content: unknown): { text: string; images: ImageData[] } {
  if (typeof content === "string") return { text: content, images: [] };
  if (!Array.isArray(content)) return { text: "", images: [] };

  let text = "";
  const images: ImageData[] = [];
  for (const part of content) {
    if (!part || typeof part !== "object") continue;
    const record = part as Record<string, unknown>;
    if (record.type === "text") {
      text += typeof record.text === "string" ? record.text : "";
      continue;
    }
    if (record.type !== "image_url") continue;
    const imageUrl = record.image_url;
    const url =
      typeof imageUrl === "string"
        ? imageUrl
        : imageUrl &&
            typeof imageUrl === "object" &&
            typeof (imageUrl as Record<string, unknown>).url === "string"
          ? ((imageUrl as Record<string, unknown>).url as string)
          : "";
    const dataUrl = /^data:([^;,]+)?;base64,([\s\S]*)$/i.exec(url);
    if (dataUrl)
      images.push({ mimeType: dataUrl[1] || "application/octet-stream", base64Data: dataUrl[2] });
  }
  return { text, images };
}

function buildImageData(image: ImageData): Uint8Array {
  return concatBytes([encodeString(1, image.base64Data), encodeString(2, image.mimeType)]);
}

function buildChatToolCall(id: string, name: string, argumentsJson: string): Uint8Array {
  const parts: Uint8Array[] = [];
  if (id) parts.push(encodeString(1, id));
  if (name) parts.push(encodeString(2, name));
  if (argumentsJson) parts.push(encodeString(3, argumentsJson));
  return concatBytes(parts);
}

function buildChatMessagePrompt(
  messageId: string,
  source: number,
  prompt: string,
  options: {
    toolCalls?: Array<{ id: string; name: string; argumentsJson: string }>;
    toolCallId?: string;
    images?: ImageData[];
  } = {}
): Uint8Array {
  const parts: Uint8Array[] = [encodeString(1, messageId), encodeVarintField(2, source)];
  if (prompt) parts.push(encodeString(3, prompt));
  for (const toolCall of options.toolCalls ?? []) {
    parts.push(
      encodeMessage(6, buildChatToolCall(toolCall.id, toolCall.name, toolCall.argumentsJson))
    );
  }
  if (options.toolCallId) parts.push(encodeString(7, options.toolCallId));
  for (const image of options.images ?? []) parts.push(encodeMessage(10, buildImageData(image)));
  return concatBytes(parts);
}

function buildChatMessagePrompts(
  messages: OpenAIMessage[],
  cascadeId: string
): { systemPrompt: string; prompts: Uint8Array[] } {
  const systemPrompts: string[] = [];
  const prompts: Uint8Array[] = [];

  for (const [index, message] of messages.entries()) {
    const role = message.role || "user";
    const { text, images } = contentAndImages(message.content);
    if (role === "system" || role === "developer") {
      if (text) systemPrompts.push(text);
      continue;
    }
    const messageId = `${cascadeId}-${index}`;
    if (role === "assistant") {
      const toolCalls = Array.isArray(message.tool_calls)
        ? message.tool_calls.flatMap((toolCall) => {
            if (!toolCall || typeof toolCall !== "object") return [];
            const record = toolCall as Record<string, unknown>;
            const fn = record.function;
            if (!fn || typeof fn !== "object") return [];
            const functionRecord = fn as Record<string, unknown>;
            return [
              {
                id: typeof record.id === "string" ? record.id : "",
                name: typeof functionRecord.name === "string" ? functionRecord.name : "",
                argumentsJson:
                  typeof functionRecord.arguments === "string" ? functionRecord.arguments : "",
              },
            ];
          })
        : [];
      prompts.push(buildChatMessagePrompt(messageId, 2, text, { toolCalls }));
      continue;
    }
    if (role === "tool") {
      prompts.push(
        buildChatMessagePrompt(messageId, 4, text, { toolCallId: message.tool_call_id, images })
      );
      continue;
    }
    prompts.push(buildChatMessagePrompt(messageId, 1, text, { images }));
  }

  return { systemPrompt: systemPrompts.join("\n\n"), prompts };
}

function buildChatToolDefinitions(tools: unknown): Uint8Array[] {
  if (!Array.isArray(tools)) return [];
  return tools.map((tool) => {
    const fn = (tool as OpenAITool | null)?.function;
    if (!fn || typeof fn.name !== "string" || !fn.name.trim()) {
      throw new InvalidRequestError("Each tool must include a non-empty function.name");
    }
    const parts = [
      encodeString(1, fn.name),
      ...(typeof fn.description === "string" && fn.description
        ? [encodeString(2, fn.description)]
        : []),
      encodeString(3, JSON.stringify(fn.parameters ?? {})),
    ];
    return concatBytes(parts);
  });
}

function modelContextLength(model: string): number {
  return (
    windsurfProvider.models.find((candidate) => candidate.id === model)?.contextLength ?? 64000
  );
}

function finiteNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function buildCompletionConfiguration(body: Record<string, unknown>, model: string): Uint8Array {
  const maxTokens = Math.min(finiteNumber(body.max_tokens, 64000), modelContextLength(model));
  const temperature = finiteNumber(body.temperature, 0.4);
  const topP = finiteNumber(body.top_p, 1);
  const stops = [
    ...DEVIN_DEFAULT_STOP_PATTERNS,
    ...(Array.isArray(body.stop)
      ? body.stop.filter((stop): stop is string => typeof stop === "string")
      : []),
  ];
  const parts: Uint8Array[] = [
    encodeVarintField(1, 1),
    encodeVarintField(2, maxTokens),
    encodeVarintField(3, 200),
  ];
  if (temperature !== 0) {
    parts.push(encodeDoubleField(5, temperature), encodeDoubleField(6, temperature));
  }
  parts.push(encodeVarintField(7, 50));
  if (topP !== 0) parts.push(encodeDoubleField(8, topP));
  for (const stop of stops) parts.push(encodeString(9, stop));
  parts.push(encodeDoubleField(11, 1));
  return concatBytes(parts);
}

function buildGetChatMessageRequest(
  apiKey: string,
  userJwt: string,
  model: string,
  contextModel: string,
  body: Record<string, unknown>,
  tools: Uint8Array[]
): Uint8Array {
  const cascadeId = randomUUID();
  const messages = Array.isArray(body.messages) ? (body.messages as OpenAIMessage[]) : [];
  const { systemPrompt, prompts } = buildChatMessagePrompts(messages, cascadeId);
  // Cascade rejects a tool-bearing request whose `prompt` is empty with
  // `invalid_argument` (verified live 2026-07-25), so a client that sends tools
  // without any system/developer message gets this minimal stand-in.
  const effectivePrompt = systemPrompt || (tools.length > 0 ? DEVIN_DEFAULT_TOOL_PROMPT : "");
  const parts: Uint8Array[] = [
    encodeMessage(1, buildMetadata(apiKey, userJwt)),
    ...(effectivePrompt ? [encodeString(2, effectivePrompt)] : []),
    encodeVarintField(7, 5),
    encodeMessage(8, buildCompletionConfiguration(body, contextModel)),
    encodeVarintField(11, 1),
    encodeMessage(12, encodeString(1, "auto")),
    encodeMessage(13, encodeVarintField(1, 1)),
    encodeString(16, cascadeId),
    encodeVarintField(20, 1),
    encodeString(21, model),
    encodeString(22, randomUUID()),
  ];
  for (const prompt of prompts) parts.push(encodeMessage(3, prompt));
  for (const tool of tools) parts.push(encodeMessage(10, tool));
  return concatBytes(parts);
}

// ─── Protobuf decoding ───────────────────────────────────────────────────────

function readVarint(bytes: Uint8Array, offset: number): [number, number] {
  let value = 0;
  let shift = 0;
  while (offset < bytes.length && shift < 35) {
    const next = bytes[offset++];
    value |= (next & 0x7f) << shift;
    if ((next & 0x80) === 0) return [value >>> 0, offset];
    shift += 7;
  }
  throw new Error("Invalid protobuf varint");
}

function decodeFields(bytes: Uint8Array): Map<number, ProtoField[]> {
  const fields = new Map<number, ProtoField[]>();
  let offset = 0;
  while (offset < bytes.length) {
    const [tag, tagEnd] = readVarint(bytes, offset);
    offset = tagEnd;
    const fieldNum = tag >>> 3;
    const wireType = tag & 0x07;
    let value: number | Uint8Array;
    if (wireType === 0) {
      [value, offset] = readVarint(bytes, offset);
    } else if (wireType === 1) {
      if (offset + 8 > bytes.length) throw new Error("Truncated fixed64 protobuf field");
      value = bytes.slice(offset, offset + 8);
      offset += 8;
    } else if (wireType === 2) {
      const [length, lengthEnd] = readVarint(bytes, offset);
      offset = lengthEnd;
      if (offset + length > bytes.length)
        throw new Error("Truncated length-delimited protobuf field");
      value = bytes.slice(offset, offset + length);
      offset += length;
    } else if (wireType === 5) {
      if (offset + 4 > bytes.length) throw new Error("Truncated fixed32 protobuf field");
      value = bytes.slice(offset, offset + 4);
      offset += 4;
    } else {
      throw new Error(`Unsupported protobuf wire type ${wireType}`);
    }
    const values = fields.get(fieldNum) ?? [];
    values.push({ wireType, value });
    fields.set(fieldNum, values);
  }
  return fields;
}

function stringField(fields: Map<number, ProtoField[]>, fieldNum: number, index = 0): string {
  const value = fields.get(fieldNum)?.[index]?.value;
  return value instanceof Uint8Array ? TEXT_DEC.decode(value) : "";
}

function varintField(fields: Map<number, ProtoField[]>, fieldNum: number, index = 0): number {
  const value = fields.get(fieldNum)?.[index]?.value;
  return typeof value === "number" ? value : 0;
}

function messageFields(
  fields: Map<number, ProtoField[]>,
  fieldNum: number
): Map<number, ProtoField[]>[] {
  return (fields.get(fieldNum) ?? [])
    .filter(
      (field): field is { wireType: number; value: Uint8Array } => field.value instanceof Uint8Array
    )
    .map((field) => decodeFields(field.value));
}

function decodeAuthResponse(payload: Uint8Array): { userJwt: string; customApiServerUrl: string } {
  try {
    const fields = decodeFields(payload);
    return { userJwt: stringField(fields, 1), customApiServerUrl: stringField(fields, 2) };
  } catch {
    const fields = decodeFields(gunzipSync(payload));
    return { userJwt: stringField(fields, 1), customApiServerUrl: stringField(fields, 2) };
  }
}

function decodeChatResponse(payload: Uint8Array): DecodedChatResponse {
  const fields = decodeFields(payload);
  const usageFields = messageFields(fields, 7)[0];
  return {
    messageId: stringField(fields, 1),
    deltaText: stringField(fields, 3),
    stopReason: varintField(fields, 5),
    deltaToolCalls: messageFields(fields, 6).map((toolCall) => ({
      id: stringField(toolCall, 1),
      name: stringField(toolCall, 2),
      argumentsJson: stringField(toolCall, 3),
    })),
    ...(usageFields
      ? {
          usage: {
            inputTokens: varintField(usageFields, 2),
            outputTokens: varintField(usageFields, 3),
            cacheReadTokens: varintField(usageFields, 5),
            cacheWriteTokens: varintField(usageFields, 4),
          },
        }
      : {}),
  };
}

function readConnectTrailerError(text: string): string | null {
  if (!text) return null;
  try {
    const parsed: unknown = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || !("error" in parsed)) return null;
    const error = parsed.error;
    if (!error || typeof error !== "object") return null;
    const code = "code" in error && typeof error.code === "string" ? error.code : "";
    const message = "message" in error && typeof error.message === "string" ? error.message : "";
    return code || message ? `Devin stream error${code ? ` ${code}` : ""}: ${message}` : null;
  } catch {
    return null;
  }
}

async function fetchDevinAuthMetadata(
  apiKey: string,
  baseUrl: string,
  signal?: AbortSignal | null
): Promise<{ userJwt: string; baseUrl?: string }> {
  const response = await fetch(`${baseUrl}${AUTH_PATH}`, {
    method: "POST",
    headers: {
      "content-type": "application/proto",
      "connect-protocol-version": "1",
      accept: "*/*",
    },
    body: buildGetUserJwtRequest(apiKey),
    signal: signal ?? undefined,
  });
  const payload = new Uint8Array(await response.arrayBuffer());
  if (!response.ok) {
    throw new Error(
      `Devin auth error ${response.status} ${response.statusText}: ${TEXT_DEC.decode(payload)}`
    );
  }
  const decoded = decodeAuthResponse(payload);
  if (!decoded.userJwt) throw new Error("Devin auth error: GetUserJwt returned an empty user JWT");
  const customBaseUrl = decoded.customApiServerUrl.trim().replace(/\/+$/, "");
  return { userJwt: decoded.userJwt, ...(customBaseUrl ? { baseUrl: customBaseUrl } : {}) };
}

function errorSseResponse(message: string): Response {
  const body = `data: ${JSON.stringify({ error: { message, type: "windsurf_error" } })}\n\ndata: [DONE]\n\n`;
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}

// ─── Windsurf executor ───────────────────────────────────────────────────────

export class WindsurfExecutor extends BaseExecutor {
  constructor() {
    super("windsurf", PROVIDERS["windsurf"] || { id: "windsurf", baseUrl: DEVIN_API_URL });
  }

  buildUrl(): string {
    return `${DEVIN_API_URL}${CHAT_PATH}`;
  }

  buildHeaders(): Record<string, string> {
    return {
      "content-type": "application/connect+proto",
      "connect-protocol-version": "1",
      "connect-content-encoding": "gzip",
      "accept-encoding": "identity",
      "connect-accept-encoding": "gzip",
      "user-agent": "connect-go/1.18.1 (go1.26.3)",
    };
  }

  transformRequest(): unknown {
    return null;
  }

  async execute({
    model,
    body,
    stream,
    credentials,
    signal,
    log,
    upstreamExtraHeaders,
  }: ExecuteInput): Promise<ExecutorExecuteResult> {
    const requestBody = (body ?? {}) as Record<string, unknown>;
    let requestPayload: Uint8Array | null = null;
    let url = `${resolveBaseUrl(credentials)}${CHAT_PATH}`;
    const headers = this.buildHeaders();

    try {
      const tools = buildChatToolDefinitions(requestBody.tools);
      const apiKey = normalizeDevinSessionToken(credentials.apiKey || credentials.accessToken);
      if (!apiKey) throw new Error("Devin auth error: missing Windsurf session token");
      const resolvedModel = resolveWsModelId(model);
      const baseUrl = resolveBaseUrl(credentials);
      const auth = await fetchDevinAuthMetadata(apiKey, baseUrl, signal);
      url = `${auth.baseUrl ?? baseUrl}${CHAT_PATH}`;
      requestPayload = buildGetChatMessageRequest(
        apiKey,
        auth.userJwt,
        resolvedModel,
        model,
        requestBody,
        tools
      );
      const framedPayload = encodeConnectFrame(0x01, gzipSync(requestPayload));
      mergeUpstreamExtraHeaders(headers, upstreamExtraHeaders);

      log?.info?.("WS", `Devin Connect → ${resolvedModel}`);
      const upstream = await fetch(url, {
        method: "POST",
        headers,
        body: framedPayload,
        signal: signal ?? undefined,
      });
      if (!upstream.ok) {
        const text = await upstream.text();
        throw new Error(`Devin API error ${upstream.status} ${upstream.statusText}: ${text}`);
      }
      if (!upstream.body) throw new Error("Devin API error: response body is empty");

      return {
        response: this.transformToSSE(upstream, model, stream),
        url,
        headers,
        transformedBody: requestPayload,
      };
    } catch (error) {
      if (error instanceof InvalidRequestError) {
        return {
          response: new Response(
            JSON.stringify({ error: { message: error.message, type: "invalid_request_error" } }),
            { status: 400, headers: { "Content-Type": "application/json" } }
          ),
          url,
          headers,
          transformedBody: requestPayload,
        };
      }
      return {
        response: errorSseResponse(error instanceof Error ? error.message : String(error)),
        url,
        headers,
        transformedBody: requestPayload,
      };
    }
  }

  private transformToSSE(upstream: Response, model: string, _stream: boolean): Response {
    const responseId = `chatcmpl-ws-${Date.now()}`;
    const created = Math.floor(Date.now() / 1000);

    const sseStream = new ReadableStream<Uint8Array>({
      async start(controller) {
        const emit = (value: unknown) =>
          controller.enqueue(TEXT_ENC.encode(`data: ${JSON.stringify(value)}\n\n`));
        let roleEmitted = false;
        let stopReason = 0;
        let usage: DecodedChatResponse["usage"];
        const toolIndexes = new Map<string, number>();
        const toolArguments = new Map<string, string>();
        // Tracks the most recently seen tool-call id so continuation frames,
        // which omit the id, attach their argument fragments to the right call.
        let activeToolCallId: string | undefined;
        // Tool-call ids whose `name` has already been forwarded to the client.
        const emittedToolNames = new Set<string>();

        const emitRole = () => {
          if (roleEmitted) return;
          emit({
            id: responseId,
            object: "chat.completion.chunk",
            created,
            model,
            choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }],
          });
          roleEmitted = true;
        };

        const emitToolChunk = (toolCall: Record<string, unknown>) => {
          emitRole();
          emit({
            id: responseId,
            object: "chat.completion.chunk",
            created,
            model,
            choices: [{ index: 0, delta: { tool_calls: [toolCall] }, finish_reason: null }],
          });
        };

        try {
          const reader = upstream.body!.getReader();
          let pending: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
          try {
            for (;;) {
              const { done, value } = await reader.read();
              if (value?.length) pending = pending.length ? concatBytes([pending, value]) : value;
              let offset = 0;
              while (pending.length - offset >= 5) {
                const frameView = new DataView(pending.buffer, pending.byteOffset + offset, 5);
                const flag = pending[offset];
                const length = frameView.getUint32(1, false);
                if (length > MAX_CONNECT_FRAME_PAYLOAD) {
                  throw new Error(
                    `Devin Connect frame length ${length} exceeds ${MAX_CONNECT_FRAME_PAYLOAD}-byte cap`
                  );
                }
                if (pending.length - offset < 5 + length) break;
                const payload = pending.slice(offset + 5, offset + 5 + length);
                offset += 5 + length;
                const raw = flag & 0x01 ? gunzipSync(payload) : payload;
                if (flag & 0x02) {
                  const trailerError = readConnectTrailerError(TEXT_DEC.decode(raw).trim());
                  if (trailerError) throw new Error(trailerError);
                  continue;
                }

                const decoded = decodeChatResponse(raw);
                if (decoded.deltaText) {
                  emitRole();
                  emit({
                    id: responseId,
                    object: "chat.completion.chunk",
                    created,
                    model,
                    choices: [
                      { index: 0, delta: { content: decoded.deltaText }, finish_reason: null },
                    ],
                  });
                }
                for (const toolCall of decoded.deltaToolCalls) {
                  // Devin sends the id only on the opening frame; subsequent
                  // argument fragments arrive with an empty id and belong to the
                  // most recent call. Dropping them loses all arguments.
                  const toolCallId = toolCall.id || activeToolCallId;
                  if (!toolCallId) continue;
                  activeToolCallId = toolCallId;
                  let index = toolIndexes.get(toolCallId);
                  if (index === undefined) {
                    index = toolIndexes.size;
                    toolIndexes.set(toolCallId, index);
                    toolArguments.set(toolCallId, "");
                    if (toolCall.name) emittedToolNames.add(toolCallId);
                    emitToolChunk({
                      index,
                      id: toolCallId,
                      type: "function",
                      function: { name: toolCall.name, arguments: "" },
                    });
                  } else if (toolCall.name && !emittedToolNames.has(toolCallId)) {
                    // A later frame may carry the name when the opening frame
                    // omitted it; forward it so the client sees the real name.
                    emittedToolNames.add(toolCallId);
                    emitToolChunk({ index, function: { name: toolCall.name, arguments: "" } });
                  }
                  if (!toolCall.argumentsJson) continue;
                  const previous = toolArguments.get(toolCallId) ?? "";
                  const accumulated = toolCall.argumentsJson.startsWith(previous)
                    ? toolCall.argumentsJson
                    : previous + toolCall.argumentsJson;
                  const delta = accumulated.slice(previous.length);
                  toolArguments.set(toolCallId, accumulated);
                  if (delta) emitToolChunk({ index, function: { arguments: delta } });
                }
                if (decoded.stopReason) stopReason = decoded.stopReason;
                if (decoded.usage) usage = decoded.usage;
              }
              if (offset) pending = pending.slice(offset);
              if (done) break;
            }
          } finally {
            reader.releaseLock();
          }
          if (pending.length) throw new Error("Truncated Devin Connect frame");

          const finishPayload: Record<string, unknown> = {
            id: responseId,
            object: "chat.completion.chunk",
            created,
            model,
            choices: [
              {
                index: 0,
                delta: {},
                finish_reason: toolIndexes.size
                  ? "tool_calls"
                  : stopReason === 3
                    ? "length"
                    : "stop",
              },
            ],
          };
          if (usage) {
            finishPayload.usage = {
              prompt_tokens: usage.inputTokens,
              completion_tokens: usage.outputTokens,
              total_tokens: usage.inputTokens + usage.outputTokens,
            };
          }
          emit(finishPayload);
          controller.enqueue(TEXT_ENC.encode("data: [DONE]\n\n"));
        } catch (error) {
          emit({
            error: {
              message: error instanceof Error ? error.message : String(error),
              type: "windsurf_error",
            },
          });
          controller.enqueue(TEXT_ENC.encode("data: [DONE]\n\n"));
        } finally {
          controller.close();
        }
      },
    });

    return new Response(sseStream, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      },
    });
  }
}
