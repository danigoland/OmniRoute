import { gunzipSync } from "node:zlib";

import {
  bodyArrayBuffer,
  CONNECT_COMPRESSED_FLAG,
  CONNECT_END_STREAM_FLAG,
  decodeFields,
  DEVIN_CLI_MODEL_CONFIGS_PATH,
  DEVIN_DESKTOP_BASE_URL,
  devinDesktopServiceBaseUrl,
  encodeDevinDesktopAuthRequest,
  readBoundedResponse,
} from "../executors/devin-desktop.ts";

const MAX_CATALOG_RESPONSE_BYTES = 2 * 1024 * 1024;
const TEXT_DECODER = new TextDecoder();

/** Wire ids Devin ships for internal plumbing rather than user-selectable models. */
const DEVIN_INTERNAL_CATALOG_IDS: Record<string, true> = {
  adaptive: true,
  "memory-migration-default": true,
  "subagent-default": true,
  MODEL_UNSPECIFIED: true,
  MODEL_UNKNOWN: true,
};

export type DevinCliCatalogModel = {
  id: string;
  name: string;
  contextLength?: number;
};

export type DevinCliCatalogResult = {
  source: "api" | "error";
  models: DevinCliCatalogModel[];
  error?: string;
};

function unwrapDevinCatalogPayload(bytes: Uint8Array): Uint8Array {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return gunzipSync(bytes, { maxOutputLength: MAX_CATALOG_RESPONSE_BYTES });
  }
  if (bytes.length >= 5 && bytes[0] <= CONNECT_END_STREAM_FLAG) {
    const length = new DataView(bytes.buffer, bytes.byteOffset + 1, 4).getUint32(0);
    if (length === bytes.length - 5) {
      const payload = bytes.subarray(5);
      return bytes[0] & CONNECT_COMPRESSED_FLAG
        ? gunzipSync(payload, { maxOutputLength: MAX_CATALOG_RESPONSE_BYTES })
        : payload;
    }
  }
  return bytes;
}

/** Parse GetCliModelConfigs: repeated field 1 items, name=1, context=18, wire id=22. */
export function parseDevinCliModelConfigs(bytes: Uint8Array): DevinCliCatalogModel[] {
  const models: DevinCliCatalogModel[] = [];
  for (const field of decodeFields(unwrapDevinCatalogPayload(bytes))) {
    if (field.wireType !== 2 || field.fieldNumber !== 1) continue;
    let id = "";
    let name = "";
    let contextLength: number | undefined;
    for (const item of decodeFields(field.value)) {
      if (item.wireType === 2 && item.fieldNumber === 1) name = TEXT_DECODER.decode(item.value);
      else if (item.wireType === 2 && item.fieldNumber === 22) id = TEXT_DECODER.decode(item.value);
      else if (item.wireType === 0 && item.fieldNumber === 18) contextLength = item.value;
    }
    id = id.trim();
    if (!id || DEVIN_INTERNAL_CATALOG_IDS[id]) continue;
    models.push({
      id,
      name: name.trim() || id,
      ...(contextLength && contextLength > 0 ? { contextLength } : {}),
    });
  }
  return models;
}

export async function fetchDevinCliModelConfigs(options: {
  apiKey: string;
  baseUrl?: string;
  signal?: AbortSignal;
  fetchImpl?: typeof fetch;
}): Promise<DevinCliCatalogResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const url = `${devinDesktopServiceBaseUrl(options.baseUrl || DEVIN_DESKTOP_BASE_URL)}${DEVIN_CLI_MODEL_CONFIGS_PATH}`;
  const body = encodeDevinDesktopAuthRequest({ apiKey: options.apiKey, sessionId: "" });
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/proto",
        Accept: "*/*",
        "Connect-Protocol-Version": "1",
      },
      body: bodyArrayBuffer(body),
      signal: options.signal,
    });
  } catch (error) {
    return {
      source: "error",
      models: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
  if (!response.ok) {
    void response.body?.cancel().catch(() => {});
    return { source: "error", models: [], error: `HTTP ${response.status}` };
  }
  try {
    const raw = await readBoundedResponse(response, MAX_CATALOG_RESPONSE_BYTES);
    const models = parseDevinCliModelConfigs(raw);
    return models.length > 0
      ? { source: "api", models }
      : { source: "error", models: [], error: "empty catalog" };
  } catch (error) {
    return {
      source: "error",
      models: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
