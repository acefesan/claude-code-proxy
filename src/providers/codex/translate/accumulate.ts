import { mapUsageToAnthropic, reduceUpstream } from "./reducer.ts";
import type { CodexUsage, ReducerEvent } from "./reducer.ts";
import type { Logger } from "../../../log.ts";
import type { TrafficCapture } from "../../types.ts";
import { attachTrafficCapture, createUpstreamStreamDiagnostics } from "./reducer.ts";
import { createBlockAccumulator, parseToolInputJsonOrRaw } from "../../translate/accumulate.ts";

export { UpstreamStreamError } from "./reducer.ts";

export interface AnthropicNonStreamResponse {
  id: string;
  type: "message";
  role: "assistant";
  model: string;
  content: Array<
    { type: "text"; text: string } | { type: "tool_use"; id: string; name: string; input: unknown }
  >;
  stop_reason: "end_turn" | "tool_use" | "max_tokens" | null;
  stop_sequence: null;
  usage: {
    input_tokens: number;
    output_tokens: number;
    cache_creation_input_tokens: number;
    cache_read_input_tokens: number;
  };
}

type FinishEvent = Extract<ReducerEvent, { kind: "finish" }>;

export interface AccumulatedResponse {
  response: AnthropicNonStreamResponse;
  rawUsage?: CodexUsage;
  terminalType?: FinishEvent["terminalType"];
  continuationEligible: boolean;
  responseId?: string;
  outputItems: FinishEvent["outputItems"];
}

/**
 * Drive the Codex SSE stream to completion through the shared reducer
 * and fold the ReducerEvents into a single Anthropic non-streaming
 * response object. Throws UpstreamStreamError on rate_limit or failed
 * upstream; server translates to a proper HTTP status.
 */
export async function accumulateResponse(
  upstream: ReadableStream<Uint8Array>,
  opts: { messageId: string; model: string; log: Logger; traffic?: TrafficCapture },
): Promise<AccumulatedResponse> {
  const blockAccumulator = createBlockAccumulator();
  let stopReason: AnthropicNonStreamResponse["stop_reason"] = null;
  let usage: ReturnType<typeof mapUsageToAnthropic> | undefined;
  let rawUsage: CodexUsage | undefined;
  let terminalType: FinishEvent["terminalType"] | undefined;
  let continuationEligible = false;
  let responseId: string | undefined;
  let outputItems: FinishEvent["outputItems"] = [];

  const diagnostics = attachTrafficCapture(createUpstreamStreamDiagnostics(), opts.traffic);

  for await (const e of reduceUpstream(upstream, opts.log, diagnostics)) {
    switch (e.kind) {
      case "text-start":
        blockAccumulator.onTextStart(e.index);
        break;
      case "text-delta": {
        blockAccumulator.onTextDelta(e.index, e.text);
        break;
      }
      case "tool-start":
        blockAccumulator.onToolStart(e.index, e.id, e.name);
        break;
      case "tool-delta": {
        blockAccumulator.onToolDelta(e.index, e.partialJson);
        break;
      }
      case "text-stop":
      case "tool-stop":
        break;
      case "finish":
        stopReason = e.stopReason;
        rawUsage = e.usage;
        usage = mapUsageToAnthropic(e.usage);
        terminalType = e.terminalType;
        continuationEligible = e.continuationEligible;
        responseId = e.responseId;
        outputItems = e.outputItems;
        break;
    }
  }

  const content: AnthropicNonStreamResponse["content"] = [];
  for (const b of blockAccumulator.orderedBlocks()) {
    if (b.kind === "text") {
      if (b.text) content.push({ type: "text", text: b.text });
    } else if (b.kind === "tool") {
      content.push({
        type: "tool_use",
        id: b.id,
        name: b.name,
        input: parseToolInputJsonOrRaw(b.args),
      });
    }
  }

  return {
    rawUsage,
    terminalType,
    continuationEligible,
    responseId,
    outputItems,
    response: {
      id: opts.messageId,
      type: "message",
      role: "assistant",
      model: opts.model,
      content,
      stop_reason: stopReason,
      stop_sequence: null,
      usage: usage ?? {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
      },
    },
  };
}
