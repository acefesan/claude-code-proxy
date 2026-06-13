import { mapUsageToAnthropic, reduceUpstream, type KimiUsage } from "./reducer.ts";
import { makeThinkingSignature } from "./signature.ts";
import type { TrafficCapture } from "../../types.ts";
import { createBlockAccumulator, parseToolInputJsonOrRaw } from "../../translate/accumulate.ts";

export { UpstreamStreamError } from "./reducer.ts";

export interface AnthropicNonStreamResponse {
  id: string;
  type: "message";
  role: "assistant";
  model: string;
  content: Array<
    | { type: "text"; text: string }
    | { type: "thinking"; thinking: string; signature: string }
    | { type: "tool_use"; id: string; name: string; input: unknown }
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

export interface AccumulatedResponse {
  response: AnthropicNonStreamResponse;
  rawUsage?: KimiUsage;
}

import type { Logger } from "../../../log.ts";

export async function accumulateResponse(
  upstream: ReadableStream<Uint8Array>,
  opts: { messageId: string; model: string; log: Logger; traffic?: TrafficCapture },
): Promise<AccumulatedResponse> {
  const blockAccumulator = createBlockAccumulator({ includeThinking: true });
  let stopReason: AnthropicNonStreamResponse["stop_reason"] = null;
  let usage: ReturnType<typeof mapUsageToAnthropic> | undefined;
  let rawUsage: KimiUsage | undefined;
  let reasoningChars = 0;
  let contentChars = 0;
  let toolCount = 0;
  const stats = { chunkCount: 0, traffic: opts.traffic };

  for await (const e of reduceUpstream(upstream, stats, opts.log)) {
    switch (e.kind) {
      case "thinking-start":
        blockAccumulator.onThinkingStart(e.index);
        break;
      case "thinking-delta": {
        if (blockAccumulator.onThinkingDelta(e.index, e.text)) {
          reasoningChars += e.text.length;
        }
        break;
      }
      case "text-start":
        blockAccumulator.onTextStart(e.index);
        break;
      case "text-delta": {
        if (blockAccumulator.onTextDelta(e.index, e.text)) {
          contentChars += e.text.length;
        }
        break;
      }
      case "tool-start":
        toolCount++;
        blockAccumulator.onToolStart(e.index, e.id, e.name);
        break;
      case "tool-delta": {
        blockAccumulator.onToolDelta(e.index, e.partialJson);
        break;
      }
      case "thinking-stop":
      case "text-stop":
      case "tool-stop":
        break;
      case "finish":
        stopReason = e.stopReason;
        rawUsage = e.usage;
        usage = mapUsageToAnthropic(e.usage);
        break;
    }
  }

  const content: AnthropicNonStreamResponse["content"] = [];
  for (const b of blockAccumulator.orderedBlocks()) {
    if (b.kind === "thinking") {
      if (b.text)
        content.push({
          type: "thinking",
          thinking: b.text,
          signature: makeThinkingSignature(opts.messageId, b.index),
        });
    } else if (b.kind === "text") {
      if (b.text) content.push({ type: "text", text: b.text });
    } else {
      content.push({
        type: "tool_use",
        id: b.id,
        name: b.name,
        input: parseToolInputJsonOrRaw(b.args),
      });
    }
  }

  opts.log.debug("accumulate summary", {
    chunkCount: stats.chunkCount,
    reasoningChars,
    contentChars,
    toolCount,
    stopReason,
    usage: rawUsage,
  });

  return {
    rawUsage,
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
