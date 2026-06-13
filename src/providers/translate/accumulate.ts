export type AccumulatedTextBlock = {
  kind: "text";
  index: number;
  text: string;
};

export type AccumulatedThinkingBlock = {
  kind: "thinking";
  index: number;
  text: string;
};

export type AccumulatedToolBlock = {
  kind: "tool";
  index: number;
  id: string;
  name: string;
  args: string;
};

export type AccumulatedBlock =
  | AccumulatedTextBlock
  | AccumulatedThinkingBlock
  | AccumulatedToolBlock;

export interface BlockAccumulator {
  onTextStart(index: number): void;
  onTextDelta(index: number, text: string): boolean;
  onThinkingStart(index: number): void;
  onThinkingDelta(index: number, text: string): boolean;
  onToolStart(index: number, id: string, name: string): void;
  onToolDelta(index: number, partialJson: string): boolean;
  orderedBlocks(): readonly AccumulatedBlock[];
}

export function createBlockAccumulator(options?: { includeThinking?: boolean }): BlockAccumulator {
  const ordered: number[] = [];
  const blocks = new Map<number, AccumulatedBlock>();
  const includeThinking = options?.includeThinking === true;

  return {
    onTextStart(index: number): void {
      blocks.set(index, { kind: "text", index, text: "" });
      ordered.push(index);
    },
    onTextDelta(index: number, text: string): boolean {
      const block = blocks.get(index);
      if (block?.kind === "text") {
        block.text += text;
        return true;
      }
      return false;
    },
    onThinkingStart(index: number): void {
      if (!includeThinking) return;
      blocks.set(index, { kind: "thinking", index, text: "" });
      ordered.push(index);
    },
    onThinkingDelta(index: number, text: string): boolean {
      const block = blocks.get(index);
      if (block?.kind === "thinking") {
        block.text += text;
        return true;
      }
      return false;
    },
    onToolStart(index: number, id: string, name: string): void {
      blocks.set(index, { kind: "tool", index, id, name, args: "" });
      ordered.push(index);
    },
    onToolDelta(index: number, partialJson: string): boolean {
      const block = blocks.get(index);
      if (block?.kind === "tool") {
        block.args += partialJson;
        return true;
      }
      return false;
    },
    orderedBlocks(): readonly AccumulatedBlock[] {
      return ordered.flatMap((index) => {
        const block = blocks.get(index);
        return block ? [block] : [];
      });
    },
  };
}

export function parseToolInputJsonOrRaw(args: string): unknown {
  try {
    return args ? JSON.parse(args) : {};
  } catch {
    return { _raw: args };
  }
}
