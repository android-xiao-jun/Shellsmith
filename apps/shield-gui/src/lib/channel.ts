export type ChannelParseError =
  | { kind: "empty" }
  | { kind: "invalid"; line: number }
  | { kind: "duplicate"; line: number; channel: string };

export type ChannelParseResult = {
  channels: string[];
  error: ChannelParseError | null;
};

/** 解析渠道列表文本，规则与 Rust 侧 parse_channel_list 保持一致。 */
export function parseChannelLines(text: string): ChannelParseResult {
  const normalized = text.replace(/^\uFEFF/, "");
  const channels: string[] = [];
  const seen = new Set<string>();

  for (const [index, raw] of normalized.split(/\r?\n/).entries()) {
    const name = raw.trim();
    if (!name) continue;
    if (Array.from(name).length > 256 || /[\u0000-\u001f\u007f"\\]/.test(name)) {
      return { channels: [], error: { kind: "invalid", line: index + 1 } };
    }
    if (seen.has(name)) {
      return { channels: [], error: { kind: "duplicate", line: index + 1, channel: name } };
    }
    seen.add(name);
    channels.push(name);
  }

  if (channels.length === 0) {
    return { channels: [], error: { kind: "empty" } };
  }
  return { channels, error: null };
}
