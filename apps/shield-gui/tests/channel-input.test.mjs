import assert from "node:assert/strict";
import { after, test } from "node:test";
import { createServer } from "vite";

const server = await createServer({ server: { middlewareMode: true }, appType: "custom" });
after(() => server.close());
const { parseChannelLines } = await server.ssrLoadModule("/src/lib/channel.ts");

test("渠道列表解析忽略 BOM 与空行并保留原顺序", () => {
  const result = parseChannelLines("\uFEFFoppo\r\n\r\n  vivo  \nx iaomi\n");
  assert.equal(result.error, null);
  assert.deepEqual(result.channels, ["oppo", "vivo", "x iaomi"]);
});

test("渠道列表解析拒绝空列表与重复渠道", () => {
  assert.deepEqual(parseChannelLines(" \n\t\n").error, { kind: "empty" });
  assert.deepEqual(parseChannelLines("oppo\nvivo\noppo\n").error, {
    kind: "duplicate",
    line: 3,
    channel: "oppo",
  });
});

test("渠道名拒绝控制字符、引号、反斜杠与超长值", () => {
  assert.deepEqual(parseChannelLines('oppo\nbad"name').error, { kind: "invalid", line: 2 });
  assert.deepEqual(parseChannelLines("oppo\nbad\\name").error, { kind: "invalid", line: 2 });
  assert.deepEqual(parseChannelLines("oppo\nbad\u0007name").error, { kind: "invalid", line: 2 });
  assert.deepEqual(parseChannelLines("a".repeat(257)).error, { kind: "invalid", line: 1 });
  assert.equal(parseChannelLines("应用宝").channels[0], "应用宝");
});
