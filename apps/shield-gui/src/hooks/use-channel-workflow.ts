import { useCallback, useEffect, useRef, useState } from "react";
import { parseChannelLines, type ChannelParseError } from "@/lib/channel";
import { t, tf, type Locale } from "@/lib/i18n";
import { notifyError, notifySuccess } from "@/lib/notify";
import { dirname, isApk, joinPath } from "@/lib/path";
import {
  api,
  onTauriEvent,
  openDirectoryDialog,
  openFileDialog,
  type ChannelArtifact,
  type DragDropPayload,
  type TaskSnapshot,
} from "@/lib/tauri";

export type ChannelState = "idle" | "packing" | "done" | "failed";

function parseErrorMessage(locale: Locale, error: ChannelParseError): string {
  switch (error.kind) {
    case "empty":
      return t(locale, "channelEmpty");
    case "invalid":
      return tf(locale, "channelInvalidLine", { line: error.line });
    case "duplicate":
      return tf(locale, "channelDuplicateLine", {
        line: error.line,
        channel: error.channel,
      });
  }
}

export function useChannelWorkflow({ active, locale }: { active: boolean; locale: Locale }) {
  const [apkPath, setApkPath] = useState("");
  const [channelsText, setChannelsText] = useState("");
  const [outputDir, setOutputDir] = useState("");
  const [force, setForce] = useState(false);
  const [state, setState] = useState<ChannelState>("idle");
  const [error, setError] = useState("");
  const [dragActive, setDragActive] = useState(false);
  const [currentStep, setCurrentStep] = useState("");
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [finishedAt, setFinishedAt] = useState<number | null>(null);
  const [results, setResults] = useState<ChannelArtifact[]>([]);
  const [currentChannel, setCurrentChannel] = useState<string | null>(null);
  const [channelSigned, setChannelSigned] = useState(false);
  const taskId = useRef<string | null>(null);
  const taskLocked = useRef(false);

  useEffect(() => {
    const unlisten = onTauriEvent<TaskSnapshot>("task-state", (payload) => {
      if (payload.kind !== "channel_pack" || payload.task_id !== taskId.current) return;
      setCurrentStep(payload.current_step);
      setStartedAt(payload.started_at_ms);
      setFinishedAt(payload.finished_at_ms ?? null);
      if (payload.status === "failed" || payload.status === "cancelled") {
        setState("failed");
        if (payload.error) setError(payload.error);
      }
    });
    return () => { void unlisten.then((fn) => fn()); };
  }, []);

  const loadCurrentChannel = useCallback(async (path: string) => {
    setCurrentChannel(null);
    setChannelSigned(false);
    try {
      const channel = await api.channelGet(path);
      setCurrentChannel(channel);
      setChannelSigned(true);
    } catch (err) {
      setChannelSigned(false);
      setError(String(err));
    }
  }, []);

  const selectApk = useCallback((path: string) => {
    setApkPath(path);
    setOutputDir(joinPath(dirname(path), "channels"));
    setState("idle");
    setError("");
    setCurrentStep("");
    setStartedAt(null);
    setFinishedAt(null);
    setResults([]);
    taskId.current = null;
    taskLocked.current = false;
    void loadCurrentChannel(path);
  }, [loadCurrentChannel]);

  useEffect(() => {
    if (!active) { setDragActive(false); return; }
    const unlisten = Promise.all([
      onTauriEvent<DragDropPayload>("tauri://drag-drop", (payload) => {
        const first = payload.paths?.[0];
        setDragActive(false);
        if (taskLocked.current) return;
        if (first && isApk(first)) {
          selectApk(first);
        } else if (first) {
          const message = t(locale, "onlyApk");
          setError(message);
          notifyError(message);
        }
      }),
      onTauriEvent<void>("tauri://drag-enter", () => setDragActive(true)),
      onTauriEvent<void>("tauri://drag-leave", () => setDragActive(false)),
    ]);
    return () => {
      void unlisten.then((items) => items.forEach((fn) => fn()));
    };
  }, [active, locale, selectApk]);

  const browseApk = useCallback(async () => {
    if (taskLocked.current) return;
    const path = await openFileDialog("APK", ["apk"]);
    if (path) selectApk(path);
  }, [selectApk]);

  const importChannels = useCallback(async () => {
    if (taskLocked.current) return;
    const path = await openFileDialog(t(locale, "channelList"), ["txt"]);
    if (!path) return;
    try {
      const channels = await api.channelReadFile(path);
      setChannelsText(channels.join("\n"));
      setError("");
    } catch (err) {
      setError(String(err));
    }
  }, [locale]);

  const chooseOutputDir = useCallback(async () => {
    if (taskLocked.current) return;
    const directory = await openDirectoryDialog(outputDir || undefined);
    if (directory) setOutputDir(directory);
  }, [outputDir]);

  const updateChannelsText = useCallback((value: string) => {
    if (!taskLocked.current) setChannelsText(value);
  }, []);

  const updateOutputDir = useCallback((value: string) => {
    if (!taskLocked.current) setOutputDir(value);
  }, []);

  const updateForce = useCallback((value: boolean) => {
    if (!taskLocked.current) setForce(value);
  }, []);

  const start = useCallback(async () => {
    if (!apkPath || taskLocked.current || !channelSigned) return;
    const parsed = parseChannelLines(channelsText);
    if (parsed.error) {
      const message = parseErrorMessage(locale, parsed.error);
      setError(message);
      notifyError(message);
      return;
    }
    if (!outputDir.trim()) {
      const message = t(locale, "channelOutputDirMissing");
      setError(message);
      notifyError(message);
      return;
    }

    taskLocked.current = true;
    setState("packing");
    setError("");
    setResults([]);
    setCurrentStep("CheckApk");
    setStartedAt(Date.now());
    setFinishedAt(null);
    taskId.current = crypto.randomUUID();

    try {
      const result = await api.channelBatch({
        taskId: taskId.current,
        input: apkPath,
        channels: parsed.channels,
        outputDir: outputDir.trim(),
        force,
      });
      setResults(result.outputs);
      setFinishedAt((previous) => previous ?? Date.now());
      setState("done");
      notifySuccess(t(locale, "channelDone"));
    } catch (err) {
      const message = String(err);
      setFinishedAt((previous) => previous ?? Date.now());
      setError(message);
      notifyError(message);
      setState("failed");
    }
  }, [apkPath, channelSigned, channelsText, force, locale, outputDir]);

  const cancel = useCallback(async () => {
    await api.cancelChannelPack().catch(() => undefined);
  }, []);

  const reset = useCallback(() => {
    setApkPath("");
    setChannelsText("");
    setOutputDir("");
    setForce(false);
    setState("idle");
    setError("");
    setCurrentStep("");
    setStartedAt(null);
    setFinishedAt(null);
    setResults([]);
    setCurrentChannel(null);
    setChannelSigned(false);
    taskId.current = null;
    taskLocked.current = false;
  }, []);

  return {
    apkPath,
    channelsText,
    setChannelsText: updateChannelsText,
    outputDir,
    setOutputDir: updateOutputDir,
    force,
    setForce: updateForce,
    state,
    error,
    dragActive,
    currentStep,
    startedAt,
    finishedAt,
    results,
    currentChannel,
    channelSigned,
    taskLocked: state === "packing",
    hasApk: Boolean(apkPath),
    browseApk,
    importChannels,
    chooseOutputDir,
    start,
    cancel,
    reset,
  };
}
