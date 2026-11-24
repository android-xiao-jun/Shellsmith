import { Clipboard, FolderOpen, Loader2, Play, RotateCcw, Upload } from "lucide-react";
import {
  AppButton,
  DropZone,
  SelectedApkCard,
  StatusMessage,
  TextArea,
  TextInput,
} from "@/components/app/common";
import { ProtectProgressPanel } from "@/components/app/protect-progress-panel";
import { Switch } from "@/components/ui/switch";
import { useChannelWorkflow } from "@/hooks/use-channel-workflow";
import { useClipboard } from "@/hooks/use-clipboard";
import { basename } from "@/lib/path";
import { t, tf, type Locale } from "@/lib/i18n";
import { api } from "@/lib/tauri";

export function ChannelPage({ active, locale }: { active: boolean; locale: Locale }) {
  const { copiedLabel, copy } = useClipboard(locale);
  const {
    apkPath,
    channelsText,
    setChannelsText,
    outputDir,
    setOutputDir,
    force,
    setForce,
    state,
    error,
    dragActive,
    currentStep,
    startedAt,
    finishedAt,
    results,
    currentChannel,
    channelSigned,
    taskLocked,
    hasApk,
    browseApk,
    importChannels,
    chooseOutputDir,
    start,
    cancel,
    reset,
  } = useChannelWorkflow({ active, locale });

  return (
    <section className="min-h-full px-10 py-9">
      {!hasApk ? (
        <div className="mx-auto w-full max-w-5xl">
          <h1 className="text-[28px] font-semibold tracking-normal">{t(locale, "channelTitle")}</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
            {t(locale, "channelDesc")}
          </p>
          <div className="mt-10">
            <DropZone
              locale={locale}
              active={dragActive}
              title={t(locale, "dropApk")}
              subtitle={t(locale, "onlyApk")}
              onBrowse={browseApk}
            />
          </div>
          {error && (
            <div className="mt-5">
              <StatusMessage kind="error">{error}</StatusMessage>
            </div>
          )}
        </div>
      ) : (
        <div className="mx-auto w-full max-w-6xl">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <h1 className="text-[28px] font-semibold tracking-normal">{t(locale, "channelTitle")}</h1>
              <p className="mt-1 truncate text-sm text-muted-foreground">{basename(apkPath)}</p>
            </div>
            <div className="flex min-w-0 flex-wrap items-center gap-3">
              {state === "packing" && (
                <AppButton variant="secondary" onClick={() => void cancel()}>
                  {t(locale, "channelCancel")}
                </AppButton>
              )}
              {state !== "done" && state !== "failed" && (
                <AppButton
                  className="min-w-[136px]"
                  disabled={taskLocked || !channelSigned || !channelsText.trim() || !outputDir.trim()}
                  onClick={() => void start()}
                >
                  {state === "packing" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                  {state === "packing" ? t(locale, "channelPacking") : t(locale, "startChannel")}
                </AppButton>
              )}
              {(state === "done" || state === "failed") && (
                <AppButton className="min-w-[136px]" variant="secondary" onClick={reset}>
                  <RotateCcw className="h-4 w-4" />
                  {t(locale, "channelAnother")}
                </AppButton>
              )}
            </div>
          </div>

          <div className="mt-8 grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px]">
            <div className="space-y-4">
              <SelectedApkCard locale={locale} path={apkPath} disabled={taskLocked} onChange={browseApk} />

              {channelSigned && (
                <StatusMessage kind="info">
                  {t(locale, "channelCurrent")}：{currentChannel ?? t(locale, "channelNotStamped")}
                </StatusMessage>
              )}

              <div className="rounded-[14px] border bg-card p-4">
                <div className="flex items-center justify-between gap-3">
                  <label className="field-label" htmlFor="channel-list">{t(locale, "channelList")}</label>
                  <AppButton size="sm" variant="secondary" disabled={taskLocked} onClick={() => void importChannels()}>
                    <Upload className="h-4 w-4" />
                    {t(locale, "channelImport")}
                  </AppButton>
                </div>
                <TextArea
                  id="channel-list"
                  className="mt-2"
                  value={channelsText}
                  placeholder={t(locale, "channelListPlaceholder")}
                  disabled={taskLocked}
                  onChange={(event) => setChannelsText(event.target.value)}
                />
                <p className="mt-2 text-xs leading-5 text-muted-foreground">{t(locale, "channelListHint")}</p>
              </div>

              <div className="rounded-[14px] border bg-card p-4">
                <label className="field-label" htmlFor="channel-output">{t(locale, "channelOutputDir")}</label>
                <div className="mt-2 flex min-w-0 gap-2">
                  <TextInput
                    id="channel-output"
                    className="font-mono text-xs"
                    value={outputDir}
                    disabled={taskLocked}
                    onChange={(event) => setOutputDir(event.target.value)}
                  />
                  <AppButton variant="secondary" disabled={taskLocked} onClick={() => void chooseOutputDir()}>
                    <FolderOpen className="h-4 w-4" />
                    {t(locale, "channelChooseDir")}
                  </AppButton>
                </div>
              </div>

              <div className="flex items-start justify-between gap-4 rounded-[14px] border bg-card p-4">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{t(locale, "channelForce")}</p>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">{t(locale, "channelForceHint")}</p>
                </div>
                <Switch checked={force} disabled={taskLocked} onCheckedChange={setForce} />
              </div>

              {results.length > 0 && (
                <div className="rounded-[14px] border bg-card p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <h2 className="text-sm font-semibold">
                      {tf(locale, "channelResultCount", { count: results.length })}
                    </h2>
                    <AppButton
                      size="sm"
                      variant="secondary"
                      onClick={() => void api.showInFolder(results[0].path)}
                    >
                      <FolderOpen className="h-4 w-4" />
                      {t(locale, "channelOpenDir")}
                    </AppButton>
                  </div>
                  <ul className="mt-3 space-y-2">
                    {results.map((output) => (
                      <li
                        key={`${output.channel}-${output.path}`}
                        className="flex flex-wrap items-center justify-between gap-2 rounded-md bg-muted/50 px-3 py-2 text-xs"
                      >
                        <span className="font-medium">{output.channel}</span>
                        <span className="min-w-0 break-all font-mono text-muted-foreground">{output.path}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {state === "done" && results.length > 0 && (
                <StatusMessage
                  kind="success"
                  action={
                    <AppButton size="sm" variant="secondary" onClick={() => void api.showInFolder(results[0].path)}>
                      <FolderOpen className="h-4 w-4" />
                      {t(locale, "showInFolder")}
                    </AppButton>
                  }
                >
                  {tf(locale, "channelResultCount", { count: results.length })}
                </StatusMessage>
              )}

              {error && (
                <StatusMessage
                  kind="error"
                  action={
                    <AppButton size="sm" variant="secondary" onClick={() => void copy(error)}>
                      <Clipboard className="h-4 w-4" />
                      {copiedLabel}
                    </AppButton>
                  }
                >
                  {error}
                </StatusMessage>
              )}
            </div>

            <ProtectProgressPanel
              locale={locale}
              state={state === "packing" ? "running" : state}
              currentStep={currentStep}
              steps={["CheckApk", "WriteChannel", "CommitChannel"]}
              showProgress={state !== "idle" || Boolean(currentStep)}
              startedAt={startedAt}
              finishedAt={finishedAt}
            />
          </div>
        </div>
      )}
    </section>
  );
}
