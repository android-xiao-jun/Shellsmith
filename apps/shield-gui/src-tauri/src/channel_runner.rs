//! 渠道包任务：读取渠道号、导入渠道列表、批量写入渠道包。
//! 业务逻辑集中在 shield-core::channel，本模块只负责 Tauri 状态、进度与取消适配。

use crate::app_config::AppConfigState;
use crate::failure_diagnostic::ExecutionFailure;
use crate::task_completion;
use crate::task_manager::{TaskKind, TaskManager};
use shield_core::diagnostic::{Diagnostic, FailureCode};
use shield_core::{ChannelError, ChannelStage, ShieldError};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Default)]
pub(crate) struct ChannelCancelHandle(pub(crate) Arc<AtomicBool>);

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChannelBatchRequest {
    pub task_id: String,
    pub input: String,
    pub channels: Vec<String>,
    pub output_dir: String,
    #[serde(default)]
    pub force: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChannelArtifact {
    channel: String,
    path: String,
    bytes: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChannelBatchResult {
    outputs: Vec<ChannelArtifact>,
}

#[tauri::command]
pub(crate) async fn channel_get(apk_path: String) -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(move || shield_core::read_channel(Path::new(&apk_path)))
        .await
        .map_err(|err| format!("后台任务执行失败: {err}"))?
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub(crate) async fn channel_read_file(path: String) -> Result<Vec<String>, String> {
    let path = PathBuf::from(path);
    if !path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("txt"))
    {
        return Err("渠道列表必须是 .txt 文件".to_string());
    }
    tokio::task::spawn_blocking(move || {
        let metadata = std::fs::metadata(&path)
            .map_err(|err| format!("读取渠道列表失败: {err}"))?;
        if metadata.len() > 4 * 1024 * 1024 {
            return Err("渠道列表过大，请控制在 4 MB 以内".to_string());
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|err| format!("读取渠道列表失败: {err}"))?;
        shield_core::parse_channel_list(&text).map_err(|err| err.to_string())
    })
    .await
    .map_err(|err| format!("后台任务执行失败: {err}"))?
}

#[tauri::command]
pub(crate) async fn channel_batch(
    window: tauri::Window,
    telemetry_state: tauri::State<'_, AppConfigState>,
    task_manager: tauri::State<'_, TaskManager>,
    cancel_handle: tauri::State<'_, ChannelCancelHandle>,
    request: ChannelBatchRequest,
) -> Result<ChannelBatchResult, String> {
    let output_dir = PathBuf::from(&request.output_dir);
    if output_dir.exists() && !output_dir.is_dir() {
        return Err(format!("输出路径不是目录：{}", output_dir.display()));
    }
    task_manager.begin(
        &window,
        request.task_id.clone(),
        TaskKind::ChannelPack,
        request.input.clone(),
        request.output_dir.clone(),
        "CheckApk",
    )?;
    cancel_handle.0.store(false, Ordering::SeqCst);

    let progress_manager = task_manager.inner().clone();
    let progress_window = window.clone();
    let progress_task_id = request.task_id.clone();
    let cancel = Arc::clone(&cancel_handle.0);
    let result = tokio::task::spawn_blocking(move || {
        let outputs = shield_core::write_channels(
            Path::new(&request.input),
            &output_dir,
            &request.channels,
            request.force,
            |event| {
                let (step, message) = match event.stage {
                    ChannelStage::Check => ("CheckApk", "检查 APK 与渠道列表".to_string()),
                    ChannelStage::Write => (
                        "WriteChannel",
                        format!(
                            "正在写入渠道 {}/{}：{}",
                            event.index, event.total, event.channel
                        ),
                    ),
                    ChannelStage::Commit => (
                        "CommitChannel",
                        format!("已生成 {}", event.output.display()),
                    ),
                };
                let _ = progress_manager.progress(
                    &progress_window,
                    &progress_task_id,
                    step,
                    message,
                );
            },
            Some(cancel.as_ref()),
        )
        .map_err(map_channel_failure)?;
        Ok(ChannelBatchResult {
            outputs: outputs
                .into_iter()
                .map(|output| ChannelArtifact {
                    channel: output.channel,
                    path: output.path.display().to_string(),
                    bytes: output.bytes,
                })
                .collect(),
        })
    })
    .await
    .map_err(|err| ExecutionFailure::from(format!("后台任务执行失败: {err}")))?;

    let finish_result = match &result {
        Ok(_) => Ok(()),
        Err(error) => Err(error.clone()),
    };
    task_completion::finish_task(
        &window,
        &task_manager,
        &telemetry_state,
        &request.task_id,
        false,
        finish_result,
    )?;
    result.map_err(|error| error.message)
}

#[tauri::command]
pub(crate) fn cancel_channel_pack(cancel: tauri::State<'_, ChannelCancelHandle>) {
    cancel.0.store(true, Ordering::SeqCst);
}

fn map_channel_failure(error: ChannelError) -> ExecutionFailure {
    match error {
        ChannelError::Cancelled => ExecutionFailure::from_shield(ShieldError::Cancelled),
        other => ExecutionFailure::diagnosed(
            other.to_string(),
            Diagnostic::new(FailureCode::Unknown),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::map_channel_failure;
    use shield_core::ChannelError;

    #[test]
    fn 渠道取消映射为可取消任务() {
        let failure = map_channel_failure(ChannelError::Cancelled);
        assert!(failure.cancelled);
        assert_eq!(failure.message, "已取消");
    }

    #[test]
    fn 渠道结构错误保留原始提示() {
        let failure = map_channel_failure(ChannelError::NoSigningBlock);
        assert!(!failure.cancelled);
        assert!(failure.message.contains("V2/V3"));
    }
}
