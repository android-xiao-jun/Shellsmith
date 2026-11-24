//! Walle 兼容的多渠道写入。
//!
//! 渠道信息存放在 APK Signing Block 的 ID-value 对中（ID `0x71777777`），
//! 与 V2/V3 签名块并列。写入发生在签名之后，只重建签名块并同步 EOCD 的
//! Central Directory 偏移，不修改 APK 内容与压缩方式，因此不会破坏 V2/V3 签名。

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

/// Meituan Walle 使用的渠道 ID。
pub const CHANNEL_BLOCK_ID: u32 = 0x7177_7777;
/// APK 签名块中的 verity padding ID；重建时按需重新生成。
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x4272_6577;

const ZIP_EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_EOCD_MIN_SIZE: usize = 22;
const ZIP_COMMENT_MAX_SIZE: usize = 0xffff;
const APK_SIG_BLOCK_MAGIC_LO: u64 = 0x2067_6953_204b_5041;
const APK_SIG_BLOCK_MAGIC_HI: u64 = 0x3234_206b_636f_6c42;
const APK_SIG_BLOCK_MIN_SIZE: u64 = 32;
const MAX_SIGNING_BLOCK_SIZE: u64 = 64 * 1024 * 1024;
const PAGE_ALIGNMENT: u64 = 4096;
const MAX_CHANNEL_CHARS: usize = 256;
const MAX_FILENAME_CHANNEL_CHARS: usize = 80;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const CANCEL_CHECK_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("输入 APK 没有 APK Signing Block，请先使用 V2/V3 签名后再写入渠道")]
    NoSigningBlock,
    #[error("APK Signing Block 结构无效：{0}")]
    Malformed(&'static str),
    #[error("渠道名无效：{0}")]
    InvalidChannel(String),
    #[error("暂不支持 ZIP64 或超过 4GB 的 APK")]
    Zip64Unsupported,
    #[error("输出文件已存在：{}", .0.display())]
    OutputExists(PathBuf),
    #[error("输入与输出不能是同一个文件")]
    SamePath,
    #[error("操作已取消")]
    Cancelled,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStage {
    Check,
    Write,
    Commit,
}

#[derive(Debug, Clone)]
pub struct ChannelOutput {
    pub channel: String,
    pub path: PathBuf,
    pub bytes: u64,
}

pub struct ChannelProgress<'a> {
    pub stage: ChannelStage,
    pub index: usize,
    pub total: usize,
    pub channel: &'a str,
    pub output: &'a Path,
}

struct EocdInfo {
    /// Central Directory 起始偏移。
    cd_offset: u64,
    /// EOCD 起始偏移。
    eocd_offset: u64,
    /// 从 EOCD 到文件末尾的原始字节（含注释）。
    tail: Vec<u8>,
}

struct SigningBlock {
    offset: u64,
    pairs: Vec<(u32, Vec<u8>)>,
}

/// 读取 APK 当前的渠道号；没有渠道块时返回 `None`。
pub fn read_channel(apk: &Path) -> Result<Option<String>, ChannelError> {
    let mut file = File::open(apk)?;
    let len = file.metadata()?.len();
    let eocd = read_eocd(&mut file, len)?;
    let block = read_signing_block(&mut file, len, eocd.cd_offset)?;
    for (id, value) in block.pairs {
        if id == CHANNEL_BLOCK_ID {
            if value.is_empty() {
                return Ok(None);
            }
            return Ok(Some(decode_channel(&value)?));
        }
    }
    Ok(None)
}

/// 校验渠道名：非空、长度受限、不含控制字符、双引号或反斜杠。
pub fn validate_channel_name(channel: &str) -> Result<(), ChannelError> {
    let trimmed = channel.trim();
    if trimmed.is_empty() {
        return Err(ChannelError::InvalidChannel("渠道名不能为空".into()));
    }
    if trimmed.chars().count() > MAX_CHANNEL_CHARS {
        return Err(ChannelError::InvalidChannel(format!(
            "渠道名不能超过 {MAX_CHANNEL_CHARS} 个字符"
        )));
    }
    for (index, ch) in trimmed.chars().enumerate() {
        if ch < ' ' || ch == '\u{7f}' || ch == '"' || ch == '\\' {
            return Err(ChannelError::InvalidChannel(format!(
                "第 {} 个字符不允许使用（控制字符、双引号或反斜杠）",
                index + 1
            )));
        }
    }
    Ok(())
}

/// 解析渠道列表文件：忽略 BOM、空行与首尾空白，重复渠道报行号。
pub fn parse_channel_list(text: &str) -> Result<Vec<String>, ChannelError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut seen = HashSet::new();
    let mut channels = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        validate_channel_name(name).map_err(|error| {
            ChannelError::InvalidChannel(format!("第 {} 行：{error}", index + 1))
        })?;
        if !seen.insert(name.to_string()) {
            return Err(ChannelError::InvalidChannel(format!(
                "第 {} 行渠道重复：{name}",
                index + 1
            )));
        }
        channels.push(name.to_string());
    }
    if channels.is_empty() {
        return Err(ChannelError::InvalidChannel("渠道列表为空".into()));
    }
    Ok(channels)
}

/// 单个渠道写入；输出已存在时覆盖。
pub fn write_channel(
    input: &Path,
    output: &Path,
    channel: &str,
) -> Result<ChannelOutput, ChannelError> {
    write_channel_inner(input, output, channel, true, None)
}

/// 批量写入渠道包，产物命名为 `原文件名_渠道名.apk`。
pub fn write_channels(
    input: &Path,
    output_dir: &Path,
    channels: &[String],
    overwrite: bool,
    mut on_progress: impl FnMut(ChannelProgress<'_>),
    cancel: Option<&AtomicBool>,
) -> Result<Vec<ChannelOutput>, ChannelError> {
    let normalized = normalize_channels(channels)?;
    fs::create_dir_all(output_dir)?;

    let input_canonical = fs::canonicalize(input)?;
    let mut filenames = HashSet::new();
    for channel in &normalized {
        let filename = channel_output_filename(input, channel);
        if !filenames.insert(filename.to_ascii_lowercase()) {
            return Err(ChannelError::InvalidChannel(format!(
                "渠道 {channel} 与已有渠道生成相同的文件名，请修改渠道名"
            )));
        }
    }

    ensure_not_cancelled(cancel)?;
    on_progress(ChannelProgress {
        stage: ChannelStage::Check,
        index: 0,
        total: normalized.len(),
        channel: "",
        output: output_dir,
    });

    let mut outputs = Vec::with_capacity(normalized.len());
    for (index, channel) in normalized.iter().enumerate() {
        ensure_not_cancelled(cancel)?;
        let path = output_dir.join(channel_output_filename(input, channel));
        ensure_distinct(&input_canonical, &path)?;
        on_progress(ChannelProgress {
            stage: ChannelStage::Write,
            index: index + 1,
            total: normalized.len(),
            channel,
            output: &path,
        });
        let output = write_channel_inner(input, &path, channel, overwrite, cancel)?;
        on_progress(ChannelProgress {
            stage: ChannelStage::Commit,
            index: index + 1,
            total: normalized.len(),
            channel,
            output: &output.path,
        });
        outputs.push(output);
    }
    Ok(outputs)
}

/// 生成 `原文件名_渠道名.apk`；渠道名中的文件系统非法字符会替换为 `_`。
pub fn channel_output_filename(input: &Path, channel: &str) -> String {
    let stem = input
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "app".to_string());
    format!("{stem}_{}.apk", sanitize_channel_for_filename(channel))
}

fn write_channel_inner(
    input: &Path,
    output: &Path,
    channel: &str,
    overwrite: bool,
    cancel: Option<&AtomicBool>,
) -> Result<ChannelOutput, ChannelError> {
    validate_channel_name(channel)?;
    let input_canonical = fs::canonicalize(input)?;
    ensure_distinct(&input_canonical, output)?;
    if output.exists() && !overwrite {
        return Err(ChannelError::OutputExists(output.to_path_buf()));
    }
    ensure_output_parent(output)?;

    let mut source = File::open(&input_canonical)?;
    let len = source.metadata()?.len();
    if len > u32::MAX as u64 {
        return Err(ChannelError::Zip64Unsupported);
    }
    let eocd = read_eocd(&mut source, len)?;
    let block = read_signing_block(&mut source, len, eocd.cd_offset)?;
    let block_offset = block.offset;

    let mut pairs: Vec<(u32, Vec<u8>)> = block
        .pairs
        .into_iter()
        .filter(|(id, _)| *id != CHANNEL_BLOCK_ID && *id != VERITY_PADDING_BLOCK_ID)
        .collect();
    pairs.push((CHANNEL_BLOCK_ID, encode_channel(channel).into_bytes()));
    let new_block = build_signing_block(&pairs);
    let new_cd_offset = block_offset
        .checked_add(new_block.len() as u64)
        .filter(|value| *value <= u32::MAX as u64)
        .ok_or(ChannelError::Zip64Unsupported)?;

    let parent = output.parent().filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;

    source.seek(SeekFrom::Start(0))?;
    copy_exact(&mut source, temp.as_file_mut(), block_offset, cancel)?;
    temp.as_file_mut().write_all(&new_block)?;
    source.seek(SeekFrom::Start(eocd.cd_offset))?;
    copy_exact(
        &mut source,
        temp.as_file_mut(),
        eocd.eocd_offset - eocd.cd_offset,
        cancel,
    )?;

    let mut tail = eocd.tail;
    tail[16..20].copy_from_slice(&(new_cd_offset as u32).to_le_bytes());
    temp.as_file_mut().write_all(&tail)?;
    temp.as_file_mut().flush()?;

    if output.exists() {
        if !overwrite {
            return Err(ChannelError::OutputExists(output.to_path_buf()));
        }
        fs::remove_file(output)?;
    }
    temp.persist(output)
        .map_err(|error| ChannelError::Io(error.error))?;

    let written = fs::metadata(output)?.len();
    match read_channel(output)? {
        Some(value) if value == channel.trim() => {}
        _ => return Err(ChannelError::Malformed("渠道写入自检失败")),
    }
    Ok(ChannelOutput {
        channel: channel.trim().to_string(),
        path: output.to_path_buf(),
        bytes: written,
    })
}

fn normalize_channels(channels: &[String]) -> Result<Vec<String>, ChannelError> {
    if channels.is_empty() {
        return Err(ChannelError::InvalidChannel("渠道列表为空".into()));
    }
    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(channels.len());
    for channel in channels {
        validate_channel_name(channel)?;
        let trimmed = channel.trim().to_string();
        if !seen.insert(trimmed.clone()) {
            return Err(ChannelError::InvalidChannel(format!("渠道重复：{trimmed}")));
        }
        normalized.push(trimmed);
    }
    Ok(normalized)
}

fn ensure_distinct(input_canonical: &Path, output: &Path) -> Result<(), ChannelError> {
    let output_canonical = if output.exists() {
        fs::canonicalize(output)?
    } else {
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = fs::canonicalize(parent)?;
        let name = output.file_name().ok_or(ChannelError::SamePath)?;
        parent.join(name)
    };
    if same_path(input_canonical, &output_canonical) {
        return Err(ChannelError::SamePath);
    }
    Ok(())
}

fn same_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn ensure_output_parent(output: &Path) -> Result<(), ChannelError> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(ChannelError::Io(std::io::Error::new(
            ErrorKind::NotFound,
            format!("输出目录不存在：{}", parent.display()),
        )));
    }
    Ok(())
}

fn ensure_not_cancelled(cancel: Option<&AtomicBool>) -> Result<(), ChannelError> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return Err(ChannelError::Cancelled);
    }
    Ok(())
}

fn copy_exact(
    reader: &mut File,
    writer: &mut File,
    mut remaining: u64,
    cancel: Option<&AtomicBool>,
) -> Result<(), ChannelError> {
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    let mut checked = 0u64;
    while remaining > 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(ChannelError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "APK 文件提前结束",
            )));
        }
        writer.write_all(&buffer[..read])?;
        remaining -= read as u64;
        checked += read as u64;
        if checked >= CANCEL_CHECK_BYTES {
            ensure_not_cancelled(cancel)?;
            checked = 0;
        }
    }
    Ok(())
}

fn read_eocd(file: &mut File, len: u64) -> Result<EocdInfo, ChannelError> {
    if len < ZIP_EOCD_MIN_SIZE as u64 {
        return Err(ChannelError::Malformed("文件太小，不是有效 ZIP/APK"));
    }
    let scan_len = len.min((ZIP_EOCD_MIN_SIZE + ZIP_COMMENT_MAX_SIZE) as u64) as usize;
    let scan_start = len - scan_len as u64;
    file.seek(SeekFrom::Start(scan_start))?;
    let mut scan = vec![0u8; scan_len];
    file.read_exact(&mut scan)?;

    let mut index = scan_len - ZIP_EOCD_MIN_SIZE;
    loop {
        if read_u32(&scan, index) == ZIP_EOCD_SIGNATURE {
            let comment_len = read_u16(&scan, index + 20) as usize;
            if comment_len == scan_len - index - ZIP_EOCD_MIN_SIZE {
                let cd_offset = read_u32(&scan, index + 16) as u64;
                let cd_size = read_u32(&scan, index + 12) as u64;
                if cd_offset == u32::MAX as u64 || cd_size == u32::MAX as u64 {
                    return Err(ChannelError::Zip64Unsupported);
                }
                if cd_offset < ZIP_EOCD_MIN_SIZE as u64 || cd_offset > len {
                    return Err(ChannelError::Malformed("Central Directory 偏移越界"));
                }
                return Ok(EocdInfo {
                    cd_offset,
                    eocd_offset: scan_start + index as u64,
                    tail: scan[index..].to_vec(),
                });
            }
        }
        if index == 0 {
            break;
        }
        index -= 1;
    }
    Err(ChannelError::Malformed("未找到 ZIP EOCD"))
}

fn read_signing_block(
    file: &mut File,
    len: u64,
    cd_offset: u64,
) -> Result<SigningBlock, ChannelError> {
    if cd_offset < APK_SIG_BLOCK_MIN_SIZE {
        return Err(ChannelError::NoSigningBlock);
    }
    file.seek(SeekFrom::Start(cd_offset - 24))?;
    let mut footer = [0u8; 24];
    file.read_exact(&mut footer)?;
    let footer_size = read_u64(&footer, 0);
    if read_u64(&footer, 8) != APK_SIG_BLOCK_MAGIC_LO
        || read_u64(&footer, 16) != APK_SIG_BLOCK_MAGIC_HI
    {
        return Err(ChannelError::NoSigningBlock);
    }
    if footer_size < 24 {
        return Err(ChannelError::Malformed("签名块长度过小"));
    }
    let total = footer_size
        .checked_add(8)
        .filter(|value| *value <= MAX_SIGNING_BLOCK_SIZE && *value <= cd_offset && *value <= len)
        .ok_or(ChannelError::Malformed("签名块长度越界或过大"))?;
    let offset = cd_offset - total;

    file.seek(SeekFrom::Start(offset))?;
    let mut block = vec![0u8; total as usize];
    file.read_exact(&mut block)?;
    if read_u64(&block, 0) != footer_size {
        return Err(ChannelError::Malformed("签名块头尾长度不一致"));
    }
    let pairs = parse_pairs(&block[8..block.len() - 24])?;
    Ok(SigningBlock { offset, pairs })
}

fn parse_pairs(mut data: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, ChannelError> {
    let mut pairs = Vec::new();
    while !data.is_empty() {
        if data.len() < 12 {
            return Err(ChannelError::Malformed("ID-value 长度不足"));
        }
        let pair_len = read_u64(data, 0);
        if pair_len < 4 || pair_len > usize::MAX as u64 {
            return Err(ChannelError::Malformed("ID-value 长度非法"));
        }
        let pair_len = pair_len as usize;
        if pair_len > data.len() - 8 {
            return Err(ChannelError::Malformed("ID-value 超出签名块"));
        }
        let id = read_u32(data, 8);
        pairs.push((id, data[12..8 + pair_len].to_vec()));
        data = &data[8 + pair_len..];
    }
    Ok(pairs)
}

fn build_signing_block(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut pairs_len: u64 = pairs
        .iter()
        .map(|(_, value)| 8 + 4 + value.len() as u64)
        .sum();
    let block_size = pairs_len + 8 + 16;
    let total = block_size + 8;
    let remainder = total % PAGE_ALIGNMENT;
    let mut padding = 0u64;
    if remainder != 0 {
        padding = PAGE_ALIGNMENT - remainder;
        if padding < 12 {
            padding += PAGE_ALIGNMENT;
        }
    }

    let mut output = Vec::with_capacity((total + padding) as usize);
    if padding == 0 {
        push_u64(&mut output, block_size);
        push_pairs(&mut output, pairs);
    } else {
        pairs_len += padding;
        let padded_size = pairs_len + 8 + 16;
        push_u64(&mut output, padded_size);
        push_pairs(&mut output, pairs);
        push_u64(&mut output, padding - 8);
        push_u32(&mut output, VERITY_PADDING_BLOCK_ID);
        output.resize(output.len() + (padding - 12) as usize, 0);
    }
    let size = if padding == 0 {
        block_size
    } else {
        pairs_len + 8 + 16
    };
    push_u64(&mut output, size);
    push_u64(&mut output, APK_SIG_BLOCK_MAGIC_LO);
    push_u64(&mut output, APK_SIG_BLOCK_MAGIC_HI);
    output
}

fn push_pairs(output: &mut Vec<u8>, pairs: &[(u32, Vec<u8>)]) {
    for (id, value) in pairs {
        push_u64(output, 4 + value.len() as u64);
        push_u32(output, *id);
        output.extend_from_slice(value);
    }
}

fn encode_channel(channel: &str) -> String {
    format!("{{\"channel\":\"{}\"}}", channel.trim())
}

fn decode_channel(value: &[u8]) -> Result<String, ChannelError> {
    let text = std::str::from_utf8(value)
        .map_err(|_| ChannelError::Malformed("渠道块不是有效 UTF-8"))?
        .trim();
    if text.starts_with('{') {
        if let Some(channel) = extract_json_string(text, "channel") {
            return Ok(channel);
        }
    }
    Ok(text.to_string())
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)?;
    let colon = json[start + needle.len()..].find(':')? + start + needle.len();
    let quote_start = json[colon..].find('"')? + colon;
    let mut result = String::new();
    let mut escaped = false;
    for ch in json[quote_start + 1..].chars() {
        if escaped {
            result.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(result);
        } else {
            result.push(ch);
        }
    }
    None
}

fn sanitize_channel_for_filename(channel: &str) -> String {
    let mut sanitized = String::new();
    for ch in channel.trim().chars() {
        if ch.is_control() || matches!(ch, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            sanitized.push('_');
        } else {
            sanitized.push(ch);
        }
    }
    let mut sanitized = sanitized
        .trim_end_matches(|ch: char| ch == ' ' || ch == '.')
        .to_string();
    if sanitized.is_empty() {
        sanitized = "channel".to_string();
    }
    if is_windows_reserved_name(&sanitized) {
        sanitized = format!("_{sanitized}");
    }
    if sanitized.chars().count() > MAX_FILENAME_CHANNEL_CHARS {
        let hash = short_hash(channel);
        sanitized = sanitized
            .chars()
            .take(MAX_FILENAME_CHANNEL_CHARS - 9)
            .collect::<String>();
        sanitized.push('_');
        sanitized.push_str(&hash);
    }
    sanitized
}

fn is_windows_reserved_name(name: &str) -> bool {
    let base = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || base
            .strip_prefix("COM")
            .or_else(|| base.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}

fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use zip::write::SimpleFileOptions;

    const FAKE_V2_ID: u32 = 0x7109_871a;

    fn build_apk(pairs: &[(u32, Vec<u8>)], comment: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            zip.start_file("AndroidManifest.xml", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"<manifest/>").unwrap();
            zip.finish().unwrap();
        }
        let bytes = cursor.into_inner();
        let eocd = find_eocd_offset(&bytes);
        let cd_offset = read_u32(&bytes, eocd + 16) as usize;
        let block = build_signing_block(pairs);
        let mut output = Vec::new();
        output.extend_from_slice(&bytes[..cd_offset]);
        output.extend_from_slice(&block);
        output.extend_from_slice(&bytes[cd_offset..]);
        let new_eocd = eocd + block.len();
        let new_cd_offset = cd_offset + block.len();
        output[new_eocd + 16..new_eocd + 20]
            .copy_from_slice(&(new_cd_offset as u32).to_le_bytes());
        if !comment.is_empty() {
            output.extend_from_slice(comment);
            output[new_eocd + 20..new_eocd + 22]
                .copy_from_slice(&(comment.len() as u16).to_le_bytes());
        }
        output
    }

    fn build_unsigned_apk() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            zip.start_file("classes.dex", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"dex").unwrap();
            zip.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn find_eocd_offset(bytes: &[u8]) -> usize {
        let mut index = bytes.len() - ZIP_EOCD_MIN_SIZE;
        loop {
            if read_u32(bytes, index) == ZIP_EOCD_SIGNATURE
                && read_u16(bytes, index + 20) as usize == bytes.len() - index - ZIP_EOCD_MIN_SIZE
            {
                return index;
            }
            if index == 0 {
                panic!("未找到 EOCD");
            }
            index -= 1;
        }
    }

    fn read_pairs(apk: &Path) -> Vec<(u32, Vec<u8>)> {
        let mut file = File::open(apk).unwrap();
        let len = file.metadata().unwrap().len();
        let eocd = read_eocd(&mut file, len).unwrap();
        read_signing_block(&mut file, len, eocd.cd_offset)
            .unwrap()
            .pairs
    }

    fn write_temp(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn 可以读取和替换渠道且保留其他签名块条目() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_temp(
            dir.path(),
            "input.apk",
            &build_apk(
                &[
                    (FAKE_V2_ID, b"fake-v2".to_vec()),
                    (CHANNEL_BLOCK_ID, br#"{"channel":"old"}"#.to_vec()),
                ],
                &[],
            ),
        );
        assert_eq!(read_channel(&input).unwrap().as_deref(), Some("old"));

        let output = dir.path().join("output.apk");
        write_channel(&input, &output, "oppo").unwrap();
        assert_eq!(read_channel(&output).unwrap().as_deref(), Some("oppo"));

        let pairs = read_pairs(&output);
        assert!(pairs.iter().any(|(id, value)| {
            *id == FAKE_V2_ID && value.as_slice() == b"fake-v2"
        }));
        assert_eq!(
            pairs.iter().filter(|(id, _)| *id == CHANNEL_BLOCK_ID).count(),
            1
        );
        assert_eq!(
            pairs
                .iter()
                .filter(|(id, _)| *id == VERITY_PADDING_BLOCK_ID)
                .count(),
            1
        );
    }

    #[test]
    fn 保留_zip_注释并输出可读取的渠道() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_temp(
            dir.path(),
            "input.apk",
            &build_apk(&[(FAKE_V2_ID, b"fake-v2".to_vec())], b"shellsmith-comment"),
        );
        let output = dir.path().join("output.apk");
        write_channel(&input, &output, "huawei").unwrap();
        let bytes = fs::read(&output).unwrap();
        assert!(bytes.ends_with(b"shellsmith-comment"));
        assert_eq!(read_channel(&output).unwrap().as_deref(), Some("huawei"));
    }

    #[test]
    fn 没有签名块时拒绝读写并提示_v2_v3() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_temp(dir.path(), "unsigned.apk", &build_unsigned_apk());
        assert!(matches!(
            read_channel(&input),
            Err(ChannelError::NoSigningBlock)
        ));
        let output = dir.path().join("out.apk");
        assert!(matches!(
            write_channel(&input, &output, "oppo"),
            Err(ChannelError::NoSigningBlock)
        ));
        assert!(!output.exists());
    }

    #[test]
    fn 渠道名校验覆盖空值超长与非法字符() {
        assert!(validate_channel_name("  ").is_err());
        assert!(validate_channel_name(&"a".repeat(257)).is_err());
        assert!(validate_channel_name("bad\"name").is_err());
        assert!(validate_channel_name("bad\\name").is_err());
        assert!(validate_channel_name("bad\nname").is_err());
        assert!(validate_channel_name("oppo-store").is_ok());
        assert!(validate_channel_name("应用宝").is_ok());
    }

    #[test]
    fn 渠道列表忽略_bom_空行并拒绝重复() {
        let parsed = parse_channel_list("\u{feff}oppo\r\n\r\n  huawei  \nvivo\n").unwrap();
        assert_eq!(parsed, ["oppo", "huawei", "vivo"]);
        assert!(parse_channel_list("oppo\n\noppo\n").is_err());
        assert!(parse_channel_list("\n \n").is_err());
        assert!(parse_channel_list("oppo\nbad\"name\n").is_err());
    }

    #[test]
    fn 文件名安全化并规避_windows_保留名() {
        assert_eq!(
            channel_output_filename(Path::new("/tmp/app.apk"), "oppo/tencent"),
            "app_oppo_tencent.apk"
        );
        assert_eq!(
            channel_output_filename(Path::new("/tmp/app.apk"), "CON"),
            "app__CON.apk"
        );
        assert_eq!(
            channel_output_filename(Path::new("/tmp/app.apk"), "应用宝"),
            "app_应用宝.apk"
        );
        let long = "a".repeat(200);
        let name = channel_output_filename(Path::new("/tmp/app.apk"), &long);
        assert!(name.chars().count() < 100);
    }

    #[test]
    fn 批量写入按渠道产出文件并支持覆盖策略() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_temp(
            dir.path(),
            "demo.apk",
            &build_apk(&[(FAKE_V2_ID, b"fake-v2".to_vec())], &[]),
        );
        let output_dir = dir.path().join("channels");
        let channels = vec!["oppo".to_string(), "vivo".to_string()];
        let outputs = write_channels(&input, &output_dir, &channels, false, |_| {}, None).unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(read_channel(&outputs[0].path).unwrap().as_deref(), Some("oppo"));
        assert_eq!(read_channel(&outputs[1].path).unwrap().as_deref(), Some("vivo"));

        let error = write_channels(&input, &output_dir, &channels, false, |_| {}, None).unwrap_err();
        assert!(matches!(error, ChannelError::OutputExists(_)));
        write_channels(&input, &output_dir, &channels, true, |_| {}, None).unwrap();
    }

    #[test]
    fn 输入输出相同或取消时拒绝写入() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_temp(
            dir.path(),
            "demo.apk",
            &build_apk(&[(FAKE_V2_ID, b"fake-v2".to_vec())], &[]),
        );
        assert!(matches!(
            write_channel(&input, &input, "oppo"),
            Err(ChannelError::SamePath)
        ));

        let cancel = AtomicBool::new(true);
        let output_dir = dir.path().join("channels");
        assert!(matches!(
            write_channels(
                &input,
                &output_dir,
                &["oppo".to_string()],
                true,
                |_| {},
                Some(&cancel)
            ),
            Err(ChannelError::Cancelled)
        ));
    }

    #[test]
    fn 重复渠道与文件名冲突在写入前拒绝() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_temp(
            dir.path(),
            "demo.apk",
            &build_apk(&[(FAKE_V2_ID, b"fake-v2".to_vec())], &[]),
        );
        assert!(write_channels(
            &input,
            &dir.path().join("a"),
            &["oppo".to_string(), "oppo".to_string()],
            false,
            |_| {},
            None
        )
        .is_err());
        assert!(write_channels(
            &input,
            &dir.path().join("b"),
            &["a/b".to_string(), "a:b".to_string()],
            false,
            |_| {},
            None
        )
        .is_err());
    }
}
