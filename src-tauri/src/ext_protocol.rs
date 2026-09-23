//! 扩展内容协议 `xhub-ext://`：扩展入口与其相对资源的**唯一来源**。
//!
//! 为什么不再让扩展走 asset 协议（见 `docs/adr/0008-extension-content-origin-isolation.md`）：
//! asset 协议的作用域是**全局单例**，而扩展 iframe 一旦与用户数据同源，扩展里一行 `fetch`
//! 就能取走数据根下的数据库（`xhub.db`）、`app.json` 与日志，**绕开桥 API 的权限系统**。
//! 每个扩展使用独立 origin，且与宿主、asset 数据协议跨源。
//!
//! URL 形态：`http://xhub-ext.e-<id 摘要>.localhost/<扩展 id>/<相对路径>`。
//! - WebView2 把自定义协议映射为 `http://<scheme>.localhost/`；非 Windows 平台为
//!   `<scheme>://localhost/`，见 [`base_url`]。
//! - 入口 HTML 由本模块**动态注入桥脚本**后返回，不再把注入结果落盘到扩展目录的
//!   `.xhpack/`（开发扩展的源码目录不该被宿主写脏）。
//!
//! 安全校验（缺一不可）：扩展 id 形状白名单；相对路径逐段 percent 解码后禁止 `..`、
//! 反斜杠、冒号（Windows 盘符 / ADS）与 NUL；解析结果 canonicalize 后必须仍在扩展目录内
//! （防符号链接逃逸）。

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::http::{Request, Response};
use tauri::Manager;

/// URL 路径段的编码集合（保留字母数字与 `-`/`_`/`.`/`~`，其余转义），
/// 与 `url` crate 的 PATH_SEGMENT 口径一致：`/` 必须转义，否则会被当成路径分隔符。
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\')
    .add(b'^')
    .add(b'|');

/// 所有响应都不缓存：本地读盘成本可忽略，而缓存会让「改了代码没生效」与
/// 「扩展更新后仍加载旧资源」变成排查成本极高的偶发问题。
const CACHE_CONTROL: &str = "no-store";

/// 开发扩展目录映射（扩展 id → 源码目录）。「我的扩展」登记时填充；
/// 已装扩展**不在**此表，回退 `<数据根>/extensions/<id>`。
#[derive(Default)]
pub struct DevExtensionDirs(pub Mutex<HashMap<String, PathBuf>>);

impl DevExtensionDirs {
    pub fn get(&self, id: &str) -> Option<PathBuf> {
        self.0.lock().ok().and_then(|m| m.get(id).cloned())
    }

    pub fn insert(&self, id: String, dir: PathBuf) {
        if let Ok(mut m) = self.0.lock() {
            m.insert(id, dir);
        }
    }

    pub fn remove(&self, id: &str) {
        if let Ok(mut m) = self.0.lock() {
            m.remove(id);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut m) = self.0.lock() {
            m.clear();
        }
    }

    /// 当前已注册的开发扩展（id, 目录）快照，供扫描合并使用
    pub fn snapshot(&self) -> Vec<(String, PathBuf)> {
        self.0
            .lock()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }
}

/// 协议 URL 前缀。WebView2（Windows）把自定义协议映射为 `http://<scheme>.localhost/`；
/// 其它平台为 `<scheme>://localhost/`。
pub fn base_url() -> &'static str {
    if cfg!(target_os = "windows") {
        "http://xhub-ext.localhost/"
    } else {
        "xhub-ext://localhost/"
    }
}

/// 每个扩展使用独立且稳定的主机名，禁止通过 document.domain 降级为共同来源。
pub fn origin(id: &str) -> String {
    let host = content_host(id);
    if cfg!(target_os = "windows") || cfg!(target_os = "android") {
        format!("http://xhub-ext.{host}")
    } else {
        format!("xhub-ext://{host}")
    }
}

fn content_host(id: &str) -> String {
    let hash = Sha256::digest(id.as_bytes());
    let key: String = hash[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("e-{key}.localhost")
}

/// 把扩展 id 与扩展目录内的相对路径拼成 iframe 可加载的入口 URL。
/// `rel` 形如 `./module/index.html`（manifest 里写的是相对路径）。
pub fn entry_url(id: &str, rel: &str) -> String {
    let rel = encode_rel_path(rel);
    format!("{}/{}/{}", origin(id), encode_segment(id), rel)
}

fn encode_segment(seg: &str) -> String {
    utf8_percent_encode(seg, PATH_SEGMENT).to_string()
}

fn encode_rel_path(rel: &str) -> String {
    rel.replace('\\', "/")
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .map(encode_segment)
        .collect::<Vec<_>>()
        .join("/")
}

/// 解析某扩展的内容目录：优先「我的扩展」登记的源码目录，其次已装扩展根。
///
/// 返回前一律归一成普通路径（剥掉 Windows 的 `\\?\` verbatim 前缀）：调用方会把这个目录
/// 交给**外部程序**——`service.rs` 拿它拼后端脚本路径喂给 Node、`open_extension_dir` 交给
/// explorer——而 Node 的 CJS 加载器读不了带前缀的脚本路径（会 `EISDIR lstat 'A:'` 后
/// `exit 1`，即「开发目录挂的 service 扩展后端静默起不来」的根因，见 `paths::simplify_path`）。
/// 宿主内部的 fs 调用两种形式都能用，所以统一在这一个出口归一，覆盖全部调用方。
pub fn resolve_ext_dir(app: &tauri::AppHandle, id: &str) -> Result<PathBuf, String> {
    if let Some(state) = app.try_state::<DevExtensionDirs>() {
        if let Some(dir) = state.get(id) {
            if dir.is_dir() {
                return Ok(crate::paths::simplify_existing(&dir));
            }
        }
    }
    let dir = crate::extension::extensions_root(app)?.join(id);
    if dir.is_dir() {
        Ok(crate::paths::simplify_existing(&dir))
    } else {
        Err(format!("NOT_FOUND: 扩展 {id} 不存在"))
    }
}

/// 扩展 id 形状：反向域名，字符集 `[A-Za-z0-9._-]`，不以 `.` 开头（避免落到隐藏目录）。
fn is_valid_ext_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && !id.contains("..")
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn decode_segment(seg: &str) -> Option<String> {
    percent_decode_str(seg).decode_utf8().ok().map(|s| s.into_owned())
}

/// 协议处理入口（在 `lib.rs` 的 Builder 上注册）。
pub fn handle(app: &tauri::AppHandle, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
    let raw_path = request.uri().path().trim_start_matches('/').to_string();
    // Referer 用于兼容回退（历史扩展的 `../assets/...` 写法会丢掉扩展前缀）
    let referer = request
        .headers()
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let host = request.uri().host().unwrap_or("");
    let resolved = request_path_for_host(host, &raw_path, referer.as_deref());
    let result = resolved.and_then(|path| serve(app, &path, None));
    match result {
        Ok((mime, bytes)) => Response::builder()
            .status(200)
            .header("Content-Type", mime)
            .header("Cache-Control", CACHE_CONTROL)
            .header("Content-Security-Policy", content_csp(app, &resolved_id(host, &raw_path, referer.as_deref())))
            .header("X-Content-Type-Options", "nosniff")
            .header("Referrer-Policy", "same-origin")
            .header("Origin-Agent-Cluster", "?1")
            .header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), document-domain=()")
            .body(bytes)
            .unwrap(),
        Err(status) => Response::builder()
            .status(status)
            .header("Cache-Control", CACHE_CONTROL)
            .body(Vec::new())
            .unwrap(),
    }
}

fn resolved_id(host: &str, path: &str, referer: Option<&str>) -> String {
    request_path_for_host(host, path, referer).ok()
        .and_then(|p| parse_request_path(&p).ok()).map(|(id, _)| id).unwrap_or_default()
}

/// 主机名与路径中的扩展身份必须一致；旧 ../assets 写法只回退到同一独立来源。
fn request_path_for_host(host: &str, path: &str, referer: Option<&str>) -> Result<String, u16> {
    if let Ok((id, _)) = parse_request_path(path) {
        if host == content_host(&id) { return Ok(path.to_string()); }
    }
    if let Some(referer) = referer {
        if let Ok(uri) = referer.parse::<tauri::http::Uri>() {
            if let Ok((id, _)) = parse_request_path(uri.path().trim_start_matches('/')) {
                if referer.starts_with(&format!("{}/", origin(&id))) && host == content_host(&id) {
                    parse_rel_path(path)?;
                    return Ok(format!("{id}/{path}"));
                }
            }
        }
    }
    Err(403)
}

fn content_csp(app: &tauri::AppHandle, id: &str) -> String {
    let network = crate::extension::read_manifest(&resolve_ext_dir(app, id).unwrap_or_default())
        .map(|m| m.permissions.iter().any(|p| p == "network"))
        .unwrap_or(false) && crate::extension::permission_granted(app, id, "network");
    let proxy = app.try_state::<crate::proxy::ProxyState>()
        .map(|s| format!(" http://127.0.0.1:{} ws://127.0.0.1:{}", s.port, s.port))
        .unwrap_or_default();
    build_content_csp(network, &proxy)
}

fn build_content_csp(network: bool, proxy: &str) -> String {
    let remote = if network { " https: wss:" } else { "" };
    format!("default-src 'none'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:{remote}; font-src 'self' data:; connect-src 'self'{proxy}{remote}; media-src 'self' blob:{remote}; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; worker-src 'self' blob:")
}

/// 段是否危险：`..` 逃逸 / 反斜杠 / 冒号（Windows 盘符与 NTFS 数据流）/ NUL / 控制字符
fn is_unsafe_segment(seg: &str) -> bool {
    seg == ".."
        || seg.contains('\\')
        || seg.contains('/')
        || seg.contains(':')
        || seg.contains('\0')
        || seg.chars().any(|c| c.is_control())
}

/// 把**整条**路径当相对路径解析成经过校验的段列表（供兼容回退使用）
fn parse_rel_path(raw_path: &str) -> Result<Vec<String>, u16> {
    let mut rel_parts: Vec<String> = Vec::new();
    for raw in raw_path.split('/') {
        if raw.is_empty() {
            continue;
        }
        let seg = decode_segment(raw).ok_or(400u16)?;
        if seg == "." {
            continue;
        }
        if is_unsafe_segment(&seg) {
            return Err(400);
        }
        rel_parts.push(seg);
    }
    if rel_parts.is_empty() {
        return Err(404);
    }
    Ok(rel_parts)
}

/// 把请求路径解析成 `(扩展 id, 相对路径段)`。失败返回 HTTP 状态码。
///
/// 独立成纯函数是为了单测安全边界：`..` 逃逸、反斜杠、冒号（Windows 盘符 / NTFS 数据流）、
/// NUL 与控制字符、空路径（不列目录）。这些分支任何一条漏掉，扩展就能读到扩展目录之外。
fn parse_request_path(raw_path: &str) -> Result<(String, Vec<String>), u16> {
    let mut segs = raw_path.split('/');
    let raw_id = segs.next().unwrap_or("");
    if raw_id.is_empty() {
        return Err(404);
    }
    let id = decode_segment(raw_id).ok_or(400u16)?;
    if !is_valid_ext_id(&id) {
        log::warn!("扩展协议拒绝非法 id: {raw_id}");
        return Err(400);
    }

    let mut rel_parts: Vec<String> = Vec::new();
    for raw in segs {
        if raw.is_empty() {
            continue; // 容忍重复斜杠
        }
        let seg = decode_segment(raw).ok_or(400u16)?;
        if seg == "." {
            continue;
        }
        if is_unsafe_segment(&seg) {
            log::warn!("扩展协议拒绝非法路径段 {id}: {raw}");
            return Err(400);
        }
        rel_parts.push(seg);
    }
    if rel_parts.is_empty() {
        return Err(404); // 不列目录
    }
    Ok((id, rel_parts))
}

/// 兼容回退：把"丢了扩展前缀"的请求归回它所属的扩展。
///
/// 为什么需要：**旧实现**把入口 HTML 写到 `<扩展目录>/.xhpack/<surface>.html`（下一层子目录），
/// 因此历史扩展普遍用 `../assets/x.js`、`../favicon.ico` 这类**上一级**写法引用扩展根下的资源。
/// 新协议的入口就在扩展根（`/<id>/tool.html`），浏览器把 `../assets/x.js` 规范化成 `/assets/x.js`
/// —— 第一段不再是扩展 id，按正常解析会 404，表现为「扩展白屏、但入口日志正常」。
///
/// 归因依据是 Referer：同源请求由**浏览器**设置该头，页面脚本无法伪造。
/// 安全上不扩大能力：`/<任意 id>/...` 本来就是可直接访问的（扩展之间本就互读，见 ADR 0008 的残余风险），
/// 这里只是把丢了前缀的请求接回去；`..`/反斜杠/冒号等危险段依然一律拒绝。
fn fallback_from_referer(raw_path: &str, referer: &str) -> Option<(String, Vec<String>)> {
    let base = base_url().trim_end_matches('/');
    let idx = referer.find(base)?;
    let rest = referer[idx + base.len()..].trim_start_matches('/');
    let id_raw = rest.split(['/', '?', '#']).next()?;
    let id = decode_segment(id_raw)?;
    if !is_valid_ext_id(&id) {
        return None;
    }
    let rel = parse_rel_path(raw_path).ok()?;
    Some((id, rel))
}

/// 解析并读取路径：`<扩展 id>/<相对路径>`。失败时返回 HTTP 状态码。
fn serve(app: &tauri::AppHandle, raw_path: &str, referer: Option<&str>) -> Result<(String, Vec<u8>), u16> {
    let (mut id, mut rel_parts) = parse_request_path(raw_path)?;

    // 解析出的 id 必须是**已注册/已装**的扩展。不是的话，最可能的情况是历史扩展用
    // `../assets/x.js`、`../favicon.ico` 这类上一级写法引用扩展根资源，被浏览器规范化后
    // 丢掉了扩展前缀（`assets` 形状合法但不是扩展 id）——此时用 Referer 归因（见 fallback_from_referer）。
    // 注意：危险路径（`..`/反斜杠/冒号…）在 parse_request_path 就被 400 挡掉了，走不到这里。
    let root = match resolve_ext_dir(app, &id) {
        Ok(r) => r,
        Err(_) => {
            let Some((fallback_id, fallback_rel)) = referer.and_then(|r| fallback_from_referer(raw_path, r))
            else {
                return Err(404);
            };
            let Ok(r) = resolve_ext_dir(app, &fallback_id) else {
                return Err(404);
            };
            log::debug!("扩展协议兼容回退: {fallback_id} <- /{raw_path}");
            id = fallback_id;
            rel_parts = fallback_rel;
            r
        }
    };
    let _ = &id;
    let mut full = root.clone();
    for p in &rel_parts {
        full.push(p);
    }

    // canonicalize 后必须仍在扩展目录内：挡住符号链接 / junction 指到目录外的情形
    let root_canon = std::fs::canonicalize(&root).map_err(|_| 404u16)?;
    let full_canon = std::fs::canonicalize(&full).map_err(|_| 404u16)?;
    if !full_canon.starts_with(&root_canon) {
        log::warn!(
            "扩展协议拒绝越界路径 {id}: {}",
            full_canon.display()
        );
        return Err(403);
    }
    if !full_canon.is_file() {
        return Err(404);
    }

    let canonical_parts: Vec<String> = full_canon.strip_prefix(&root_canon).map_err(|_| 403u16)?
        .iter().map(|p| p.to_string_lossy().into_owned()).collect();
    if !public_content_path(&rel_parts) || !public_content_path(&canonical_parts) { return Err(403); }

    let mut bytes = std::fs::read(&full_canon).map_err(|_| 404u16)?;
    let mime = mime_for(&full_canon);
    // 入口 HTML：动态注入桥脚本（等价于旧的 `.xhpack/<surface>.html`，但不落盘）
    //
    // ⚠️ 这里必须**按扩展名**判断，不能比较 MIME 字符串：`mime_for` 返回的是
    // `"text/html; charset=utf-8"`，与字面量 `"text/html"` 永不相等 —— 曾经的写法导致
    // 桥脚本从未注入，表现为「扩展自己的 JS 能跑、但没有 window.xhub、8 秒后判白屏」。
    if is_html(&full_canon) {
        if let Ok(html) = std::str::from_utf8(&bytes) {
            bytes = crate::extension::inject_bridge(html, crate::extension::XHUB_BRIDGE_SCRIPT)
                .into_bytes();
        }
    }
    Ok((mime.to_string(), bytes))
}

/// 配置、凭据、运行数据与开发元数据不能通过网页资源协议读取。
fn public_content_path(parts: &[String]) -> bool {
    parts.iter().all(|p| {
        let p = p.to_ascii_lowercase();
        !p.starts_with('.') && !matches!(p.as_str(), "backend" | "server" | "node_modules" | "data" | "logs")
            && !crate::market::sensitive_package_file(&p)
    })
}

/// 是否是需要注入桥脚本的 HTML（按扩展名，别看 MIME 字符串）
fn is_html(path: &std::path::Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str(),
        "html" | "htm"
    )
}

fn mime_for(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" | "cjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "txt" | "md" => "text/plain; charset=utf-8",
        "map" => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn security_network_permission_controls_content_policy() {
        let blocked = super::build_content_csp(false, " http://127.0.0.1:12345");
        assert!(!blocked.contains("https:"));
        assert!(blocked.contains("http://127.0.0.1:12345"));
        assert!(blocked.contains("frame-src 'none'"));
        assert!(blocked.contains("form-action 'none'"));
        assert!(super::build_content_csp(true, "").contains("https: wss:"));
    }
    use super::*;

    #[test]
    fn ext_id_shape_is_validated() {
        assert!(is_valid_ext_id("com.x-hub.ctool"));
        assert!(is_valid_ext_id("my_ext-1"));
        assert!(!is_valid_ext_id(""));
        assert!(!is_valid_ext_id(".hidden"));
        assert!(!is_valid_ext_id("a..b"));
        assert!(!is_valid_ext_id("a/b"));
        assert!(!is_valid_ext_id("扩展"));
    }

    #[test]
    fn entry_url_encodes_each_segment() {
        assert_eq!(
            entry_url("com.x-hub.ctool", "./module/index.html"),
            format!("{}/com.x-hub.ctool/module/index.html", origin("com.x-hub.ctool"))
        );
        // 空格与中文按段编码，斜杠保留
        let url = entry_url("com.x-hub.x", "./my dir/页 面.html");
        assert!(url.ends_with("/my%20dir/%E9%A1%B5%20%E9%9D%A2.html"), "{url}");
    }

    #[test]
    fn segment_encoding_roundtrips() {
        for seg in ["a b", "中文", "#x", "%y", "a+b"] {
            let enc = encode_segment(seg);
            assert_eq!(decode_segment(&enc).unwrap(), seg);
        }
    }

    #[test]
    fn falls_back_to_referer_for_legacy_asset_paths() {
        // 历史扩展用 `../assets/x.js` 引用扩展根资源 → 浏览器规范化成 `/assets/x.js`（丢了扩展前缀）
        let referer = format!("{}com.x-hub.ctool/tool.html", base_url());
        let got = fallback_from_referer("assets/tool-abc.js", &referer).expect("应能回退");
        assert_eq!(got.0, "com.x-hub.ctool");
        assert_eq!(got.1, vec!["assets", "tool-abc.js"]);

        // 绝对路径（`../favicon.ico` 越界到根）同理
        assert_eq!(
            fallback_from_referer("favicon.ico", &referer).unwrap().0,
            "com.x-hub.ctool"
        );

        // Referer 带 query 也要能解析
        let with_query = format!("{}com.x-hub.ctool/tool.html?v=1", base_url());
        assert_eq!(
            fallback_from_referer("assets/a.css", &with_query).unwrap().0,
            "com.x-hub.ctool"
        );

        // 非本协议的来源绝不回退（不把任意请求归到某个扩展）
        assert!(fallback_from_referer("assets/a.js", "https://evil.example/x").is_none());
        assert!(fallback_from_referer("assets/a.js", "http://asset.localhost/x").is_none());
        // Referer 第一段**形状非法**也不回退
        assert!(fallback_from_referer("assets/a.js", &format!("{}.hidden/x.html", base_url())).is_none());
        assert!(fallback_from_referer("assets/a.js", &format!("{}a..b/x.html", base_url())).is_none());
        // 注意分工：形状合法但**未安装**的 id（例如 referer 里的 `tool.html`）这里会返回 Some，
        // 由调用方 `serve` 用 `resolve_ext_dir(...).is_ok()` 兜住 —— 那一道是"能不能接管"的判据，
        // 本函数只负责"能不能解析出候选"。改动时别把这道检查挪掉。

        // 危险路径在回退路径上依然被拒（`..` 与反斜杠不能借回退混进来）
        assert!(fallback_from_referer("%2e%2e/secret", &referer).is_none());
        assert!(fallback_from_referer("a%5Cb.js", &referer).is_none());
    }

    #[test]
    fn detects_html_for_bridge_injection() {
        // 关键回归：判断必须按扩展名，不能比较 MIME 字符串
        //（mime_for 返回 "text/html; charset=utf-8"，与 "text/html" 永不相等）
        for name in ["index.html", "view.HTML", "a/b/module.htm"] {
            assert!(is_html(std::path::Path::new(name)), "{name} 应判为 HTML");
        }
        for name in ["app.js", "style.css", "data.json", "icon.svg", "noext"] {
            assert!(!is_html(std::path::Path::new(name)), "{name} 不应判为 HTML");
        }
        // 并且确认 mime_for 的 HTML 结果确实不是裸的 "text/html"（就是当年踩的坑）
        assert_ne!(mime_for(std::path::Path::new("index.html")), "text/html");
    }

    #[test]
    fn parses_valid_request_paths() {
        let (id, parts) = parse_request_path("com.x-hub.ctool/module/index.html").unwrap();
        assert_eq!(id, "com.x-hub.ctool");
        assert_eq!(parts, vec!["module", "index.html"]);

        // 容忍重复斜杠与 `./` 前缀（扩展里写 `./index.html` 很常见）
        let (id2, parts2) = parse_request_path("com.x-hub.ctool//.//view/index.html").unwrap();
        assert_eq!(id2, "com.x-hub.ctool");
        assert_eq!(parts2, vec!["view", "index.html"]);

        // 段内 percent 解码（中文 / 空格目录名）
        let (_, parts3) = parse_request_path("com.x-hub.ctool/%E4%B8%AD%E6%96%87/a%20b.html").unwrap();
        assert_eq!(parts3, vec!["中文", "a b.html"]);
    }

    #[test]
    fn rejects_unsafe_request_paths() {
        // 空路径 / 只要目录 → 404（不列目录）
        assert_eq!(parse_request_path("").unwrap_err(), 404);
        assert_eq!(parse_request_path("com.x-hub.ctool").unwrap_err(), 404);
        assert_eq!(parse_request_path("com.x-hub.ctool/").unwrap_err(), 404);
        assert_eq!(parse_request_path("com.x-hub.ctool/./").unwrap_err(), 404);

        // 非法 id → 400
        assert_eq!(parse_request_path(".hidden/index.html").unwrap_err(), 400);
        assert_eq!(parse_request_path("a..b/index.html").unwrap_err(), 400);
        assert_eq!(parse_request_path("%E6%89%A9%E5%B1%95/index.html").unwrap_err(), 400); // 非 ASCII id

        // 路径逃逸与非法段 → 400
        assert_eq!(parse_request_path("com.x-hub.x/../secret.txt").unwrap_err(), 400);
        assert_eq!(parse_request_path("com.x-hub.x/%2e%2e/secret.txt").unwrap_err(), 400); // 编码后的 ..
        assert_eq!(parse_request_path("com.x-hub.x/a%5Cb.js").unwrap_err(), 400); // 反斜杠 %5C
        assert_eq!(parse_request_path("com.x-hub.x/C:/Windows/win.ini").unwrap_err(), 400); // 盘符冒号
        assert_eq!(parse_request_path("com.x-hub.x/a%00b.js").unwrap_err(), 400); // NUL
        assert_eq!(parse_request_path("com.x-hub.x/a%0Ab.js").unwrap_err(), 400); // 控制字符
    }

    #[test]
    fn security_content_origins_and_private_files_are_isolated() {
        let a = "com.x-hub.a";
        let b = "com.x-hub.b";
        assert_ne!(origin(a), origin(b));
        assert!(request_path_for_host(&content_host(a), &format!("{a}/index.html"), None).is_ok());
        assert!(request_path_for_host(&content_host(a), &format!("{b}/index.html"), None).is_err());
        assert!(request_path_for_host("localhost", &format!("{a}/index.html"), None).is_err());
        for p in [".config.json", ".storage.json", ".env", "app.db", "credentials.json", "server/key.js", "data/cache.json"] {
            assert!(!public_content_path(&p.split('/').map(String::from).collect::<Vec<_>>()), "{p}");
        }
        assert!(public_content_path(&vec!["assets".into(), "app.js".into()]));
        assert!(parse_request_path(&format!("{a}/a%2F..%2Fsecret")).is_err());
        let referer = entry_url(a, "index.html");
        assert_eq!(request_path_for_host(&content_host(a), "assets/app.js", Some(&referer)).unwrap(), format!("{a}/assets/app.js"));
    }
}
