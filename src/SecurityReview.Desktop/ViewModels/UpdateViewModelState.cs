namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// State machine for <see cref="UpdateViewModel"/>:
/// 空闲 / 检查中 / 无更新 / 有更新 / 下载中 / 待安装 / 失败。
/// </summary>
public enum UpdateViewModelState
{
    /// <summary>空闲 — no check has run yet (or a check was cancelled).</summary>
    Idle,

    /// <summary>检查中 — a version check is in flight.</summary>
    Checking,

    /// <summary>无更新 — the running version is current.</summary>
    NoUpdate,

    /// <summary>有更新 — a newer stable release is available.</summary>
    UpdateAvailable,

    /// <summary>下载中 — the verified installer is downloading (see percent).</summary>
    Downloading,

    /// <summary>待安装 — download finished and hash-verified; apply is next.</summary>
    ReadyToInstall,

    /// <summary>失败 — the last check/download failed; see status text.</summary>
    Failed,
}
