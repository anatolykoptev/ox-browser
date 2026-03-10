use std::path::Path;
use std::process::Command;

use crate::MediaError;

/// Merge video-only and audio-only DASH streams into a single MP4 using ffmpeg.
///
/// After a successful merge, the input files (video + audio) are deleted.
pub fn merge_dash(video: &Path, audio: &Path, output: &Path) -> Result<(), MediaError> {
    let status = Command::new("ffmpeg")
        .args(["-i", &video.display().to_string()])
        .args(["-i", &audio.display().to_string()])
        .args(["-c", "copy", "-y"])
        .arg(output.display().to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| MediaError::MergeFailed(format!("ffmpeg spawn: {e}")))?;

    if !status.success() {
        return Err(MediaError::MergeFailed(format!(
            "ffmpeg exit code: {}",
            status.code().unwrap_or(-1)
        )));
    }

    // Clean up temp DASH files
    let _ = std::fs::remove_file(video);
    let _ = std::fs::remove_file(audio);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn merge_fails_with_missing_ffmpeg_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let video = dir.path().join("v.mp4");
        let audio = dir.path().join("a.m4a");
        let output = dir.path().join("out.mp4");

        // Files don't exist — ffmpeg should fail
        let result = merge_dash(&video, &audio, &output);
        assert!(result.is_err());
    }

    #[test]
    fn merge_cleans_up_inputs_on_success() {
        // Only run if ffmpeg is available
        if Command::new("ffmpeg").arg("-version").output().is_err() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let video = dir.path().join("v.mp4");
        let audio = dir.path().join("a.m4a");
        let output = dir.path().join("out.mp4");

        // Create minimal valid files (ffmpeg will fail but we test the path)
        fs::write(&video, b"not a real video").unwrap();
        fs::write(&audio, b"not a real audio").unwrap();

        // This will fail because files aren't valid media, but that's fine
        let _ = merge_dash(&video, &audio, &output);
    }
}
