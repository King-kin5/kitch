package ffmpeg

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type FFmpeg struct {
	path    string
	threads int
}

type TranscodingOptions struct {
	InputPath        string
	OutputPath       string
	VideoBitrate     string
	AudioBitrate     string
	Resolution       string
	Format           string
	SegmentTime      int
	KeyframeInterval int
}

func New(path string, threads int) *FFmpeg {
	return &FFmpeg{
		path:    path,
		threads: threads,
	}
}

func (f *FFmpeg) Transcode(opts TranscodingOptions) error {
	args := []string{
		"-i", opts.InputPath,
		"-c:v", "libx264",
		"-preset", "veryfast",
		"-b:v", opts.VideoBitrate,
		"-maxrate", opts.VideoBitrate,
		"-bufsize", opts.VideoBitrate,
		"-vf", fmt.Sprintf("scale=%s", opts.Resolution),
		"-c:a", "aac",
		"-b:a", opts.AudioBitrate,
		"-ar", "48000",
		"-g", fmt.Sprintf("%d", opts.KeyframeInterval),
		"-keyint_min", fmt.Sprintf("%d", opts.KeyframeInterval),
		"-sc_threshold", "0",
		"-f", opts.Format,
		"-hls_time", fmt.Sprintf("%d", opts.SegmentTime),
		"-hls_playlist_type", "event",
		"-hls_segment_type", "mpegts",
		"-hls_flags", "independent_segments",
		"-threads", fmt.Sprintf("%d", f.threads),
		opts.OutputPath,
	}

	cmd := exec.Command(f.path, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ffmpeg error: %v, stderr: %s", err, stderr.String())
	}

	return nil
}

func (f *FFmpeg) GetStreamInfo(inputPath string) (map[string]string, error) {
	args := []string{
		"-i", inputPath,
		"-show_entries", "stream=width,height,r_frame_rate,codec_name",
		"-select_streams", "v:0",
		"-of", "csv=p=0",
	}

	cmd := exec.Command(f.path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffprobe error: %v, stderr: %s", err, stderr.String())
	}

	info := make(map[string]string)
	output := strings.TrimSpace(stdout.String())
	parts := strings.Split(output, ",")

	if len(parts) >= 4 {
		info["width"] = parts[0]
		info["height"] = parts[1]
		info["fps"] = parts[2]
		info["codec"] = parts[3]
	}

	return info, nil
}

func (f *FFmpeg) GenerateThumbnail(inputPath, outputPath string, timestamp string) error {
	args := []string{
		"-i", inputPath,
		"-ss", timestamp,
		"-vframes", "1",
		"-q:v", "2",
		outputPath,
	}

	cmd := exec.Command(f.path, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ffmpeg thumbnail error: %v, stderr: %s", err, stderr.String())
	}

	return nil
}
