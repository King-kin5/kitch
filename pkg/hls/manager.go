package hls

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type HLSManager struct {
	basePath     string
	segmentTime  int
	maxSegments  int
	cleanupAfter time.Duration
}

type StreamInfo struct {
	ID          string
	Title       string
	Description string
	CreatedAt   time.Time
	IsLive      bool
	Viewers     int
}

func NewManager(basePath string, segmentTime, maxSegments int, cleanupAfter time.Duration) *HLSManager {
	return &HLSManager{
		basePath:     basePath,
		segmentTime:  segmentTime,
		maxSegments:  maxSegments,
		cleanupAfter: cleanupAfter,
	}
}

func (m *HLSManager) CreateStreamDirectory(streamID string) error {
	paths := []string{
		filepath.Join(m.basePath, streamID),
		filepath.Join(m.basePath, streamID, "segments"),
		filepath.Join(m.basePath, streamID, "thumbnails"),
	}

	for _, path := range paths {
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", path, err)
		}
	}

	return nil
}

func (m *HLSManager) GenerateMasterPlaylist(streamID string, qualities []string) error {
	content := "#EXTM3U\n#EXT-X-VERSION:3\n"

	for _, quality := range qualities {
		content += fmt.Sprintf("#EXT-X-STREAM-INF:BANDWIDTH=%s,RESOLUTION=%s\n%s/playlist.m3u8\n",
			getBandwidth(quality),
			getResolution(quality),
			quality,
		)
	}

	path := filepath.Join(m.basePath, streamID, "master.m3u8")
	return os.WriteFile(path, []byte(content), 0644)
}

func (m *HLSManager) UpdatePlaylist(streamID string, segmentName string) error {
	playlistPath := filepath.Join(m.basePath, streamID, "playlist.m3u8")

	content := "#EXTM3U\n"
	content += "#EXT-X-VERSION:3\n"
	content += fmt.Sprintf("#EXT-X-TARGETDURATION:%d\n", m.segmentTime)
	content += "#EXT-X-MEDIA-SEQUENCE:0\n"
	content += "#EXT-X-PLAYLIST-TYPE:EVENT\n"

	// Add segments
	segments, err := m.getSegments(streamID)
	if err != nil {
		return err
	}

	for _, segment := range segments {
		content += fmt.Sprintf("#EXTINF:%.3f,\n%s\n", float64(m.segmentTime), segment)
	}

	return os.WriteFile(playlistPath, []byte(content), 0644)
}

func (m *HLSManager) CleanupOldSegments(streamID string) error {
	segments, err := m.getSegments(streamID)
	if err != nil {
		return err
	}

	if len(segments) <= m.maxSegments {
		return nil
	}

	segmentsToDelete := segments[:len(segments)-m.maxSegments]
	for _, segment := range segmentsToDelete {
		path := filepath.Join(m.basePath, streamID, "segments", segment)
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("failed to delete segment %s: %v", segment, err)
		}
	}

	return nil
}

func (m *HLSManager) getSegments(streamID string) ([]string, error) {
	segmentsDir := filepath.Join(m.basePath, streamID, "segments")
	files, err := os.ReadDir(segmentsDir)
	if err != nil {
		return nil, err
	}

	var segments []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".ts") {
			segments = append(segments, file.Name())
		}
	}

	return segments, nil
}

func getBandwidth(quality string) string {
	switch quality {
	case "1080p":
		return "5000000"
	case "720p":
		return "2800000"
	case "480p":
		return "1400000"
	case "360p":
		return "800000"
	default:
		return "2800000"
	}
}

func getResolution(quality string) string {
	switch quality {
	case "1080p":
		return "1920x1080"
	case "720p":
		return "1280x720"
	case "480p":
		return "854x480"
	case "360p":
		return "640x360"
	default:
		return "1280x720"
	}
}
