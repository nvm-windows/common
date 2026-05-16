package http

import (
	"context"
	"errors"
	"io"
	gohttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var GlobalHeaders = map[string]string{}

type DownloadConfig struct {
	Cache         bool
	Destination   string
	AllowInsecure bool
	Headers       map[string]string
}

type DownloadResponse struct {
	Success   bool
	Content   []byte
	FromCache bool
	CachePath string
	ETag      string
	Response  *gohttp.Response
}

type DownloadProgress struct {
	Downloaded int64
	Total      int64
}

type DownloadResult struct {
	Response *DownloadResponse
	Error    error
}

type DownloadJob struct {
	ctx      context.Context
	cancel   context.CancelFunc
	Progress <-chan DownloadProgress
	Result   <-chan DownloadResult
	wg       sync.WaitGroup
}

// Cancel stops the download
func (j *DownloadJob) Cancel() {
	j.cancel()
}

// Wait blocks until download completes and returns the result
func (j *DownloadJob) Wait() (*DownloadResponse, error) {
	result := <-j.Result
	return result.Response, result.Error
}

// Download starts an asynchronous download and returns a DownloadJob.
// The caller must read from the job's Result channel or call Wait() to retrieve the response.
func Download(url string, config ...DownloadConfig) (*DownloadJob, error) {
	if url == "" {
		return nil, errors.New("empty URL")
	}

	// Normalize the URL to handle trailing slashes and path inconsistencies
	normalizedURL, err := normalizeURL(url)
	if err != nil {
		return nil, errors.New("invalid URL: " + err.Error())
	}

	var cfg DownloadConfig
	if len(config) > 0 {
		cfg = config[0]
	} else {
		cfg = DownloadConfig{Cache: false}
	}

	ctx, cancel := context.WithCancel(context.Background())
	progressChan := make(chan DownloadProgress, 10)
	resultChan := make(chan DownloadResult, 1)

	job := &DownloadJob{
		ctx:      ctx,
		cancel:   cancel,
		Progress: progressChan,
		Result:   resultChan,
	}

	job.wg.Add(1)
	go func() {
		defer job.wg.Done()
		defer close(progressChan)
		defer close(resultChan)
		response, err := downloadInternal(ctx, normalizedURL, cfg, progressChan)
		resultChan <- DownloadResult{Response: response, Error: err}
	}()

	return job, nil
}

// downloadInternal performs the actual download logic
func downloadInternal(ctx context.Context, url string, cfg DownloadConfig, progress chan<- DownloadProgress) (*DownloadResponse, error) {
	req, err := makeRequest("GET", url)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	// Apply global headers
	for k, v := range GlobalHeaders {
		req.Header.Set(k, v)
	}

	// Apply custom headers from DownloadConfig
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	client := new(cfg.AllowInsecure)
	res, err := client.client.Do(req)
	if err != nil {
		// HTTP/2 stream errors can occur in elevated/admin Windows contexts due to
		// differences in system proxy routing. Retry with HTTP/1.1 forced.
		if strings.Contains(err.Error(), "stream error") {
			req2, _ := makeRequest("GET", url)
			req2 = req2.WithContext(ctx)
			res, err = h1only(cfg.AllowInsecure).client.Do(req2)
		}
		if err != nil {
			return nil, err
		}
	}

	result := &DownloadResponse{}
	result.Response = res
	result.Success = res.StatusCode >= 200 && res.StatusCode < 300

	if !cfg.Cache {
		content, readErr := readWithProgress(ctx, res.Body, res.ContentLength, progress)
		_ = res.Body.Close()
		if readErr != nil {
			return nil, readErr
		}

		result.Content = content

		// Write to destination if configured
		if cfg.Destination != "" {
			if err := save(url, cfg.Destination, content); err != nil {
				return nil, err
			}
		}

		return result, nil
	}

	responseEtag := normalizeEtag(res.Header.Get("ETag"))
	result.ETag = responseEtag

	if responseEtag == "" {
		content, readErr := readWithProgress(ctx, res.Body, res.ContentLength, progress)
		_ = res.Body.Close()
		if readErr != nil {
			return nil, readErr
		}

		result.Content = content

		// Write to destination if configured
		if cfg.Destination != "" {
			if err := save(url, cfg.Destination, content); err != nil {
				return nil, err
			}
		}

		return result, nil
	}

	cachePath, err := getCacheFilePath(url, responseEtag)
	if err != nil {
		_ = res.Body.Close()
		return nil, err
	}
	result.CachePath = cachePath
	_ = pruneURLCacheEntries(url, cachePath)

	if content, readErr := os.ReadFile(cachePath); readErr == nil {
		// If server provides size metadata, reject truncated cache entries.
		if res.ContentLength > 0 && int64(len(content)) != res.ContentLength {
			_ = os.Remove(cachePath)
		} else {
			result.FromCache = true
			result.Content = content
			_ = res.Body.Close()

			// Write to destination if configured
			if cfg.Destination != "" {
				if err := save(url, cfg.Destination, content); err != nil {
					return nil, err
				}
			}

			return result, nil
		}
	}

	cacheFile, err := os.Create(cachePath)
	if err != nil {
		_ = res.Body.Close()
		return nil, err
	}

	res.Body = &cacheWriteCloser{
		body: res.Body,
		file: cacheFile,
		path: cachePath,
	}

	content, readErr := readWithProgress(ctx, res.Body, res.ContentLength, progress)
	_ = res.Body.Close()
	if readErr != nil {
		return nil, readErr
	}

	result.Content = content

	// Write to destination if configured
	if cfg.Destination != "" {
		if err := save(url, cfg.Destination, content); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// readWithProgress reads from the reader while sending progress updates.
// Returns early if context is cancelled.
func readWithProgress(ctx context.Context, reader io.Reader, total int64, progress chan<- DownloadProgress) ([]byte, error) {
	progReader := &progressReader{
		reader:   reader,
		total:    total,
		progress: progress,
		ctx:      ctx,
	}

	return io.ReadAll(progReader)
}

type progressReader struct {
	reader   io.Reader
	total    int64
	current  int64
	progress chan<- DownloadProgress
	ctx      context.Context
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.current += int64(n)
		select {
		case pr.progress <- DownloadProgress{Downloaded: pr.current, Total: pr.total}:
		case <-pr.ctx.Done():
			return n, pr.ctx.Err()
		default:
			// Drop progress updates when no receiver is active; prevents deadlock
			// for callers that only use job.Wait() and never read job.Progress.
		}
	}
	return n, err
}

// extractFilenameFromURL extracts the filename from a given URL.
// For example, "https://example.com/path/to/file.tar.gz" returns "file.tar.gz".
// If the path is empty or ends with a slash, returns "downloaded".
func extractFilenameFromURL(downloadURL string) string {
	parsed, err := url.Parse(downloadURL)
	if err != nil {
		return "downloaded"
	}

	path := parsed.Path
	if path == "" || strings.HasSuffix(path, "/") {
		return "downloaded"
	}

	return filepath.Base(path)
}

// resolveDestinationPath determines the actual file path to write to.
// If destination is a directory, it appends the filename from the URL.
// Otherwise, it treats destination as a full file path.
func resolveDestinationPath(downloadURL, destination string) (string, error) {
	// Check if destination is a directory
	info, err := os.Stat(destination)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		// Path doesn't exist; check if parent directory exists and treat as file
		parentDir := filepath.Dir(destination)
		if parentDir == "." || parentDir == "" {
			// Use current directory, treat destination as filename
			return destination, nil
		}
		if _, err := os.Stat(parentDir); err == nil {
			// Parent exists, treat destination as filename
			return destination, nil
		}
		return "", err
	}

	if info.IsDir() {
		// Destination is a directory; append filename from URL
		filename := extractFilenameFromURL(downloadURL)
		return filepath.Join(destination, filename), nil
	}

	// Destination is a file path
	return destination, nil
}

// writeDestination writes content to the specified destination path.
func save(downloadURL, destination string, content []byte) error {
	filePath, err := resolveDestinationPath(downloadURL, destination)
	if err != nil {
		return err
	}

	// Create parent directories if needed
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return err
	}

	return os.WriteFile(filePath, content, 0644)
}
