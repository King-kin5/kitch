package stream

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
)

type Processor struct {
	workers    int
	jobQueue   chan *ProcessingJob
	activeJobs map[string]*ProcessingJob
	mu         sync.RWMutex
}

type ProcessingJob struct {
	ID         string
	InputPath  string
	OutputPath string
	Quality    string
	Status     string
	Error      error
	Progress   float64
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewProcessor(workers int) *Processor {
	p := &Processor{
		workers:    workers,
		jobQueue:   make(chan *ProcessingJob, 100),
		activeJobs: make(map[string]*ProcessingJob),
	}

	go p.startWorkers()
	return p
}

func (p *Processor) startWorkers() {
	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range p.jobQueue {
				p.processJob(job)
			}
		}()
	}
}

func (p *Processor) processJob(job *ProcessingJob) {
	// TODO: Implement FFmpeg processing
	// 1. Validate input
	// 2. Create output directory
	// 3. Run FFmpeg command
	// 4. Monitor progress
	// 5. Handle errors
}

func (p *Processor) AddJob(inputPath, outputPath, quality string) (*ProcessingJob, error) {
	ctx, cancel := context.WithCancel(context.Background())
	job := &ProcessingJob{
		ID:         generateJobID(),
		InputPath:  inputPath,
		OutputPath: outputPath,
		Quality:    quality,
		Status:     "queued",
		ctx:        ctx,
		cancel:     cancel,
	}

	p.mu.Lock()
	p.activeJobs[job.ID] = job
	p.mu.Unlock()

	p.jobQueue <- job
	return job, nil
}

func (p *Processor) GetJobStatus(jobID string) (*ProcessingJob, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	job, exists := p.activeJobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}
	return job, nil
}

func (p *Processor) CancelJob(jobID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	job, exists := p.activeJobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	job.cancel()
	job.Status = "cancelled"
	return nil
}

func generateJobID() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return "job-" + string(b)
}
