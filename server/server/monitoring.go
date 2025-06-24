package server

import (
	"sync"
	"time"
)

// MonitoringTracker tracks server performance metrics
type MonitoringTracker struct {
	mu                 sync.RWMutex
	startTime          time.Time
	queriesCurrentHour int
	queriesLast24H     int
	currentHour        int
	hourlyQueries      [24]int // Rolling 24-hour window
	responseTimes      []float64
	errorCount         int
	totalRequests      int
	lastHourHistogram  [60]int // Per-minute histogram for current hour
}

// NewMonitoringTracker creates a new monitoring tracker
func NewMonitoringTracker() *MonitoringTracker {
	return &MonitoringTracker{
		startTime:   time.Now(),
		currentHour: time.Now().Hour(),
	}
}

// RecordRequest records a successful request with response time
func (m *MonitoringTracker) RecordRequest(responseTimeMs float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	hour := now.Hour()
	minute := now.Minute()

	// Check if we've moved to a new hour
	if hour != m.currentHour {
		// Shift the hourly queries array
		hoursElapsed := (hour - m.currentHour + 24) % 24
		for i := 0; i < hoursElapsed; i++ {
			m.shiftHourlyQueries()
		}
		m.currentHour = hour
		m.queriesCurrentHour = 0
		// Clear histogram for new hour
		m.lastHourHistogram = [60]int{}
	}

	// Record the request
	m.queriesCurrentHour++
	m.hourlyQueries[hour]++
	m.totalRequests++
	m.lastHourHistogram[minute]++

	// Track response time (keep last 1000 for average)
	m.responseTimes = append(m.responseTimes, responseTimeMs)
	if len(m.responseTimes) > 1000 {
		m.responseTimes = m.responseTimes[1:]
	}

	// Recalculate 24-hour total
	m.queriesLast24H = 0
	for _, count := range m.hourlyQueries {
		m.queriesLast24H += count
	}
}

// RecordError records an error
func (m *MonitoringTracker) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.errorCount++
	m.totalRequests++
}

// GetMonitoringInfo returns current monitoring information
func (m *MonitoringTracker) GetMonitoringInfo() *MonitoringInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Calculate average response time
	var avgResponseTime float64
	if len(m.responseTimes) > 0 {
		sum := 0.0
		for _, rt := range m.responseTimes {
			sum += rt
		}
		avgResponseTime = sum / float64(len(m.responseTimes))
	}

	// Calculate error rate
	var errorRate float64
	if m.totalRequests > 0 {
		errorRate = (float64(m.errorCount) / float64(m.totalRequests)) * 100
	}

	// Convert histogram to slice (only non-zero values for efficiency)
	histogram := []int{}
	for _, count := range m.lastHourHistogram {
		histogram = append(histogram, count)
	}

	return &MonitoringInfo{
		QueriesCurrentHour: m.queriesCurrentHour,
		QueriesLast24H:     m.queriesLast24H,
		UptimeStart:        m.startTime.Format(time.RFC3339),
		ResponseTimeAvgMs:  avgResponseTime,
		ErrorRatePercent:   errorRate,
		LastHourHistogram:  histogram,
	}
}

// shiftHourlyQueries shifts the hourly queries array by one hour
func (m *MonitoringTracker) shiftHourlyQueries() {
	// Remove the oldest hour and add a new zero hour
	copy(m.hourlyQueries[:], m.hourlyQueries[1:])
	m.hourlyQueries[23] = 0
}
