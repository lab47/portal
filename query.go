package portal

import "github.com/lab47/portal/query"

// Query models remain aliases so existing Portal callers and wire formats stay compatible.
type (
	MonitorRequest          = query.MonitorRequest
	NumericComparison       = query.NumericComparison
	TracepointFilter        = query.TracepointFilter
	TracepointEvent         = query.TracepointEvent
	DiskFilter              = query.DiskFilter
	DiskEvent               = query.DiskEvent
	SyscallFile             = query.SyscallFile
	ProcessFilter           = query.ProcessFilter
	ProcessEvent            = query.ProcessEvent
	ProcessInfo             = query.ProcessInfo
	Snapshot                = query.Snapshot
	PacketFilter            = query.PacketFilter
	PacketEvent             = query.PacketEvent
	CollectionStats         = query.CollectionStats
	Event                   = query.Event
	AggregateMetric         = query.AggregateMetric
	AggregationRequest      = query.AggregationRequest
	AggregateCount          = query.AggregateCount
	AggregateValue          = query.AggregateValue
	HistogramBucket         = query.HistogramBucket
	Histogram               = query.Histogram
	AggregateRow            = query.AggregateRow
	AggregationResult       = query.AggregationResult
	AggregateReport         = query.AggregateReport
	AggregateExpression     = query.AggregateExpression
	AggregateComputedColumn = query.AggregateComputedColumn
	StackCapture            = query.StackCapture
	StackShape              = query.StackShape
	CapturedStack           = query.CapturedStack
	StackCoverage           = query.StackCoverage
	StackCoverageReport     = query.StackCoverageReport
	SymbolRequest           = query.SymbolRequest
	SymbolResult            = query.SymbolResult
	SymbolFrame             = query.SymbolFrame
	SymbolRecord            = query.SymbolRecord
	CPUInfo                 = query.CPUInfo
	MemoryInfo              = query.MemoryInfo
	InterfaceInfo           = query.InterfaceInfo
	KernelInfo              = query.KernelInfo
	KernelCounters          = query.KernelCounters
	SensorInfo              = query.SensorInfo
	ContainerInfo           = query.ContainerInfo
	CgroupInfo              = query.CgroupInfo
	CgroupIO                = query.CgroupIO
	CgroupIODevice          = query.CgroupIODevice
	GPUInfo                 = query.GPUInfo
	SampleField             = query.SampleField
	SamplingCapability      = query.SamplingCapability
	Capabilities            = query.Capabilities
	SourceCapability        = query.SourceCapability
	FieldCapability         = query.FieldCapability
	FilterCapability        = query.FilterCapability
	AggregateCapability     = query.AggregateCapability
	CapabilityLimits        = query.CapabilityLimits
)

const (
	DefaultSampleInterval = query.DefaultSampleInterval
	MinSampleInterval     = query.MinSampleInterval
)

// ParseMonitorQuery compiles the shared query DSL.
func ParseMonitorQuery(text string) (MonitorRequest, error) { return query.ParseMonitorQuery(text) }
