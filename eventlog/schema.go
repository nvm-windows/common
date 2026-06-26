package eventlog

var (
	// These defaults are overridden in certified builds from cli/src/manifest.json.
	providerName             = "NVM for Windows"
	providerDisplayName      = "NVM for Windows"
	providerManifestFileName = "NVMWindows.Events.man"
)

const (
	providerOperationalChannel uint8 = 16

	levelError         uint8 = 2
	levelWarning       uint8 = 3
	levelInformational uint8 = 4

	// Manifest channel keyword base (OperationalChannel_KEYWORD in NVMWindows.Events.h)
	// OR'd with provider keyword masks so Event Log publishing accepts the event.
	keywordOperational uint64 = 0x8000000000000001
	keywordExecution   uint64 = 0x8000000000000002

	taskCliOperational  uint16 = 1
	taskShimExecution   uint16 = 2
	taskShimOperational uint16 = 3
	taskStructured      uint16 = 4

	RegisteredInfoID    uint32 = 100
	RegisteredWarningID uint32 = 101
	RegisteredErrorID   uint32 = 102

	RegisteredStructuredInfoID    uint32 = 120
	RegisteredStructuredWarningID uint32 = 121
	RegisteredStructuredErrorID   uint32 = 122

	RegisteredShimExecutionID uint32 = 200

	RegisteredShimInfoID    uint32 = 210
	RegisteredShimWarningID uint32 = 211
	RegisteredShimErrorID   uint32 = 212
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type eventDataDescriptor struct {
	Ptr      uint64
	Size     uint32
	Reserved uint32
}

var providerGUID = guid{
	Data1: 0x4c0f8d8e,
	Data2: 0x2d6b,
	Data3: 0x4f93,
	Data4: [8]byte{0x9f, 0x0f, 0x3f, 0x0d, 0x7b, 0x4e, 0x2d, 0x11},
}

var (
	operationalInfoDescriptor = eventDescriptor{
		ID:      uint16(RegisteredInfoID),
		Channel: providerOperationalChannel,
		Level:   levelInformational,
		Task:    taskCliOperational,
		Keyword: keywordOperational,
	}
	operationalWarningDescriptor = eventDescriptor{
		ID:      uint16(RegisteredWarningID),
		Channel: providerOperationalChannel,
		Level:   levelWarning,
		Task:    taskCliOperational,
		Keyword: keywordOperational,
	}
	operationalErrorDescriptor = eventDescriptor{
		ID:      uint16(RegisteredErrorID),
		Channel: providerOperationalChannel,
		Level:   levelError,
		Task:    taskCliOperational,
		Keyword: keywordOperational,
	}
	structuredInfoDescriptor = eventDescriptor{
		ID:      uint16(RegisteredStructuredInfoID),
		Channel: providerOperationalChannel,
		Level:   levelInformational,
		Task:    taskStructured,
		Keyword: keywordOperational,
	}
	structuredWarningDescriptor = eventDescriptor{
		ID:      uint16(RegisteredStructuredWarningID),
		Channel: providerOperationalChannel,
		Level:   levelWarning,
		Task:    taskStructured,
		Keyword: keywordOperational,
	}
	structuredErrorDescriptor = eventDescriptor{
		ID:      uint16(RegisteredStructuredErrorID),
		Channel: providerOperationalChannel,
		Level:   levelError,
		Task:    taskStructured,
		Keyword: keywordOperational,
	}
)
