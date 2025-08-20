package msp

// ExportConfig is a test-friendly wrapper for exportConfig.
func ExportConfig(mspDir, caFile string, enable bool) error {
	return exportConfig(mspDir, caFile, enable)
}
