//go:build !darwin

package collector

func readDarwinSMCTemperatures() (cpuTemp float64, hasCPU bool, gpuTemp float64, hasGPU bool) {
	return 0, false, 0, false
}
