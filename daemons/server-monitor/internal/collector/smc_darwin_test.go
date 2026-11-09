//go:build darwin

package collector

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestReadDarwinSMCTemperatures(t *testing.T) {
	cpuTemp, hasCPU, gpuTemp, hasGPU := readDarwinSMCTemperatures()
	t.Logf("Darwin SMC: hasCPU=%v (%.1f°C), hasGPU=%v (%.1f°C)", hasCPU, cpuTemp, hasGPU, gpuTemp)

	if hasGPU {
		if math.IsNaN(gpuTemp) || math.IsInf(gpuTemp, 0) || gpuTemp < 11 || gpuTemp > 150 {
			t.Errorf("invalid GPU temperature from SMC: %f", gpuTemp)
		}
	}
	if hasCPU {
		if math.IsNaN(cpuTemp) || math.IsInf(cpuTemp, 0) || cpuTemp < 11 || cpuTemp > 150 {
			t.Errorf("invalid CPU temperature from SMC: %f", cpuTemp)
		}
	}

	// Verify caching on second call
	cpu2, hasCPU2, gpu2, hasGPU2 := readDarwinSMCTemperatures()
	if hasGPU != hasGPU2 {
		t.Errorf("hasGPU mismatch on second call: %v vs %v", hasGPU, hasGPU2)
	}
	if hasCPU != hasCPU2 {
		t.Errorf("hasCPU mismatch on second call: %v vs %v", hasCPU, hasCPU2)
	}
	if hasGPU && (gpu2 < 11 || gpu2 > 150) {
		t.Errorf("invalid GPU temperature on cached call: %f", gpu2)
	}
	if hasCPU && (cpu2 < 11 || cpu2 > 150) {
		t.Errorf("invalid CPU temperature on cached call: %f", cpu2)
	}
}

func TestDecodeSMCTemperature(t *testing.T) {
	// 1. Valid IEEE-754 float32 ("flt ")
	var rawFlt [32]byte
	binary.LittleEndian.PutUint32(rawFlt[:4], math.Float32bits(38.5))
	val, ok := decodeSMCTemperature("flt ", 4, rawFlt)
	if !ok || math.Abs(val-38.5) > 0.001 {
		t.Errorf("expected 38.5 for flt, got ok=%v val=%f", ok, val)
	}

	// 2. Valid signed fixed-point 7.8 ("sp78") -> 42.5°C
	var rawSp78 [32]byte
	rawSp78[0] = 42
	rawSp78[1] = 128
	val, ok = decodeSMCTemperature("sp78", 2, rawSp78)
	if !ok || math.Abs(val-42.5) > 0.001 {
		t.Errorf("expected 42.5 for sp78, got ok=%v val=%f", ok, val)
	}

	// 3. Reject NaN
	var rawNaN [32]byte
	binary.LittleEndian.PutUint32(rawNaN[:4], math.Float32bits(float32(math.NaN())))
	if _, ok := decodeSMCTemperature("flt ", 4, rawNaN); ok {
		t.Errorf("expected NaN to be rejected")
	}

	// 4. Reject +Inf and -Inf
	var rawInf [32]byte
	binary.LittleEndian.PutUint32(rawInf[:4], math.Float32bits(float32(math.Inf(1))))
	if _, ok := decodeSMCTemperature("flt ", 4, rawInf); ok {
		t.Errorf("expected +Inf to be rejected")
	}

	// 5. Reject <= 0, power-gated sleep (< 11.0°C, e.g. 4.6°C), and > 150
	var rawZero [32]byte
	if _, ok := decodeSMCTemperature("flt ", 4, rawZero); ok {
		t.Errorf("expected 0.0 to be rejected")
	}
	var rawSleep [32]byte
	binary.LittleEndian.PutUint32(rawSleep[:4], math.Float32bits(4.61))
	if _, ok := decodeSMCTemperature("flt ", 4, rawSleep); ok {
		t.Errorf("expected power-gated 4.61°C to be rejected")
	}
	var rawHot [32]byte
	binary.LittleEndian.PutUint32(rawHot[:4], math.Float32bits(175.0))
	if _, ok := decodeSMCTemperature("flt ", 4, rawHot); ok {
		t.Errorf("expected >150.0 to be rejected")
	}

	// 6. Reject unknown data type or size
	if _, ok := decodeSMCTemperature("ui32", 4, rawFlt); ok {
		t.Errorf("expected unknown type ui32 to be rejected")
	}
}

func TestAppleSiliconModelSensorMap(t *testing.T) {
	spec, ok := appleSiliconModelSensors["Mac14,3"]
	if !ok {
		t.Fatalf("expected Mac14,3 in appleSiliconModelSensors")
	}
	if len(spec.cpuKeys) != 8 || len(spec.gpuKeys) != 2 {
		t.Errorf("unexpected Mac14,3 sensor counts: cpu=%d gpu=%d", len(spec.cpuKeys), len(spec.gpuKeys))
	}
	for _, k := range spec.cpuKeys {
		if nonCPUSMCKeys[k] {
			t.Errorf("model CPU key %q should not be in nonCPUSMCKeys", k)
		}
	}
}
