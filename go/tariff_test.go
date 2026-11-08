package fareward

import "testing"

// The blocks come from the config; zero keeps the default, and Tariff states what APICPUCredits
// charges, which is what the route file hands the SPOE agent.
func TestConfigureTariffChangesTheBlocks(t *testing.T) {
	t.Cleanup(func() {
		if err := ConfigureTariff(DefaultGetBlockKiB, DefaultPostBlockKiB); err != nil {
			t.Fatal(err)
		}
	})

	if err := ConfigureTariff(64, 0); err != nil {
		t.Fatal(err)
	}
	// 1 MiB past the 8 KiB free block is 16 started 64 KiB blocks.
	if got, _ := APICPUCredits("GET", 1<<20); got != 2+16 {
		t.Fatalf("a 1 MiB GET with 64 KiB blocks costs %d; want 18", got)
	}
	// The POST block was left at zero, so it keeps its default.
	if got, _ := APICPUCredits("POST", 16*1024+1); got != 7 {
		t.Fatalf("a 16 KiB + 1 POST costs %d; want 7", got)
	}

	for _, step := range Tariff() {
		for _, size := range []int{0, step.BaseKiB * 1024, step.BaseKiB*1024 + 1,
			(step.BaseKiB+step.StepKiB)*1024 + 1, (step.BaseKiB+7*step.StepKiB)*1024 + 3} {
			want, err := APICPUCredits(step.Method, size)
			if err != nil {
				t.Fatal(err)
			}
			steps := 0
			if extra := size - step.BaseKiB*1024; extra > 0 {
				steps = (extra + step.StepKiB*1024 - 1) / (step.StepKiB * 1024)
			}
			if got := int(step.BaseCredits) + steps; got != int(want) {
				t.Fatalf("%s %d bytes: Tariff says %d, APICPUCredits %d", step.Method, size, got, want)
			}
		}
	}

	for _, invalid := range [][2]int{{-1, 8}, {8, -1}, {maxBlockKiB + 1, 8}} {
		if err := ConfigureTariff(invalid[0], invalid[1]); err == nil {
			t.Fatalf("ConfigureTariff(%d, %d) was accepted", invalid[0], invalid[1])
		}
	}
}
