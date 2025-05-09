package generic

import (
	"fmt"
	"time"
)

type Sleep struct {
	Duration time.Duration
}

func (s *Sleep) Run() error {
	fmt.Printf("Sleeping for %v\n", s.Duration)
	time.Sleep(s.Duration)
	return nil
}

func (s *Sleep) Prevalidate() error {
	if s.Duration < 0 {
		return fmt.Errorf("duration cannot be negative: %v", s.Duration)
	}
	return nil
}

func (s *Sleep) Stop() error {
	return nil
}
