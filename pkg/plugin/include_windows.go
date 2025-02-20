// nolint // don't complain about this file
package plugin

// Plugins self-register via their init() funcs as long as they are imported.
import (
	_ "github.com/vpidatala94/retina/pkg/plugin/ebpfwindows"
	_ "github.com/vpidatala94/retina/pkg/plugin/hnsstats"
	_ "github.com/vpidatala94/retina/pkg/plugin/pktmon"
)
