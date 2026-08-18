//go:build !linux

package browser

func probeBrowserResources() browserResourceSnapshot {
	return browserResourceSnapshot{}
}
