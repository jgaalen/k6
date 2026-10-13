package js

import (
	"errors"
	"sync"

	"go.k6.io/k6/v2/ext"
	"go.k6.io/k6/v2/js/common"
	"go.k6.io/k6/v2/js/modules"
)

func getJSModules() map[string]any {
	result := getInternalJSModules()
	external := ext.Get(ext.JSExtension)

	// external is always prefixed with `k6/x`
	for _, e := range external {
		result[e.Name] = e.Module
	}

	return result
}

type removedModule struct {
	errMsg string
}

func newRemovedModule(errMsg string) modules.Module {
	return &removedModule{errMsg: errMsg}
}

func (rm *removedModule) NewModuleInstance(vu modules.VU) modules.Instance {
	common.Throw(vu.Runtime(), errors.New(rm.errMsg))

	return nil
}

type warnExperimentalModule struct {
	once sync.Once
	msg  string
	base modules.Module
}

func newWarnExperimentalModule(base modules.Module, msg string) modules.Module {
	return &warnExperimentalModule{
		msg:  msg,
		base: base,
	}
}

func (w *warnExperimentalModule) NewModuleInstance(vu modules.VU) modules.Instance {
	w.once.Do(func() { vu.InitEnv().Logger.Warn(w.msg) })
	return w.base.NewModuleInstance(vu)
}
