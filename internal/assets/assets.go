package assets

import _ "embed"

//go:embed dscida_sidecar.py
var Sidecar []byte

//go:embed dscida_validator.py
var Validator []byte
