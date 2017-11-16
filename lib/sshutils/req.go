/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sshutils

import (
	"github.com/gravitational/teleport"

	"github.com/gravitational/trace"
)

// EnvReqParams are parameters for env request
type EnvReqParams struct {
	Name  string
	Value string
}

// WinChangeReqParams specifies parameters for window changes
type WinChangeReqParams struct {
	W   uint32
	H   uint32
	Wpx uint32
	Hpx uint32
}

// PTYReqParams specifies parameters for pty change window
type PTYReqParams struct {
	Env   string
	W     uint32
	H     uint32
	Wpx   uint32
	Hpx   uint32
	Modes string
}

// Check validates PTY parameters.
func (p *PTYReqParams) Check() error {
	if p.W > maxSize || p.W < minSize {
		return trace.BadParameter("bad width: %v", p.W)
	}
	if p.H > maxSize || p.H < minSize {
		return trace.BadParameter("bad height: %v", p.H)
	}

	return nil
}

// CheckAndSetDefaults validates PTY parameters and ensures parameters
// are within default values.
func (p *PTYReqParams) CheckAndSetDefaults() error {
	if p.W > maxSize || p.W < minSize {
		p.W = teleport.DefaultTerminalWidth
	}
	if p.H > maxSize || p.H < minSize {
		p.H = teleport.DefaultTerminalHeight
	}

	return nil
}

// ExecReq specifies parameters for a "exec" request.
type ExecReq struct {
	Command string
}

// SubsystemReq specifies the parameters for a "subsystem" request.
type SubsystemReq struct {
	Name string
}

// SessionEnvVar is environment variable for SSH session
const SessionEnvVar = "TELEPORT_SESSION"

const (
	// ExecRequest is a request to run a command.
	ExecRequest = "exec"

	// ShellRequest is a request for a shell.
	ShellRequest = "shell"

	// EnvRequest is a request to set an environment variable.
	EnvRequest = "env"

	// SubsystemRequest is a request to run a subsystem.
	SubsystemRequest = "subsystem"

	// WindowChangeRequest is a request to change window.
	WindowChangeRequest = "window-change"

	// PTYRequest is a request for PTY.
	PTYRequest = "pty-req"

	// AgentForwardRequest is SSH agent request.
	AgentForwardRequest = "auth-agent-req@openssh.com"

	// AuthAgentRequest is a request to a SSH client to open an agent channel.
	AuthAgentRequest = "auth-agent@openssh.com"
)

const (
	minSize = 1
	maxSize = 4096
)
