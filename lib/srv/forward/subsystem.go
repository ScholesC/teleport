/*
Copyright 2017 Gravitational, Inc.

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

package forward

import (
	"context"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

type remoteSubsystem struct {
	log *log.Entry

	serverContext *srv.ServerContext
	subsytemName  string

	ctx     context.Context
	errorCh chan error
}

func parseRemoteSubsystem(ctx context.Context, subsytemName string, serverContext *srv.ServerContext) *remoteSubsystem {
	return &remoteSubsystem{
		log: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRemoteSubsystem,
			trace.ComponentFields: map[string]string{
				"name": subsytemName,
			},
		}),
		serverContext: serverContext,
		subsytemName:  subsytemName,
		ctx:           ctx,
		errorCh:       make(chan error),
	}
}

// Start will begin execution of the remote subsytem on the passed in channel.
func (r *remoteSubsystem) Start(ch ssh.Channel) error {
	session := r.serverContext.RemoteSession

	stdout, err := session.StdoutPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	err = session.RequestSubsystem(r.subsytemName)
	if err != nil {
		// emit an event to the audit log with the reason remote execution failed
		r.emitAuditEvent(err)

		return trace.Wrap(err)
	}

	go func() {
		defer session.Close()

		_, err := io.Copy(ch, stdout)
		r.errorCh <- err
	}()
	go func() {
		defer session.Close()

		_, err := io.Copy(ch.Stderr(), stderr)
		r.errorCh <- err
	}()
	go func() {
		defer session.Close()

		_, err := io.Copy(stdin, ch)
		r.errorCh <- err
	}()

	return nil
}

// Wait until the remote subsystem has finished execution and then return the last error.
func (r *remoteSubsystem) Wait() error {
	var lastErr error

	for i := 0; i < 2; i++ {
		select {
		case err := <-r.errorCh:
			if err != nil && err != io.EOF {
				r.log.Warnf("Connection problem: %v %T", trace.DebugReport(err), err)
				lastErr = err
			}
		case <-r.ctx.Done():
			lastErr = trace.ConnectionProblem(nil, "context is closing")
		}
	}

	// emit an event to the audit log with the result of execution
	r.emitAuditEvent(lastErr)

	return lastErr
}

func (r *remoteSubsystem) emitAuditEvent(err error) {
	srv := r.serverContext.GetServer()

	srv.EmitAuditEvent(events.SubsystemEvent, events.EventFields{
		events.SubsystemName:  r.subsytemName,
		events.SubsystemError: err,
		events.EventUser:      r.serverContext.TeleportUser,
		events.EventLogin:     r.serverContext.Login,
		events.LocalAddr:      r.serverContext.RemoteClient.LocalAddr().String(),
		events.RemoteAddr:     r.serverContext.RemoteClient.RemoteAddr().String(),
	})
}
