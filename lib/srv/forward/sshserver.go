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
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

// Server is a forwarding server. Server is used to create a single in-memory
// SSH server that will forward connections to a remote server. It's used along
// with the recording proxy to allow Teleport to record sessions with OpenSSH
// nodes at the proxy level.
type Server struct {
	log *log.Entry

	clientConn net.Conn
	serverConn net.Conn

	agent        agent.Agent
	agentChannel ssh.Channel

	hostCertificate ssh.Signer

	remoteClient  *ssh.Client
	remoteSession *ssh.Session

	authHandlers *srv.AuthHandlers

	authClient      auth.ClientI
	auditLog        events.IAuditLog
	authService     auth.AccessPoint
	sessionRegistry *srv.SessionRegistry
	sessionServer   session.Service
}

// ServerConfig is the configuration needed to create an instance of a Server.
type ServerConfig struct {
	AuthClient      auth.ClientI
	UserAgent       agent.Agent
	Source          string
	Destination     string
	HostCertificate ssh.Signer
}

// CheckDefaults makes sure all required parameters are passed in.
func (s *ServerConfig) CheckDefaults() error {
	if s.AuthClient == nil {
		return trace.BadParameter("auth client required")
	}
	if s.UserAgent == nil {
		return trace.BadParameter("user agent required to connect to remote host")
	}
	if s.Source == "" {
		return trace.BadParameter("source address required to identify client")
	}
	if s.Destination == "" {
		return trace.BadParameter("destination address required to connect to remote host")
	}
	if s.HostCertificate == nil {
		return trace.BadParameter("host certificate required to act on behalf of remote host")
	}

	return nil
}

//func New(authClient auth.ClientI, a agent.Agent, src string, dst string, hostCertificate ssh.Signer) (*Server, error) {
func New(c ServerConfig) (*Server, error) {
	// check and make sure we everything we need to build a forwarding node
	err := c.CheckDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// build a pipe connection to hook up the client and the server. we save both
	// here and will pass them along to the context when we create it so they
	// can be closed by the context.
	srcAddr, err := utils.ParseAddr(c.Source)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	dstAddr, err := utils.ParseAddr(c.Destination)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	serverConn, clientConn := utils.DualPipeNetConn(srcAddr, dstAddr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s := &Server{
		log: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentForwardingNode,
			trace.ComponentFields: map[string]string{
				"src-addr": c.Source,
				"dst-addr": c.Destination,
			},
		}),
		agent:           c.UserAgent,
		hostCertificate: c.HostCertificate,
		authClient:      c.AuthClient,
		auditLog:        c.AuthClient,
		authService:     c.AuthClient,
		sessionServer:   c.AuthClient,
		serverConn:      serverConn,
		clientConn:      clientConn,
	}

	// common auth handlers
	s.authHandlers = &srv.AuthHandlers{
		Entry: log.WithFields(log.Fields{
			trace.Component:       teleport.ComponentForwardingNode,
			trace.ComponentFields: log.Fields{},
		}),
		Server:      nil,
		Component:   teleport.ComponentForwardingNode,
		AuditLog:    c.AuthClient,
		AccessPoint: c.AuthClient,
	}

	s.sessionRegistry = srv.NewSessionRegistry(s)

	return s, nil
}

// ID returns 0 for forwarding servers for now.
func (s *Server) ID() string {
	return "0"
}

// GetNamespace returns the namespace the forwarding server resides is.
func (s *Server) GetNamespace() string {
	return defaults.Namespace
}

// AdvertiseAddr is the address of the remote host this forwarding server is
// connected to.
func (s *Server) AdvertiseAddr() string {
	return s.clientConn.RemoteAddr().String()
}

// Component is the type of node this server is.
func (s *Server) Component() string {
	return teleport.ComponentForwardingNode
}

// EmitAuditEvent sends an event to the Audit Log.
func (s *Server) EmitAuditEvent(eventType string, fields events.EventFields) {
	auditLog := s.GetAuditLog()
	if auditLog != nil {
		if err := auditLog.EmitAuditEvent(eventType, fields); err != nil {
			s.log.Error(err)
		}
	} else {
		s.log.Warn("SSH server has no audit log")
	}
}

// PermitUserEnvironment is always false because it's up the the remote host
// to decide if the user environment will be read or not.
func (s *Server) PermitUserEnvironment() bool {
	return false
}

// GetAuditLog returns the Audit Log for this cluster.
func (s *Server) GetAuditLog() events.IAuditLog {
	return s.auditLog
}

// GetAccessPoint returns an auth.AccessPoint for this cluster.
func (s *Server) GetAccessPoint() auth.AccessPoint {
	return s.authService
}

// GetSessionServer returns a session server.
func (s *Server) GetSessionServer() session.Service {
	return s.sessionServer
}

// Dial returns the client connection created by pipeAddrConn.
func (s *Server) Dial() (net.Conn, error) {
	return s.clientConn, nil
}

func (s *Server) Serve() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: s.authHandlers.UserKeyAuth,
	}
	config.AddHostKey(s.hostCertificate)

	sconn, chans, reqs, err := ssh.NewServerConn(s.serverConn, config)
	if err != nil {
		defer s.serverConn.Close()
		defer s.clientConn.Close()

		s.log.Errorf("Unable to create server connection: %v", err)
		return
	}

	// build a remote session to the remote node
	s.remoteClient, s.remoteSession, err = newRemoteSession(s.clientConn.RemoteAddr().String(), sconn.User(), s.agent, s.authHandlers)
	if err != nil {
		defer s.serverConn.Close()
		defer s.clientConn.Close()

		// reject the connection with an error so the client doesn't hang then
		// close the connection
		s.rejectChannel(chans, err)
		sconn.Close()

		s.log.Errorf("Unable to create remote connection: %v", err)
		return
	}

	// process global and channel requests
	go s.handleConnection(sconn, chans, reqs)
}

func (s *Server) handleConnection(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	for {
		select {
		// global out-of-band requests
		case newRequest := <-reqs:
			if newRequest == nil {
				return
			}
			go s.handleGlobalRequest(newRequest)
		// channel requests
		case newChannel := <-chans:
			if newChannel == nil {
				return
			}
			go s.handleChannel(sconn, newChannel)
		}
	}
}

func (s *Server) rejectChannel(chans <-chan ssh.NewChannel, err error) {
	for newChannel := range chans {
		err := newChannel.Reject(ssh.ConnectionFailed, err.Error())
		if err != nil {
			s.log.Errorf("Unable to reject and close connection.")
		}
		return
	}
}

func (s *Server) handleGlobalRequest(req *ssh.Request) {
	ok, err := s.remoteSession.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		s.log.Warnf("Failed to forward global request %v: %v", req.Type, err)
		return
	}
	if req.WantReply {
		err = req.Reply(ok, nil)
		if err != nil {
			s.log.Warnf("Failed to reply to global request: %v: %v", req.Type, err)
		}
	}
}

//func (s *Server) handleChannel(nc net.Conn, sconn *ssh.ServerConn, nch ssh.NewChannel) {
func (s *Server) handleChannel(sconn *ssh.ServerConn, nch ssh.NewChannel) {
	channelType := nch.ChannelType()

	switch channelType {
	// a client requested the terminal size to be sent along with every
	// session message (Teleport-specific SSH channel for web-based terminals)
	case "x-teleport-request-resize-events":
		ch, _, _ := nch.Accept()
		go s.handleTerminalResize(sconn, ch)
	case "session": // interactive sessions
		ch, requests, err := nch.Accept()
		if err != nil {
			s.log.Infof("could not accept channel (%s)", err)
		}
		go s.handleSessionRequests(sconn, ch, requests)
	case "direct-tcpip": //port forwarding
		req, err := sshutils.ParseDirectTCPIPReq(nch.ExtraData())
		if err != nil {
			s.log.Errorf("failed to parse request data: %v, err: %v", string(nch.ExtraData()), err)
			nch.Reject(ssh.UnknownChannelType, "failed to parse direct-tcpip request")
		}
		ch, _, err := nch.Accept()
		if err != nil {
			s.log.Infof("could not accept channel (%s)", err)
		}
		go s.handleDirectTCPIPRequest(sconn, ch, req)
	default:
		nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", channelType))
	}
}

// handleDirectTCPIPRequest does the port forwarding
func (s *Server) handleDirectTCPIPRequest(sconn *ssh.ServerConn, ch ssh.Channel, req *sshutils.DirectTCPIPReq) {
	ctx := srv.NewServerContext(s, sconn)

	ctx.RemoteClient = s.remoteClient
	ctx.RemoteSession = s.remoteSession
	ctx.SetAgent(s.agent, s.agentChannel)

	ctx.AddCloser(ch)
	ctx.AddCloser(s.serverConn)
	ctx.AddCloser(s.clientConn)
	ctx.AddCloser(s.remoteSession)
	ctx.AddCloser(s.remoteClient)

	defer ctx.Debugf("Closed direct-tcp context")
	defer func() {
		err := ctx.Close()
		if err != nil {
			ctx.Debugf("Error while closing context: %v", err)
		}
	}()

	addr := fmt.Sprintf("%v:%d", req.Host, req.Port)
	ctx.Infof("direct-tcpip channel: %#v to --> %v", req, addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		ctx.Infof("failed connecting to: %v, err: %v", addr, err)
		return
	}
	defer conn.Close()

	// emit a port forwarding audit event
	s.EmitAuditEvent(events.PortForwardEvent, events.EventFields{
		events.PortForwardAddr: addr,
		events.EventLogin:      ctx.Login,
		events.LocalAddr:       sconn.LocalAddr().String(),
		events.RemoteAddr:      sconn.RemoteAddr().String(),
	})

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(ch, conn)
		ch.Close()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(conn, ch)
		conn.Close()
	}()

	wg.Wait()
}

// handleTerminalResize is called by the web proxy via its SSH connection.
// when a web browser connects to the web API, the web proxy asks us,
// by creating this new SSH channel, to start injecting the terminal size
// into every SSH write back to it.
//
// this is the only way to make web-based terminal UI not break apart
// when window changes its size
func (s *Server) handleTerminalResize(sconn *ssh.ServerConn, ch ssh.Channel) {
	err := s.sessionRegistry.PushTermSizeToParty(sconn, ch)
	if err != nil {
		s.log.Warnf("Unable to push terminal size to party: %v", err)
	}
}

// handleSessionRequests handles out of band session requests once the session channel has been created
// this function's loop handles all the "exec", "subsystem" and "shell" requests.
func (s *Server) handleSessionRequests(sconn *ssh.ServerConn, ch ssh.Channel, in <-chan *ssh.Request) {
	ctx := srv.NewServerContext(s, sconn)

	ctx.RemoteClient = s.remoteClient
	ctx.RemoteSession = s.remoteSession
	ctx.SetAgent(s.agent, s.agentChannel)

	ctx.AddCloser(ch)
	ctx.AddCloser(s.serverConn)
	ctx.AddCloser(s.clientConn)
	ctx.AddCloser(s.remoteSession)
	ctx.AddCloser(s.remoteClient)

	defer s.log.Debugf("Closed session context")
	defer func() {
		err := ctx.Close()
		if err != nil {
			s.log.Debugf("Error while closing session context: %v", err)
		}
	}()

	for {
		// update ctx with the session ID:
		err := ctx.CreateOrJoinSession(s.sessionRegistry)
		if err != nil {
			errorMessage := fmt.Sprintf("unable to update context: %v", err)
			ctx.Errorf("%v", errorMessage)

			// write the error to channel and close it
			ch.Stderr().Write([]byte(errorMessage))
			_, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{C: teleport.RemoteCommandFailure}))
			if err != nil {
				ctx.Errorf("failed to send exit status %v", errorMessage)
			}
			return
		}

		select {
		case result := <-ctx.SubsystemResultCh:
			// this means that subsystem has finished executing and
			// want us to close session and the channel
			ctx.Debugf("Subsystem execution result: %v", result.Err)
			return
		case req := <-in:
			if req == nil {
				// this will happen when the client closes/drops the connection
				ctx.Debugf("Client %v disconnected", sconn.RemoteAddr())
				return
			}
			if err := s.dispatch(ch, req, ctx); err != nil {
				replyError(ch, req, err)
				return
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
		case result := <-ctx.ExecResultCh:
			ctx.Debugf("Exec request (%q) complete: %v", result.Command, result.Code)

			// this means that exec process has finished and delivered the execution result,
			// we send it back and close the session
			_, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{C: uint32(result.Code)}))
			if err != nil {
				ctx.Infof("%v failed to send exit status: %v", result.Command, err)
			}
			return
		}
	}
}

func (s *Server) dispatch(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	var err error

	ctx.Debugf("Handling request %v (WantReply=%v)", req.Type, req.WantReply)

	switch req.Type {
	case sshutils.ExecRequest:
		return s.handleExec(ch, req, ctx)
	case sshutils.PTYRequest:
		return s.handlePTYReq(ch, req, ctx)
	case sshutils.ShellRequest:
		ctx.ExecRequest, err = srv.NewExecRequest(ctx, "")
		if err != nil {
			return trace.Wrap(err)
		}
		if err := s.sessionRegistry.OpenSession(ch, req, ctx); err != nil {
			s.log.Error(err)
			return trace.Wrap(err)
		}
		return nil
	case sshutils.EnvRequest:
		return s.handleEnv(ch, req, ctx)
	case sshutils.SubsystemRequest:
		return s.handleSubsystem(ch, req, ctx)
	case sshutils.WindowChangeRequest:
		return s.handleWinChange(ch, req, ctx)
	case sshutils.AgentForwardRequest:
		// to maintain interoperability with OpenSSH, agent forwarding requests
		// should never fail, all errors should be logged and we should continue
		// processing requests.
		err := s.handleAgentForward(ch, req, ctx)
		if err != nil {
			s.log.Info(err)
		}
		return nil
	default:
		return trace.BadParameter(
			"%v doesn't support request type '%v'", s.Component(), req.Type)
	}
}

func (s *Server) handleAgentForward(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	// check if the users rbac role allows agent forwarding
	err := s.authHandlers.CheckAgentForward(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// forward requests to agent passed in from the proxy and held in the context
	err = agent.ForwardToAgent(s.remoteClient, ctx.GetAgent())
	if err != nil {
		return trace.Wrap(err)
	}

	// make the actual agent forwarding request
	err = agent.RequestAgentForwarding(s.remoteSession)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (s *Server) handleWinChange(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	params, err := parseWinChange(req)
	if err != nil {
		ctx.Error(err)
		return trace.Wrap(err)
	}
	term := ctx.GetTerm()
	if term != nil {
		err = term.SetWinSize(*params)
		if err != nil {
			ctx.Error(err)
		}
	}
	err = s.sessionRegistry.NotifyWinChange(*params, ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (s *Server) handleSubsystem(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	subsystem, err := parseSubsystemRequest(req, ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	err = subsystem.Start(ch)
	if err != nil {
		ctx.SendSubsystemResult(srv.SubsystemResult{
			Name: subsystem.subsytemName,
			Err:  trace.Wrap(err),
		})
		return trace.Wrap(err)
	}

	go func() {
		err := subsystem.Wait()
		ctx.SendSubsystemResult(srv.SubsystemResult{
			Name: subsystem.subsytemName,
			Err:  trace.Wrap(err),
		})
	}()

	return nil
}

func (s *Server) handleEnv(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	var e sshutils.EnvReqParams
	if err := ssh.Unmarshal(req.Payload, &e); err != nil {
		ctx.Error(err)
		return trace.Wrap(err, "failed to parse env request")
	}

	err := s.remoteSession.Setenv(e.Name, e.Value)
	if err != nil {
		s.log.Debugf("Unable to set environment variable: %v: %v", e.Name, e.Value)
	}

	return nil
}

func (s *Server) handlePTYReq(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	// parse and get the window size requested
	r, err := srv.ParsePTYReq(req)
	if err != nil {
		return trace.Wrap(err)
	}

	params, err := session.NewTerminalParamsFromUint32(r.W, r.H)
	if err != nil {
		return trace.Wrap(err)
	}
	ctx.Debugf("Requested terminal of size %v", *params)

	// get an existing terminal or create a new one
	term := ctx.GetTerm()
	if term == nil {
		term, err = srv.NewTerminal(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
		ctx.SetTerm(term)
	}
	term.SetWinSize(*params)
	term.SetTermType(r.Env)

	// update the session:
	if err := s.sessionRegistry.NotifyWinChange(*params, ctx); err != nil {
		s.log.Error(err)
	}
	return nil
}

func (s *Server) handleExec(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	execRequest, err := parseExecRequest(req, ctx)
	if err != nil {
		ctx.Infof("Failed to parse exec request: %v", err)
		replyError(ch, req, err)
		return trace.Wrap(err)
	}
	if req.WantReply {
		req.Reply(true, nil)
	}
	// a terminal has been previously allocate for this command.
	// run this inside an interactive session
	if ctx.GetTerm() != nil {
		return s.sessionRegistry.OpenSession(ch, req, ctx)
	}
	// ... otherwise, regular execution:
	result, err := execRequest.Start(ch)
	if err != nil {
		ctx.Error(err)
		replyError(ch, req, err)
	}
	if result != nil {
		ctx.Debugf("Exec request %q result: %v", execRequest, result)
		ctx.SendExecResult(*result)
	}
	if err != nil {
		return trace.Wrap(err)
	}

	// in case if result is nil and no error, this means that program is
	// running in the background
	go func() {
		result, err = execRequest.Wait()
		if err != nil {
			ctx.Errorf("Exec request %q wait failed: %v", execRequest, err)
		}
		if result != nil {
			ctx.SendExecResult(*result)
		}
	}()
	return nil
}

func replyError(ch ssh.Channel, req *ssh.Request, err error) {
	message := []byte(utils.UserMessageFromError(err))
	ch.Stderr().Write(message)
	if req.WantReply {
		req.Reply(false, message)
	}
}

func parseWinChange(req *ssh.Request) (*session.TerminalParams, error) {
	var r sshutils.WinChangeReqParams
	if err := ssh.Unmarshal(req.Payload, &r); err != nil {
		return nil, trace.Wrap(err)
	}
	params, err := session.NewTerminalParamsFromUint32(r.W, r.H)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return params, nil
}

func parseExecRequest(req *ssh.Request, ctx *srv.ServerContext) (srv.Exec, error) {
	var err error

	var r sshutils.ExecReq
	if err = ssh.Unmarshal(req.Payload, &r); err != nil {
		return nil, trace.Wrap(err)
	}

	ctx.ExecRequest, err = srv.NewExecRequest(ctx, r.Command)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ctx.ExecRequest, nil
}

func parseSubsystemRequest(req *ssh.Request, ctx *srv.ServerContext) (*remoteSubsystem, error) {
	var r sshutils.SubsystemReq
	err := ssh.Unmarshal(req.Payload, &r)
	if err != nil {
		return nil, trace.BadParameter("failed to parse subsystem request: %v", err)
	}

	return parseRemoteSubsystem(context.Background(), r.Name, ctx), nil
}
