// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5/internal/auth"
	"github.com/pion/turn/v5/internal/proto"
)

const (
	// See: https://tools.ietf.org/html/rfc5766#section-6.2 defines 3600 seconds recommendation.
	maximumAllocationLifetime = time.Hour
)

func buildAndSend(conn net.PacketConn, dst net.Addr, attrs ...stun.Setter) error {
	msg, err := stun.Build(attrs...)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(msg.Raw, dst)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}

	return err
}

// Send a STUN packet and return the original error to the caller.
func buildAndSendErr(conn net.PacketConn, dst net.Addr, err error, attrs ...stun.Setter) error {
	if sendErr := buildAndSend(conn, dst, attrs...); sendErr != nil {
		err = fmt.Errorf("%w %v %v", errFailedToSendError, sendErr, err) //nolint:errorlint
	}

	return err
}

func buildMsg(
	transactionID [stun.TransactionIDSize]byte,
	msgType stun.MessageType,
	additional ...stun.Setter,
) []stun.Setter {
	return append([]stun.Setter{&stun.Message{TransactionID: transactionID}, msgType}, additional...)
}

// FORK (vk-turn-proxy, tools/turn-relay): a REQUEST whose 5-tuple has no
// allocation is ANSWERED with an error response — upstream returns the error
// and sends nothing. A client behind a NAT that gave its socket a new mapping
// (a phone asleep on a carrier's network) asks from a source the server holds
// no allocation for; left unanswered it runs its whole retransmission ladder
// and the session above stands dead until some liveness rule finds it. VK's
// relays answer, and the client this relay serves ends the session on that
// answer at once — so the codes are VK's (measured): 400 to CreatePermission
// and ChannelBind, 437 to Refresh. The request has passed authenticateRequest
// by then: only a sender that holds a nonce of this server is answered.
// Indications and ChannelData from such a source are still met with silence.
// The error is returned as before — the caller's event is raised all the same.
func answerNoAllocation(req Request, stunMsg *stun.Message, code stun.ErrorCode) error {
	return buildAndSendErr(req.Conn, req.SrcAddr,
		fmt.Errorf("%w %v:%v", errNoAllocationFound, req.SrcAddr, req.Conn.LocalAddr()),
		buildMsg(stunMsg.TransactionID, stun.NewType(stunMsg.Type.Method, stun.ClassErrorResponse), code)...)
}

func authenticateRequest(req Request, stunMsg *stun.Message, callingMethod stun.Method) (
	messageIntegrity stun.MessageIntegrity,
	hasAuth bool,
	username string,
	err error,
) {
	respondWithNonce := func(responseCode stun.ErrorCode) (stun.MessageIntegrity, bool, string, error) {
		nonce, err := req.NonceHash.Generate()
		if err != nil {
			return nil, false, "", err
		}

		return nil, false, "", buildAndSend(req.Conn, req.SrcAddr, buildMsg(stunMsg.TransactionID,
			stun.NewType(callingMethod, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: responseCode},
			stun.NewNonce(nonce),
			stun.NewRealm(req.Realm),
		)...)
	}

	if !stunMsg.Contains(stun.AttrMessageIntegrity) {
		return respondWithNonce(stun.CodeUnauthorized)
	}

	nonceAttr := &stun.Nonce{}
	usernameAttr := &stun.Username{}
	realmAttr := &stun.Realm{}
	badRequestMsg := buildMsg(
		stunMsg.TransactionID,
		stun.NewType(callingMethod, stun.ClassErrorResponse),
		&stun.ErrorCodeAttribute{Code: stun.CodeBadRequest},
	)

	// No Auth handler is set, server is running in STUN only mode
	// Respond with 400 so clients don't retry.
	if req.AuthHandler == nil {
		sendErr := buildAndSend(req.Conn, req.SrcAddr, badRequestMsg...)

		return nil, false, "", sendErr
	}

	if err := nonceAttr.GetFrom(stunMsg); err != nil {
		return nil, false, "", buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	// Assert Nonce is signed and is not expired.
	if err := req.NonceHash.Validate(nonceAttr.String()); err != nil {
		return respondWithNonce(stun.CodeStaleNonce)
	}

	if err := realmAttr.GetFrom(stunMsg); err != nil {
		return nil, false, "", buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	} else if err := usernameAttr.GetFrom(stunMsg); err != nil {
		return nil, false, "", buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	userID, ourKey, ok := req.AuthHandler(&auth.RequestAttributes{
		Username: usernameAttr.String(),
		Realm:    realmAttr.String(),
		SrcAddr:  req.SrcAddr,
		TLS:      req.TLS,
	})
	if !ok {
		return nil, false, "", buildAndSendErr(
			req.Conn,
			req.SrcAddr,
			fmt.Errorf("%w %s", errNoSuchUser, usernameAttr.String()),
			badRequestMsg...,
		)
	}

	// FORK (vk-turn-proxy, tools/turn-relay): the request's MESSAGE-INTEGRITY is
	// NOT checked. This relay stands in the TURN override list of a client that
	// signs with credentials VK issued — a password this server cannot know
	// (issue #105: the user's own relay first, VK's relays after it). The
	// AuthHandler still names the user and hands a key for the responses (which
	// the pion client does not verify); the nonce is still validated above. What
	// keeps the relay from being open is the PermissionHandler (peers) and the
	// QuotaHandler (allocations), not the signature.
	_ = ourKey

	genAuthEvent(req, stunMsg, callingMethod, true)

	return stun.MessageIntegrity(ourKey), true, userID, nil
}

func genAuthEvent(req Request, stunMsg *stun.Message, callingMethod stun.Method, verdict bool) {
	if req.AllocationManager.EventHandler.OnAuth == nil {
		return
	}

	realmAttr := &stun.Realm{}
	if err := realmAttr.GetFrom(stunMsg); err != nil {
		return
	}

	// Auth event is generated per the username, not the user-id.
	usernameAttr := &stun.Username{}
	if err := usernameAttr.GetFrom(stunMsg); err != nil {
		return
	}

	transportAttr := &proto.RequestedTransport{}
	if err := transportAttr.GetFrom(stunMsg); err != nil {
		transportAttr = &proto.RequestedTransport{Protocol: proto.ProtoUDP}
	}

	req.AllocationManager.EventHandler.OnAuth(req.SrcAddr, req.Conn.LocalAddr(),
		transportAttr.Protocol.String(), usernameAttr.String(), realmAttr.String(),
		callingMethod.String(), verdict)
}

func allocationLifeTime(req Request, m *stun.Message) time.Duration {
	lifetimeDuration := req.AllocationLifetime

	var lifetime proto.Lifetime
	if err := lifetime.GetFrom(m); err == nil {
		if lifetime.Duration < maximumAllocationLifetime {
			lifetimeDuration = lifetime.Duration
		}
	}

	return lifetimeDuration
}
