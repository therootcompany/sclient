package tunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
)

// Pipe relays local <-> remote in both directions, ending each stream when its
// source is exhausted, then hangs up on both.
func Pipe(local io.ReadWriteCloser, remote io.ReadWriteCloser) error {
	var (
		wg        sync.WaitGroup
		localErr  error
		remoteErr error
	)

	wg.Go(func() { localErr = pipeToRemote(local, remote) })
	wg.Go(func() { remoteErr = pipeToLocal(remote, local) })
	wg.Wait()

	_ = remote.Close()
	return errors.Join(localErr, remoteErr)
}

// pipeToRemote copies local to remote, then half-closes the remote so a
// keep-alive server sees EOF without losing its buffered answer. The other copy
// closes the local side when the remote ends, so a closed local connection is a
// normal ending, not an error.
func pipeToRemote(local io.Reader, remote io.WriteCloser) error {
	_, err := io.Copy(remote, local)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	if cw, ok := remote.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
		return nil
	}
	if err := remote.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// pipeToLocal copies remote to local, then hangs up on the local side.
func pipeToLocal(remote io.Reader, local io.WriteCloser) error {
	_, err := io.Copy(local, remote)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	if err := local.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}
